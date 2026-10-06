import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  ExchangeKey,
  associatedData as legacyAssociatedData,
} from "./encryption.ts";
import { fingerprint } from "./fingerprint.ts";
import { IdentityKey } from "./identity.ts";
import { maxBodySize, maxCiphertextSize, sessionIdSize } from "./protocol.ts";
import {
  type Sealed,
  SessionKeys,
  type Side,
  type Transcript,
  associatedData,
  derivationInfo,
  sessionBindingMessage,
  verifySession,
} from "./session.ts";
import { memoryStore } from "./testing.ts";
import { type Unlocked, loadVault } from "./vault.ts";

type Party = {
  identity: IdentityKey;
  exchange: ExchangeKey;
  session: SessionKeys;
};

async function party(identity?: IdentityKey, exchange?: ExchangeKey) {
  return {
    identity: identity ?? (await IdentityKey.generate()),
    exchange: exchange ?? (await ExchangeKey.generate()),
    session: await SessionKeys.create(),
  };
}

function side(p: Party, epoch?: number): Side {
  const current = p.session.current;
  assert.ok(current);
  const at = epoch ?? current.epoch;
  const ephemeral = p.session.publicKeyOf(at);
  assert.ok(ephemeral);
  return {
    identity: p.identity.identity,
    staticKey: p.exchange.publicRaw,
    session: p.session.session,
    epoch: at,
    ephemeral,
  };
}

function transcript(from: Party, to: Party, id = "m1"): Transcript {
  return { id, from: side(from), to: side(to) };
}

async function seal(t: Transcript, from: Party, body: string): Promise<Sealed> {
  const sealed = await from.session.seal(t, body);
  assert.ok(sealed);
  return sealed;
}

async function rotate(p: Party): Promise<number> {
  const epoch = await p.session.prepare();
  assert.ok(epoch !== null);
  assert.equal(p.session.activate(epoch), true);
  return epoch;
}

function flip(text: string, index = 0): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 0x01;
  return encodeBase64Url(bytes);
}

test("creates fresh sessions that expose no private material", async () => {
  const sessions = await Promise.all(
    Array.from({ length: 20 }, () => SessionKeys.create()),
  );
  assert.equal(new Set(sessions.map((s) => s.session)).size, 20);
  assert.equal(
    new Set(
      sessions.map((s) => encodeBase64Url(s.current?.key ?? new Uint8Array())),
    ).size,
    20,
  );
  for (const s of sessions) {
    assert.equal(decodeBase64Url(s.session, sessionIdSize)?.length, 16);
    assert.deepEqual(s.epochs, [0]);
    assert.deepEqual(Object.keys(s), ["session"]);
    assert.equal(JSON.stringify(s), JSON.stringify({ session: s.session }));
    const copy = s.current?.key;
    assert.ok(copy);
    copy[0] ^= 0xff;
    assert.notDeepEqual(copy, s.current?.key);
  }
});

test("binds ephemeral keys to the identity, static key, session, and epoch", async () => {
  const a = await party();
  const b = await party();
  const bundle = await a.session.bind(a.identity, a.exchange, "current");
  assert.ok(bundle);
  assert.deepEqual(
    await verifySession(a.identity.identity, a.exchange.publicRaw, bundle),
    a.session.current?.key,
  );
  const other = await b.session.bind(b.identity, b.exchange, "current");
  assert.ok(other);
  const staticBinding = await a.exchange.bind(a.identity);
  assert.ok(staticBinding);
  const high = decodeBase64Url(bundle.key, 32);
  assert.ok(high);
  high[31] |= 0x80;

  const rejected: [string, string, Uint8Array, typeof bundle][] = [
    ["other identity", b.identity.identity, a.exchange.publicRaw, bundle],
    ["other static key", a.identity.identity, b.exchange.publicRaw, bundle],
    [
      "other session",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, session: other.session },
    ],
    [
      "other epoch",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, epoch: 1 },
    ],
    [
      "other key",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, key: other.key },
    ],
    [
      "other signature",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, signature: other.signature },
    ],
    [
      "static binding reused",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, signature: staticBinding.signature },
    ],
    [
      "flipped signature",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, signature: flip(bundle.signature) },
    ],
    [
      "non-canonical key",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, key: encodeBase64Url(high) },
    ],
    [
      "negative epoch",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, epoch: -1 },
    ],
    [
      "fractional epoch",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, epoch: 0.5 },
    ],
    [
      "short session",
      a.identity.identity,
      a.exchange.publicRaw,
      { ...bundle, session: "AAAA" },
    ],
  ];
  for (const [name, identity, staticKey, candidate] of rejected) {
    assert.equal(
      await verifySession(identity, staticKey, candidate),
      null,
      name,
    );
  }
  const message = sessionBindingMessage(
    a.identity.identity,
    a.exchange.publicRaw,
    bundle.session,
    0,
    a.session.current?.key ?? new Uint8Array(),
  );
  assert.ok(message);
  assert.equal(
    new TextDecoder().decode(message.slice(0, 18)),
    "ghostx/session/v1\0",
  );
  assert.equal(message.length, 18 + 32 + 32 + 16 + 4 + 32);
});

test("both peers derive the same message keys in each direction", async () => {
  const a = await party();
  const b = await party();
  const body = "hello 🌍 \n\t multi-line";
  const ab = transcript(a, b);
  assert.equal(await b.session.open(ab, await seal(ab, a, body)), body);
  const ba = transcript(b, a, "r1");
  assert.equal(await a.session.open(ba, await seal(ba, b, "reply")), "reply");
  const max = "a".repeat(maxBodySize);
  const big = await seal(ab, a, max);
  assert.equal(
    decodeBase64Url(big.ciphertext, maxCiphertextSize)?.length,
    maxCiphertextSize,
  );
  assert.equal(await b.session.open(ab, big), max);
});

test("binds every transcript field into derivation and authenticated data", async () => {
  const a = await party();
  const b = await party();
  const c = await party();
  const t = transcript(a, b);
  const sealed = await seal(t, a, "bound");
  const variants: Record<string, Transcript> = {
    "message id": { ...t, id: "m2" },
    "sender identity": {
      ...t,
      from: { ...t.from, identity: c.identity.identity },
    },
    "recipient identity": {
      ...t,
      to: { ...t.to, identity: c.identity.identity },
    },
    "sender static key": {
      ...t,
      from: { ...t.from, staticKey: c.exchange.publicRaw },
    },
    "recipient static key": {
      ...t,
      to: { ...t.to, staticKey: c.exchange.publicRaw },
    },
    "sender session": { ...t, from: { ...t.from, session: c.session.session } },
    "sender epoch": { ...t, from: { ...t.from, epoch: 1 } },
    "sender ephemeral key": {
      ...t,
      from: { ...t.from, ephemeral: side(c).ephemeral },
    },
  };
  const infos = new Set([
    encodeBase64Url(derivationInfo(t) ?? new Uint8Array()),
  ]);
  for (const [name, variant] of Object.entries(variants)) {
    assert.equal(await b.session.open(variant, sealed), null, name);
    infos.add(
      encodeBase64Url(derivationInfo(variant) ?? new Uint8Array()) +
        encodeBase64Url(associatedData(variant) ?? new Uint8Array()),
    );
  }
  assert.equal(infos.size, Object.keys(variants).length + 1);
  assert.equal(await b.session.open(t, sealed), "bound");

  const info = derivationInfo(t);
  const aad = associatedData(t);
  assert.ok(info && aad);
  const context = new TextEncoder().encode("ghostx/message/v2\0");
  assert.deepEqual(info.slice(0, context.length), context);
  assert.deepEqual(aad.slice(0, context.length), context);
  const legacy = legacyAssociatedData({
    id: t.id,
    from: t.from.identity,
    to: t.to.identity,
    fromKey: t.from.ephemeral,
    toKey: t.to.ephemeral,
  });
  assert.ok(legacy);
  assert.notDeepEqual(legacy.slice(0, context.length), context);
  assert.equal(associatedData({ ...t, id: "" }), null);
  assert.equal(associatedData({ ...t, id: "x".repeat(65) }), null);
  assert.equal(derivationInfo({ ...t, from: { ...t.from, epoch: -1 } }), null);
  assert.notDeepEqual(
    associatedData({ ...t, id: "ab" }),
    associatedData({ ...t, id: "a" }),
  );
});

test("derivation info and authenticated data each bind their own fields", async () => {
  const a = await party();
  const b = await party();
  const c = await party();
  const t = transcript(a, b);
  const info = derivationInfo(t);
  const aad = associatedData(t);
  assert.ok(info && aad);
  const changes: Record<string, [Transcript, boolean, boolean]> = {
    "message id": [{ ...t, id: "m2" }, false, true],
    "sender identity": [
      { ...t, from: { ...t.from, identity: c.identity.identity } },
      true,
      true,
    ],
    "recipient identity": [
      { ...t, to: { ...t.to, identity: c.identity.identity } },
      true,
      true,
    ],
    "sender static key": [
      { ...t, from: { ...t.from, staticKey: c.exchange.publicRaw } },
      true,
      false,
    ],
    "recipient static key": [
      { ...t, to: { ...t.to, staticKey: c.exchange.publicRaw } },
      true,
      false,
    ],
    "sender session": [
      { ...t, from: { ...t.from, session: c.session.session } },
      true,
      true,
    ],
    "recipient session": [
      { ...t, to: { ...t.to, session: c.session.session } },
      true,
      true,
    ],
    "sender epoch": [{ ...t, from: { ...t.from, epoch: 7 } }, true, true],
    "recipient epoch": [{ ...t, to: { ...t.to, epoch: 7 } }, true, true],
    "sender ephemeral": [
      { ...t, from: { ...t.from, ephemeral: side(c).ephemeral } },
      true,
      false,
    ],
    "recipient ephemeral": [
      { ...t, to: { ...t.to, ephemeral: side(c).ephemeral } },
      true,
      false,
    ],
  };
  for (const [name, [variant, inInfo, inAad]] of Object.entries(changes)) {
    assert.equal(
      encodeBase64Url(derivationInfo(variant) ?? new Uint8Array()) !==
        encodeBase64Url(info),
      inInfo,
      `info ${name}`,
    );
    assert.equal(
      encodeBase64Url(associatedData(variant) ?? new Uint8Array()) !==
        encodeBase64Url(aad),
      inAad,
      `aad ${name}`,
    );
  }
});

test("enforces sender and recipient roles", async () => {
  const a = await party();
  const b = await party();
  const c = await party();
  const t = transcript(a, b);
  const sealed = await seal(t, a, "for b");

  assert.equal(await a.session.open(t, sealed), null);
  assert.equal(await c.session.open(t, sealed), null);
  assert.equal(await c.session.open({ ...t, to: side(c) }, sealed), null);
  assert.equal(await b.session.seal(t, "wrong sender"), null);
  assert.equal(
    await a.session.seal({ ...t, from: { ...t.from, epoch: 3 } }, "no key"),
    null,
  );
  assert.equal(
    await a.session.seal(
      { ...t, from: { ...t.from, ephemeral: side(c).ephemeral } },
      "foreign key",
    ),
    null,
  );
});

test("rejects tampered or malformed envelopes and uses fresh randomness", async () => {
  const a = await party();
  const b = await party();
  const t = transcript(a, b);
  const sealed = await seal(t, a, "integrity");
  for (const bad of [
    { ...sealed, ciphertext: flip(sealed.ciphertext) },
    { ...sealed, ciphertext: flip(sealed.ciphertext, 9) },
    { ...sealed, iv: flip(sealed.iv) },
    { ...sealed, salt: flip(sealed.salt) },
    { ...sealed, ciphertext: sealed.ciphertext.slice(0, -2) },
    { ...sealed, salt: "" },
    { ...sealed, iv: `${sealed.iv}=` },
    { ...sealed, ciphertext: "not base64!" },
    { ...sealed, ciphertext: encodeBase64Url(new Uint8Array(16)) },
  ]) {
    assert.equal(await b.session.open(t, bad), null);
  }
  const many = await Promise.all(
    Array.from({ length: 50 }, () => seal(t, a, "same")),
  );
  for (const field of ["salt", "iv", "ciphertext"] as const) {
    assert.equal(new Set(many.map((s) => s[field])).size, many.length);
  }
});

test("forward secrecy: discarded epochs cannot be recovered from remaining state", async () => {
  const a = await party();
  const b = await party();
  const t0 = transcript(a, b, "m0");
  const m0 = await seal(t0, a, "protected by epoch 0");
  assert.equal(await b.session.open(t0, m0), "protected by epoch 0");
  const keyB0 = b.session.current?.key;
  const keyA0 = a.session.current?.key;

  assert.equal(await rotate(b), 1);
  assert.deepEqual(b.session.epochs, [0, 1]);
  assert.notDeepEqual(b.session.current?.key, keyB0);
  assert.equal(await b.session.open(t0, m0), "protected by epoch 0");

  const t1 = transcript(a, b, "m1");
  assert.equal(t1.to.epoch, 1);
  const m1 = await seal(t1, a, "protected by epoch 1");
  assert.equal(await b.session.open(t1, m1), "protected by epoch 1");
  assert.equal(
    await b.session.open(
      {
        ...t1,
        to: { ...t1.to, epoch: 0, ephemeral: keyB0 ?? new Uint8Array() },
      },
      m1,
    ),
    null,
  );

  b.session.discardPrevious();
  assert.equal(await rotate(a), 1);
  assert.equal(await rotate(a), 2);
  assert.deepEqual(b.session.epochs, [1]);
  assert.deepEqual(a.session.epochs, [1, 2]);
  assert.equal(b.session.publicKeyOf(0), null);
  assert.equal(a.session.publicKeyOf(0), null);
  assert.notDeepEqual(a.session.current?.key, keyA0);

  assert.equal(await b.session.open(t0, m0), null);
  const reboundToCurrent: Transcript = { ...t0, to: side(b) };
  assert.equal(await b.session.open(reboundToCurrent, m0), null);
  const reboundBoth: Transcript = { ...t0, from: side(a), to: side(b) };
  assert.equal(await b.session.open(reboundBoth, m0), null);
  assert.equal(await a.session.open(t0, m0), null);
  assert.equal(await a.session.open({ ...t0, to: side(a) }, m0), null);
  for (const holder of [a, b]) {
    assert.equal(
      await holder.exchange.openLegacy(
        {
          id: "m0",
          from: a.identity.identity,
          to: b.identity.identity,
          fromKey: a.exchange.publicRaw,
          toKey: b.exchange.publicRaw,
        },
        m0,
      ),
      null,
    );
  }
  const fresh = await SessionKeys.create();
  assert.equal(
    await fresh.open({ ...t0, to: { ...t0.to, session: fresh.session } }, m0),
    null,
  );

  const t2 = transcript(a, b, "m2");
  assert.equal(t2.from.epoch, 2);
  const m2 = await seal(t2, a, "after rotation");
  assert.equal(await b.session.open(t2, m2), "after rotation");
  assert.equal(
    await b.session.open(
      {
        ...t2,
        from: { ...t2.from, epoch: 0, ephemeral: keyA0 ?? new Uint8Array() },
      },
      m2,
    ),
    null,
  );
  assert.deepEqual(Object.keys(b.session), ["session"]);
  assert.equal(JSON.stringify(a.session).includes("privateKey"), false);
});

test("epoch transitions are strict and destruction is final", async () => {
  const a = await party();
  const b = await party();
  assert.equal(a.session.activate(1), false);
  const pending = await a.session.prepare();
  assert.equal(pending, 1);
  assert.equal(a.session.activate(2), false);
  a.session.discardPending();
  assert.equal(a.session.activate(1), false);
  assert.deepEqual(a.session.epochs, [0]);
  assert.equal(await a.session.bind(a.identity, a.exchange, "pending"), null);

  assert.equal(await rotate(a), 1);
  assert.equal(await rotate(a), 2);
  assert.deepEqual(a.session.epochs, [1, 2]);
  const t = transcript(a, b);
  const sealed = await seal(t, a, "x");
  const reply = transcript(b, a);
  const back = await seal(reply, b, "y");

  a.session.destroy();
  assert.equal(a.session.destroyed, true);
  assert.deepEqual(a.session.epochs, []);
  assert.equal(a.session.current, null);
  assert.equal(a.session.publicKeyOf(2), null);
  assert.equal(await a.session.prepare(), null);
  assert.equal(await a.session.seal(t, "after destroy"), null);
  assert.equal(await a.session.open(reply, back), null);
  assert.equal(await a.session.bind(a.identity, a.exchange, "current"), null);
  assert.equal(await b.session.open(t, sealed), "x");
});

test("sessions of the same identity are cryptographically isolated", async () => {
  const identity = await IdentityKey.generate();
  const exchange = await ExchangeKey.generate();
  const a1 = await party(identity, exchange);
  const a2 = await party(identity, exchange);
  const b = await party();
  assert.notEqual(a1.session.session, a2.session.session);

  const toA1 = transcript(b, a1);
  const sealed = await seal(toA1, b, "only a1");
  assert.equal(await a1.session.open(toA1, sealed), "only a1");
  assert.equal(await a2.session.open(toA1, sealed), null);
  assert.equal(await a2.session.open({ ...toA1, to: side(a2) }, sealed), null);
  assert.equal(
    await a2.session.open(
      { ...toA1, to: { ...side(a2), session: a1.session.session } },
      sealed,
    ),
    null,
  );

  const toA2 = transcript(b, a2, "m2");
  const other = await seal(toA2, b, "only a2");
  assert.notEqual(other.ciphertext, sealed.ciphertext);
  assert.equal(await a1.session.open(toA2, other), null);
  assert.equal(await a2.session.open(toA2, other), "only a2");
  await rotate(a1);
  assert.equal(await a2.session.open(toA2, other), "only a2");
  assert.deepEqual(a2.session.epochs, [0]);
});

test("session keys never reach persistent storage and reloads start fresh", async () => {
  const store = memoryStore();
  const state = await loadVault(store);
  assert.equal(state.status, "ready");
  const { keys } = state as Unlocked;
  const sessions = [await SessionKeys.create(), await SessionKeys.create()];
  for (const s of sessions) {
    for (let i = 0; i < 3; i++) {
      await s.prepare();
      s.activate((s.current?.epoch ?? 0) + 1);
    }
  }
  const stored = [...store.data.values()].flatMap((value) =>
    Object.values(value as Record<string, unknown>),
  );
  const cryptoKeys = stored.filter(
    (v) => v instanceof CryptoKey,
  ) as CryptoKey[];
  assert.deepEqual(cryptoKeys.map((k) => k.algorithm.name).sort(), [
    "AES-GCM",
    "Ed25519",
    "HMAC",
    "X25519",
  ]);
  const serialized = JSON.stringify([...store.data.entries()]);
  for (const s of sessions) {
    assert.ok(!serialized.includes(s.session));
    assert.ok(
      !serialized.includes(encodeBase64Url(s.current?.key ?? new Uint8Array())),
    );
  }

  const reloaded = await loadVault(store);
  assert.equal(reloaded.status, "ready");
  assert.equal(
    (reloaded as Unlocked).keys.identity.identity,
    keys.identity.identity,
  );
  const after = await SessionKeys.create();
  assert.ok(!sessions.some((s) => s.session === after.session));
  assert.deepEqual(after.epochs, [0]);
  assert.equal(store.writes, 1);
});

test("identity fingerprints are independent of ephemeral session rotation", async () => {
  const a = await party();
  const before = await fingerprint(a.identity.identity, a.exchange.publicKey);
  const bundles: string[] = [];
  for (let i = 0; i < 4; i++) {
    const bundle = await a.session.bind(a.identity, a.exchange, "current");
    assert.ok(bundle);
    bundles.push(bundle.key);
    await rotate(a);
  }
  assert.equal(new Set(bundles).size, 4);
  const replacement = await SessionKeys.create();
  assert.notEqual(replacement.session, a.session.session);
  assert.deepEqual(
    await fingerprint(a.identity.identity, a.exchange.publicKey),
    before,
  );
  const staticBundle = await a.exchange.bind(a.identity);
  assert.ok(staticBundle && !bundles.includes(staticBundle.key));
});
