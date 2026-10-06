import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { ExchangeKey } from "./encryption.ts";
import {
  type ResponderKeys,
  type Transcript,
  type VerifiedBundle,
  confirmAcceptance,
  initiate,
  prekeyBindingMessage,
  proofMessage,
  respond,
  signPrekey,
  transcriptBytes,
  verifyPrekey,
} from "./handshake.ts";
import { IdentityKey } from "./identity.ts";

type Party = { identity: IdentityKey; exchange: ExchangeKey };
type Slot = { id: number; key: Uint8Array<ArrayBuffer>; privateKey: CryptoKey };

const device = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));

async function party(): Promise<Party> {
  return {
    identity: await IdentityKey.generate(),
    exchange: await ExchangeKey.generate(),
  };
}

async function slot(id: number): Promise<Slot> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  return {
    id,
    key: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
    privateKey: pair.privateKey,
  };
}

async function recipient(withOnetime = true) {
  const owner = await party();
  const signed = await slot(7);
  const onetime = withOnetime ? await slot(42) : null;
  const bundle: VerifiedBundle = {
    identity: owner.identity.identity,
    staticKey: owner.exchange.publicRaw,
    device,
    signed: { id: signed.id, key: signed.key },
    onetime: onetime ? { id: onetime.id, key: onetime.key } : null,
  };
  const keys: ResponderKeys = { signed, onetime };
  return { owner, bundle, keys };
}

async function same(
  a: CryptoKey | Uint8Array,
  b: CryptoKey | Uint8Array,
): Promise<boolean> {
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    return (
      a instanceof Uint8Array &&
      b instanceof Uint8Array &&
      encodeBase64Url(a) === encodeBase64Url(b)
    );
  }
  const data = new TextEncoder().encode("probe");
  const [x, y] = await Promise.all([
    crypto.subtle.sign("HMAC", a, data),
    crypto.subtle.sign("HMAC", b, data),
  ]);
  return (
    encodeBase64Url(new Uint8Array(x)) === encodeBase64Url(new Uint8Array(y))
  );
}

function flip(text: string, index = 0): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 1;
  return encodeBase64Url(bytes);
}

test("signed and one-time prekeys are bound to identity, static key, device, id, and kind", async () => {
  const owner = await party();
  const other = await party();
  const key = (await slot(1)).key;
  const signed = await signPrekey(
    "signed",
    owner.identity,
    owner.exchange.publicRaw,
    device,
    5,
    key,
  );
  assert.ok(signed);
  const verify = (
    o: Partial<{
      kind: "signed" | "onetime";
      identity: string;
      staticKey: Uint8Array;
      device: string;
    }>,
    p = signed,
  ) =>
    verifyPrekey(
      o.kind ?? "signed",
      o.identity ?? owner.identity.identity,
      o.staticKey ?? owner.exchange.publicRaw,
      o.device ?? device,
      p,
    );
  assert.deepEqual(await verify({}), key);
  const high = key.slice();
  high[31] |= 0x80;
  for (const [name, result] of [
    ["kind", await verify({ kind: "onetime" })],
    ["identity", await verify({ identity: other.identity.identity })],
    ["static key", await verify({ staticKey: other.exchange.publicRaw })],
    ["device", await verify({ device: encodeBase64Url(new Uint8Array(16)) })],
    ["id", await verify({}, { ...signed, id: 6 })],
    [
      "key",
      await verify(
        {},
        { ...signed, key: encodeBase64Url((await slot(2)).key) },
      ),
    ],
    [
      "signature",
      await verify({}, { ...signed, signature: flip(signed.signature) }),
    ],
    [
      "foreign signer",
      await verify(
        {},
        (await signPrekey(
          "signed",
          other.identity,
          owner.exchange.publicRaw,
          device,
          5,
          key,
        )) ?? signed,
      ),
    ],
    [
      "non-canonical key",
      await verify({}, { ...signed, key: encodeBase64Url(high) }),
    ],
    ["negative id", await verify({}, { ...signed, id: -1 })],
    ["short key", await verify({}, { ...signed, key: "AAAA" })],
  ] as const) {
    assert.equal(result, null, name);
  }
  const s = prekeyBindingMessage(
    "signed",
    owner.identity.identity,
    owner.exchange.publicRaw,
    device,
    5,
    key,
  );
  const o = prekeyBindingMessage(
    "onetime",
    owner.identity.identity,
    owner.exchange.publicRaw,
    device,
    5,
    key,
  );
  assert.ok(s && o);
  assert.notDeepEqual(s, o);
  assert.equal(s.length, 24 + 32 + 32 + 16 + 4 + 32);
});

test("initiator and responder derive the same root with and without a one-time prekey", async () => {
  for (const withOnetime of [true, false]) {
    const a = await party();
    const b = await recipient(withOnetime);
    const started = await initiate(a, b.bundle);
    assert.ok(started);
    assert.equal(started.initiation.onetime, withOnetime ? 42 : null);
    const done = await respond(b.owner, b.keys, {
      from: a.identity.identity,
      fromStatic: a.exchange.publicRaw,
      ...started.initiation,
    });
    assert.ok(done);
    assert.equal(done.id, started.pending.id);
    assert.ok(await same(done.secret, started.pending.secret));
    assert.equal(
      await confirmAcceptance(
        started.pending.responder,
        started.pending.transcript,
        done.accept,
      ),
      true,
    );
    assert.equal(done.secret.length, 32);
    assert.equal(
      started.initiation.ratchet,
      encodeBase64Url(started.pending.ratchet.publicKey),
    );
    assert.equal(started.pending.ratchet.privateKey.extractable, false);
  }
});

test("every key-agreement input changes the derived root", async () => {
  const a = await party();
  const b = await recipient();
  const base = await initiate(a, b.bundle);
  const again = await initiate(a, b.bundle);
  assert.ok(base && again);
  assert.notEqual(base.initiation.ephemeral, again.initiation.ephemeral);
  assert.notEqual(base.pending.id, again.pending.id);
  assert.equal(await same(base.pending.secret, again.pending.secret), false);
  const variants: VerifiedBundle[] = [
    { ...b.bundle, signed: { id: 7, key: (await slot(7)).key } },
    { ...b.bundle, onetime: { id: 42, key: (await slot(42)).key } },
    { ...b.bundle, onetime: null },
    { ...b.bundle, staticKey: (await ExchangeKey.generate()).publicRaw },
    { ...b.bundle, identity: (await IdentityKey.generate()).identity },
  ];
  for (const variant of variants) {
    const other = await initiate(a, variant);
    assert.ok(other);
    assert.equal(await same(other.pending.secret, base.pending.secret), false);
  }
  const otherInitiator = await initiate(await party(), b.bundle);
  assert.ok(otherInitiator);
  assert.equal(
    await same(otherInitiator.pending.secret, base.pending.secret),
    false,
  );
});

test("the responder rejects any modified transcript, proof, or confirmation", async () => {
  const a = await party();
  const b = await recipient();
  const c = await party();
  const started = await initiate(a, b.bundle);
  assert.ok(started);
  const valid = {
    from: a.identity.identity,
    fromStatic: a.exchange.publicRaw,
    ...started.initiation,
  };
  const otherSlot = await slot(42);
  const cases: [string, ResponderKeys, typeof valid][] = [
    ["sender identity", b.keys, { ...valid, from: c.identity.identity }],
    [
      "sender static key",
      b.keys,
      { ...valid, fromStatic: c.exchange.publicRaw },
    ],
    [
      "device",
      b.keys,
      { ...valid, device: encodeBase64Url(new Uint8Array(16)) },
    ],
    [
      "ephemeral",
      b.keys,
      { ...valid, ephemeral: encodeBase64Url((await slot(1)).key) },
    ],
    ["proof", b.keys, { ...valid, proof: flip(valid.proof) }],
    ["confirm", b.keys, { ...valid, confirm: flip(valid.confirm) }],
    ["signed id", { ...b.keys, signed: { ...b.keys.signed, id: 8 } }, valid],
    [
      "signed private key",
      { ...b.keys, signed: { ...(await slot(7)), key: b.keys.signed.key } },
      valid,
    ],
    [
      "one-time id",
      { ...b.keys, onetime: b.keys.onetime && { ...b.keys.onetime, id: 43 } },
      valid,
    ],
    [
      "one-time private key",
      {
        ...b.keys,
        onetime: { ...otherSlot, key: b.keys.onetime?.key ?? otherSlot.key },
      },
      valid,
    ],
    ["one-time omitted", { ...b.keys, onetime: null }, valid],
  ];
  for (const [name, keys, initiation] of cases) {
    assert.equal(await respond(b.owner, keys, initiation), null, name);
  }
  const forged = await c.identity.sign(
    proofMessage({
      initiator: a.identity.identity,
      responder: b.owner.identity.identity,
      initiatorStatic: a.exchange.publicRaw,
      responderStatic: b.owner.exchange.publicRaw,
      device,
      signed: { id: 7, key: b.keys.signed.key },
      onetime: b.keys.onetime && { id: 42, key: b.keys.onetime.key },
      ephemeral: decodeBase64Url(valid.ephemeral, 32) ?? new Uint8Array(),
      ratchet: decodeBase64Url(valid.ratchet, 32) ?? new Uint8Array(),
    }) ?? new Uint8Array(),
  );
  assert.equal(
    await respond(b.owner, b.keys, { ...valid, proof: forged ?? "" }),
    null,
  );
  const wrongResponder = await party();
  assert.equal(await respond(wrongResponder, b.keys, valid), null);
  assert.ok(await respond(b.owner, b.keys, valid));
});

test("roles and derivation domains are separated", async () => {
  const a = await party();
  const b = await recipient();
  const started = await initiate(a, b.bundle);
  assert.ok(started);
  const done = await respond(b.owner, b.keys, {
    from: a.identity.identity,
    fromStatic: a.exchange.publicRaw,
    ...started.initiation,
  });
  assert.ok(done);
  assert.equal(
    await confirmAcceptance(
      started.pending.responder,
      started.pending.transcript,
      started.initiation.confirm,
    ),
    false,
  );
  assert.equal(
    await confirmAcceptance(
      started.pending.responder,
      started.pending.transcript,
      flip(done.accept),
    ),
    false,
  );
  assert.equal(await same(done.secret, started.pending.responder), false);
  const reversed = await respond(a, b.keys, {
    from: b.owner.identity.identity,
    fromStatic: b.owner.exchange.publicRaw,
    ...started.initiation,
  });
  assert.equal(reversed, null);
});

test("transcripts are canonical and fixed-length", async () => {
  const a = await party();
  const b = await recipient();
  const t: Transcript = {
    initiator: a.identity.identity,
    responder: b.owner.identity.identity,
    initiatorStatic: a.exchange.publicRaw,
    responderStatic: b.owner.exchange.publicRaw,
    device,
    signed: { id: 7, key: b.keys.signed.key },
    onetime: { id: 42, key: b.keys.onetime?.key ?? new Uint8Array(32) },
    ephemeral: (await slot(1)).key,
    ratchet: (await slot(3)).key,
  };
  const full = transcriptBytes(t);
  const short = transcriptBytes({ ...t, onetime: null });
  assert.ok(full && short);
  assert.equal(full.length, 15 + 32 * 4 + 16 + 4 + 32 + 1 + 4 + 32 + 32 + 32);
  assert.equal(short.length, full.length - 36);
  assert.equal(new TextDecoder().decode(full.slice(0, 15)), "ghostx/x3dh/v2\0");
  const proof = proofMessage(t);
  assert.ok(proof);
  assert.equal(
    new TextDecoder().decode(proof.slice(0, 24)),
    "ghostx/x3dh/initiate/v2\0",
  );
  for (const bad of [
    { ...t, initiator: "x" },
    { ...t, device: "AAAA" },
    { ...t, signed: { id: -1, key: t.signed.key } },
    { ...t, ephemeral: new Uint8Array(31) },
    { ...t, ratchet: new Uint8Array(31) },
  ]) {
    assert.equal(transcriptBytes(bad), null);
  }
});

test("each side must hold its long-term exchange private key", async () => {
  const a = await party();
  const b = await recipient();
  const impostor = (real: ExchangeKey) =>
    ({
      publicRaw: real.publicRaw,
      publicKey: real.publicKey,
      agree: async () => crypto.getRandomValues(new Uint8Array(32)),
    }) as unknown as ExchangeKey;

  const started = await initiate(a, b.bundle);
  assert.ok(started);
  const initiation = {
    from: a.identity.identity,
    fromStatic: a.exchange.publicRaw,
    ...started.initiation,
  };
  assert.equal(
    await respond(
      { identity: b.owner.identity, exchange: impostor(b.owner.exchange) },
      b.keys,
      initiation,
    ),
    null,
  );

  const forged = await initiate(
    { identity: a.identity, exchange: impostor(a.exchange) },
    b.bundle,
  );
  assert.ok(forged);
  assert.equal(
    await respond(b.owner, b.keys, {
      from: a.identity.identity,
      fromStatic: a.exchange.publicRaw,
      ...forged.initiation,
    }),
    null,
  );
  assert.ok(await respond(b.owner, b.keys, initiation));
});

test("the root, identifier, and confirmations bind the entire transcript", async () => {
  const { derive } = await import("./handshake.ts");
  const a = await party();
  const b = await recipient();
  const secrets = [1, 2, 3, 4].map(() =>
    crypto.getRandomValues(new Uint8Array(32)),
  );
  const base: Transcript = {
    initiator: a.identity.identity,
    responder: b.owner.identity.identity,
    initiatorStatic: a.exchange.publicRaw,
    responderStatic: b.owner.exchange.publicRaw,
    device,
    signed: { id: 7, key: b.keys.signed.key },
    onetime: { id: 42, key: b.keys.onetime?.key ?? new Uint8Array(32) },
    ephemeral: (await slot(1)).key,
    ratchet: (await slot(3)).key,
  };
  const variants: Record<string, Transcript> = {
    device: { ...base, device: encodeBase64Url(new Uint8Array(16)) },
    "signed id": { ...base, signed: { ...base.signed, id: 8 } },
    "one-time id": {
      ...base,
      onetime: { id: 43, key: base.onetime?.key ?? new Uint8Array(32) },
    },
    "one-time absent": { ...base, onetime: null },
    initiator: { ...base, initiator: b.owner.identity.identity },
    responder: { ...base, responder: a.identity.identity },
    ephemeral: { ...base, ephemeral: (await slot(2)).key },
    ratchet: { ...base, ratchet: (await slot(4)).key },
  };
  const bytes = transcriptBytes(base);
  assert.ok(bytes);
  const reference = await derive(secrets, bytes);
  const again = await derive(secrets, bytes);
  assert.equal(again.id, reference.id);
  assert.ok(await same(again.secret, reference.secret));
  for (const [name, variant] of Object.entries(variants)) {
    const other = transcriptBytes(variant);
    assert.ok(other, name);
    const derived = await derive(secrets, other);
    assert.notEqual(derived.id, reference.id, name);
    assert.equal(await same(derived.secret, reference.secret), false, name);
    assert.equal(
      await same(derived.initiator, reference.initiator),
      false,
      name,
    );
    assert.equal(
      await same(derived.responder, reference.responder),
      false,
      name,
    );
  }
  assert.equal(await same(reference.initiator, reference.responder), false);
  assert.equal(reference.secret.length, 32);
});
