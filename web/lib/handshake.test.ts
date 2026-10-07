import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { ExchangeKey } from "./encryption.ts";
import {
  type DeviceRef,
  type OwnDevice,
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
import { memoryStore } from "./testing.ts";
import { type Keys, type Unlocked, createVault, linkVault } from "./vault.ts";

type Slot = { id: number; key: Uint8Array<ArrayBuffer>; privateKey: CryptoKey };

async function party(): Promise<Keys> {
  return ((await createVault(memoryStore())) as Unlocked).keys;
}

async function sibling(of: Keys): Promise<Keys> {
  return ((await linkVault(memoryStore(), of.identity)) as Unlocked).keys;
}

function ref(p: Keys): DeviceRef {
  return {
    id: p.deviceId,
    signing: p.device.identity,
    exchange: p.exchange.publicKey,
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
    identity: owner.identity,
    device: ref(owner),
    signed: { id: signed.id, key: signed.key },
    onetime: onetime ? { id: onetime.id, key: onetime.key } : null,
  };
  const keys: ResponderKeys = { signed, onetime };
  return { owner, bundle, keys };
}

type Started = {
  ephemeral: string;
  ratchet: string;
  proof: string;
  confirm: string;
};

function incoming(a: Keys, initiation: Started) {
  return {
    from: a.identity,
    fromDevice: ref(a),
    ephemeral: initiation.ephemeral,
    ratchet: initiation.ratchet,
    proof: initiation.proof,
    confirm: initiation.confirm,
  };
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

test("prekeys are bound to identity, device, device key, id, and kind by the device key", async () => {
  const owner = await party();
  const other = await party();
  const twin = await sibling(owner);
  const key = (await slot(1)).key;
  const signed = await signPrekey("signed", owner, 5, key);
  assert.ok(signed);
  const check = (
    device: Partial<DeviceRef>,
    p = signed,
    identity = owner.identity,
    kind: "signed" | "onetime" = "signed",
  ) => verifyPrekey(kind, identity, { ...ref(owner), ...device }, p);
  assert.deepEqual(await check({}), key);
  const high = key.slice();
  high[31] |= 0x80;
  const binding = prekeyBindingMessage(
    "signed",
    owner.identity,
    owner.deviceId,
    owner.exchange.publicRaw,
    5,
    key,
  );
  assert.ok(binding);
  const rootSigned = {
    ...signed,
    signature: (await owner.root?.sign(binding)) ?? "",
  };
  for (const [name, result] of [
    ["kind", await check({}, signed, owner.identity, "onetime")],
    ["identity", await check({}, signed, other.identity)],
    ["device id", await check({ id: twin.deviceId })],
    ["device key", await check({ signing: twin.device.identity })],
    ["exchange key", await check({ exchange: twin.exchange.publicKey })],
    ["id", await check({}, { ...signed, id: 6 })],
    [
      "key",
      await check({}, { ...signed, key: encodeBase64Url((await slot(2)).key) }),
    ],
    [
      "signature",
      await check({}, { ...signed, signature: flip(signed.signature) }),
    ],
    [
      "sibling signer",
      await check({}, (await signPrekey("signed", twin, 5, key)) ?? signed),
    ],
    ["identity root as signer", await check({}, rootSigned)],
    [
      "non-canonical key",
      await check({}, { ...signed, key: encodeBase64Url(high) }),
    ],
    ["negative id", await check({}, { ...signed, id: -1 })],
  ] as const) {
    assert.equal(result, null, name);
  }
  const onetime = prekeyBindingMessage(
    "onetime",
    owner.identity,
    owner.deviceId,
    owner.exchange.publicRaw,
    5,
    key,
  );
  assert.ok(onetime);
  assert.notDeepEqual(binding, onetime);
  assert.equal(binding.length, 24 + 32 + 16 + 32 + 4 + 32);
});

test("initiator and responder devices derive the same root with and without a one-time prekey", async () => {
  for (const withOnetime of [true, false]) {
    const a = await party();
    const b = await recipient(withOnetime);
    const started = await initiate(a, b.bundle);
    assert.ok(started);
    assert.equal(started.initiation.device, b.owner.deviceId);
    assert.equal(started.initiation.onetime, withOnetime ? 42 : null);
    const done = await respond(
      b.owner,
      b.keys,
      incoming(a, started.initiation),
    );
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
    assert.equal(started.pending.ratchet.privateKey.extractable, false);
  }
});

test("sessions with different devices of the same identity are cryptographically distinct", async () => {
  const a = await party();
  const a2 = await sibling(a);
  const b = await recipient();
  const fromA = await initiate(a, b.bundle);
  const fromA2 = await initiate(a2, b.bundle);
  assert.ok(fromA && fromA2);
  assert.notEqual(fromA.pending.id, fromA2.pending.id);
  assert.equal(await same(fromA.pending.secret, fromA2.pending.secret), false);
  const b2 = await sibling(b.owner);
  const toB2 = await initiate(a, { ...b.bundle, device: ref(b2) });
  assert.ok(toB2);
  assert.notEqual(toB2.pending.id, fromA.pending.id);
  const crossed = await respond(b.owner, b.keys, {
    ...incoming(a, fromA.initiation),
    fromDevice: ref(a2),
  });
  assert.equal(crossed, null);
});

test("every key-agreement input changes the derived root", async () => {
  const a = await party();
  const b = await recipient();
  const base = await initiate(a, b.bundle);
  assert.ok(base);
  const variants: VerifiedBundle[] = [
    { ...b.bundle, signed: { id: 7, key: (await slot(7)).key } },
    { ...b.bundle, onetime: { id: 42, key: (await slot(42)).key } },
    { ...b.bundle, onetime: null },
    {
      ...b.bundle,
      device: {
        ...b.bundle.device,
        exchange: (await ExchangeKey.generate()).publicKey,
      },
    },
    { ...b.bundle, identity: (await party()).identity },
  ];
  for (const variant of variants) {
    const other = await initiate(a, variant);
    assert.ok(other);
    assert.equal(await same(other.pending.secret, base.pending.secret), false);
  }
});

test("the responder rejects any modified transcript, proof, or confirmation", async () => {
  const a = await party();
  const a2 = await sibling(a);
  const b = await recipient();
  const c = await party();
  const started = await initiate(a, b.bundle);
  assert.ok(started);
  const valid = incoming(a, started.initiation);
  const cases: [string, ResponderKeys, typeof valid][] = [
    ["sender identity", b.keys, { ...valid, from: c.identity }],
    ["sender device", b.keys, { ...valid, fromDevice: ref(a2) }],
    [
      "sender device key",
      b.keys,
      { ...valid, fromDevice: { ...ref(a), signing: a2.device.identity } },
    ],
    [
      "sender exchange key",
      b.keys,
      { ...valid, fromDevice: { ...ref(a), exchange: c.exchange.publicKey } },
    ],
    [
      "ephemeral",
      b.keys,
      { ...valid, ephemeral: encodeBase64Url((await slot(1)).key) },
    ],
    ["proof", b.keys, { ...valid, proof: flip(valid.proof) }],
    ["confirm", b.keys, { ...valid, confirm: flip(valid.confirm) }],
    ["signed id", { ...b.keys, signed: { ...b.keys.signed, id: 8 } }, valid],
    ["one-time omitted", { ...b.keys, onetime: null }, valid],
  ];
  for (const [name, keys, initiation] of cases) {
    assert.equal(await respond(b.owner, keys, initiation), null, name);
  }
  const t: Transcript = {
    initiator: a.identity,
    initiatorDevice: a.deviceId,
    responder: b.owner.identity,
    responderDevice: b.owner.deviceId,
    initiatorStatic: a.exchange.publicRaw,
    responderStatic: b.owner.exchange.publicRaw,
    signed: { id: 7, key: b.keys.signed.key },
    onetime: b.keys.onetime && { id: 42, key: b.keys.onetime.key },
    ephemeral: decodeBase64Url(valid.ephemeral, 32) ?? new Uint8Array(),
    ratchet: decodeBase64Url(valid.ratchet, 32) ?? new Uint8Array(),
  };
  const input = proofMessage(t);
  assert.ok(input);
  for (const [name, signer] of [
    ["another identity's device", c.device],
    ["sibling device", a2.device],
    ["identity root", a.root],
  ] as const) {
    const forged: string | null | undefined = await signer?.sign(input);
    assert.equal(
      await respond(b.owner, b.keys, { ...valid, proof: forged ?? "" }),
      null,
      name,
    );
  }
  const b2 = await sibling(b.owner);
  assert.equal(await respond(b2, b.keys, valid), null);
  assert.ok(await respond(b.owner, b.keys, valid));
});

test("roles and derivation domains are separated", async () => {
  const a = await party();
  const b = await recipient();
  const started = await initiate(a, b.bundle);
  assert.ok(started);
  const done = await respond(b.owner, b.keys, incoming(a, started.initiation));
  assert.ok(done);
  assert.equal(
    await confirmAcceptance(
      started.pending.responder,
      started.pending.transcript,
      started.initiation.confirm,
    ),
    false,
  );
  assert.equal(await same(done.secret, started.pending.responder), false);
  const owner: OwnDevice = a;
  assert.equal(
    await respond(owner, b.keys, incoming(b.owner, started.initiation)),
    null,
  );
});

test("transcripts are canonical, fixed-length, and versioned", async () => {
  const a = await party();
  const b = await recipient();
  const t: Transcript = {
    initiator: a.identity,
    initiatorDevice: a.deviceId,
    responder: b.owner.identity,
    responderDevice: b.owner.deviceId,
    initiatorStatic: a.exchange.publicRaw,
    responderStatic: b.owner.exchange.publicRaw,
    signed: { id: 7, key: b.keys.signed.key },
    onetime: { id: 42, key: b.keys.onetime?.key ?? new Uint8Array(32) },
    ephemeral: (await slot(1)).key,
    ratchet: (await slot(3)).key,
  };
  const full = transcriptBytes(t);
  const short = transcriptBytes({ ...t, onetime: null });
  assert.ok(full && short);
  assert.equal(
    full.length,
    15 + 32 + 16 + 32 + 16 + 32 + 32 + 4 + 32 + 1 + 4 + 32 + 32 + 32,
  );
  assert.equal(short.length, full.length - 36);
  assert.equal(new TextDecoder().decode(full.slice(0, 15)), "ghostx/x3dh/v3\0");
  const proof = proofMessage(t);
  assert.ok(proof);
  assert.equal(
    new TextDecoder().decode(proof.slice(0, 24)),
    "ghostx/x3dh/initiate/v3\0",
  );
  for (const bad of [
    { ...t, initiator: "x" },
    { ...t, initiatorDevice: "AAAA" },
    { ...t, responderDevice: "AAAA" },
    { ...t, signed: { id: -1, key: t.signed.key } },
    { ...t, ephemeral: new Uint8Array(31) },
  ]) {
    assert.equal(transcriptBytes(bad), null);
  }
});

test("each device must hold its exchange private key", async () => {
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
  const initiation = incoming(a, started.initiation);
  const fake: OwnDevice = { ...b.owner, exchange: impostor(b.owner.exchange) };
  assert.equal(await respond(fake, b.keys, initiation), null);
  const forged = await initiate(
    { ...a, exchange: impostor(a.exchange) },
    b.bundle,
  );
  assert.ok(forged);
  assert.equal(
    await respond(b.owner, b.keys, incoming(a, forged.initiation)),
    null,
  );
  assert.ok(await respond(b.owner, b.keys, initiation));
});

test("the root, identifier, and confirmations bind the entire device transcript", async () => {
  const { derive } = await import("./handshake.ts");
  const a = await party();
  const a2 = await sibling(a);
  const b = await recipient();
  const secrets = [1, 2, 3, 4].map(() =>
    crypto.getRandomValues(new Uint8Array(32)),
  );
  const base: Transcript = {
    initiator: a.identity,
    initiatorDevice: a.deviceId,
    responder: b.owner.identity,
    responderDevice: b.owner.deviceId,
    initiatorStatic: a.exchange.publicRaw,
    responderStatic: b.owner.exchange.publicRaw,
    signed: { id: 7, key: b.keys.signed.key },
    onetime: { id: 42, key: b.keys.onetime?.key ?? new Uint8Array(32) },
    ephemeral: (await slot(1)).key,
    ratchet: (await slot(3)).key,
  };
  const variants: Record<string, Transcript> = {
    "initiator device": { ...base, initiatorDevice: a2.deviceId },
    "responder device": { ...base, responderDevice: a2.deviceId },
    "signed id": { ...base, signed: { ...base.signed, id: 8 } },
    "one-time absent": { ...base, onetime: null },
    initiator: { ...base, initiator: b.owner.identity },
    responder: { ...base, responder: a.identity },
    ephemeral: { ...base, ephemeral: (await slot(2)).key },
    ratchet: { ...base, ratchet: (await slot(4)).key },
  };
  const bytes = transcriptBytes(base);
  assert.ok(bytes);
  const reference = await derive(secrets, bytes);
  for (const [name, variant] of Object.entries(variants)) {
    const other = transcriptBytes(variant);
    assert.ok(other, name);
    const derived = await derive(secrets, other);
    assert.notEqual(derived.id, reference.id, name);
    assert.equal(await same(derived.secret, reference.secret), false, name);
  }
});
