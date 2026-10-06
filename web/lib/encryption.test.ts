import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  ExchangeKey,
  type Parties,
  type Sealed,
  associatedData,
  keyBindingMessage,
  verifyBundle,
} from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import {
  exchangeKeySize,
  ivSize,
  maxBodySize,
  maxCiphertextSize,
  saltSize,
  tagSize,
} from "./protocol.ts";

type Holder = { identity: IdentityKey; exchange: ExchangeKey };

async function holder(): Promise<Holder> {
  const [identity, exchange] = await Promise.all([
    IdentityKey.generate(),
    ExchangeKey.generate(),
  ]);
  return { identity, exchange };
}

function parties(from: Holder, to: Holder, id = "m1"): Parties {
  return {
    id,
    from: from.identity.identity,
    to: to.identity.identity,
    fromKey: from.exchange.publicRaw,
    toKey: to.exchange.publicRaw,
  };
}

async function seal(from: Holder, to: Holder, body: string, id = "m1") {
  const sealed = await from.exchange.seal(parties(from, to, id), body);
  assert.ok(sealed);
  return sealed;
}

function flip(text: string, index = 0): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 0x01;
  return encodeBase64Url(bytes);
}

test("generates distinct exchange keys with non-extractable private parts", async () => {
  const keys = await Promise.all(
    Array.from({ length: 20 }, () => ExchangeKey.generate()),
  );

  assert.equal(new Set(keys.map((k) => k.publicKey)).size, keys.length);
  for (const key of keys) {
    assert.equal(key.publicRaw.length, exchangeKeySize);
    assert.equal(decodeBase64Url(key.publicKey, exchangeKeySize)?.length, 32);
    assert.deepEqual(Object.keys(key), ["publicKey"]);
    assert.equal(
      JSON.stringify(key),
      JSON.stringify({ publicKey: key.publicKey }),
    );
  }
  const copy = keys[0].publicRaw;
  copy[0] ^= 0xff;
  assert.notDeepEqual(copy, keys[0].publicRaw);
});

test("binds the exchange key to the identity", async () => {
  const a = await holder();
  const b = await holder();
  const bundle = await a.exchange.bind(a.identity);
  assert.ok(bundle);
  assert.equal(bundle.identity, a.identity.identity);
  assert.equal(bundle.key, a.exchange.publicKey);

  assert.deepEqual(await verifyBundle(bundle), a.exchange.publicRaw);

  const foreign = await a.exchange.bind(b.identity);
  assert.ok(foreign);
  assert.equal(
    await verifyBundle({ ...foreign, identity: a.identity.identity }),
    null,
  );
  assert.equal(
    await verifyBundle({ ...bundle, key: b.exchange.publicKey }),
    null,
  );
  assert.equal(
    await verifyBundle({ ...bundle, identity: b.identity.identity }),
    null,
  );
  assert.equal(await verifyBundle({ ...bundle, key: "short" }), null);
  assert.equal(
    await verifyBundle({ ...bundle, signature: flip(bundle.signature) }),
    null,
  );
  const contextSwap = await a.identity.sign(
    keyBindingMessage(b.identity.identity, a.exchange.publicRaw),
  );
  assert.equal(
    await verifyBundle({ ...bundle, signature: contextSwap ?? "" }),
    null,
  );
});

test("encrypts and decrypts between two holders", async () => {
  const a = await holder();
  const b = await holder();
  const body = "hello 🌍 \n\t multi-line";
  const sealed = await seal(a, b, body);

  assert.equal(await b.exchange.open(parties(a, b), sealed), body);
  assert.ok(
    !sealed.ciphertext.includes(
      encodeBase64Url(new TextEncoder().encode(body)),
    ),
  );
  assert.equal(
    decodeBase64Url(
      sealed.ciphertext,
      new TextEncoder().encode(body).length + tagSize,
    )?.length,
    new TextEncoder().encode(body).length + tagSize,
  );
});

test("uses a fresh salt and nonce for every message", async () => {
  const a = await holder();
  const b = await holder();
  const sealed = await Promise.all(
    Array.from({ length: 50 }, () => seal(a, b, "same")),
  );

  assert.equal(new Set(sealed.map((s) => s.salt)).size, sealed.length);
  assert.equal(new Set(sealed.map((s) => s.iv)).size, sealed.length);
  assert.equal(new Set(sealed.map((s) => s.ciphertext)).size, sealed.length);
  for (const s of sealed) {
    assert.ok(decodeBase64Url(s.salt, saltSize));
    assert.ok(decodeBase64Url(s.iv, ivSize));
  }
});

test("only the intended recipient can decrypt", async () => {
  const a = await holder();
  const b = await holder();
  const c = await holder();
  const sealed = await seal(a, b, "for b only");

  assert.equal(await c.exchange.open(parties(a, b), sealed), null);
  assert.equal(
    await c.exchange.open(
      { ...parties(a, b), toKey: c.exchange.publicRaw },
      sealed,
    ),
    null,
  );
  assert.equal(await a.exchange.open(parties(a, b), sealed), null);
  assert.equal(
    await b.exchange.open(
      { ...parties(a, b), fromKey: c.exchange.publicRaw },
      sealed,
    ),
    null,
  );
});

test("detects tampering with ciphertext, nonce, and salt", async () => {
  const a = await holder();
  const b = await holder();
  const sealed = await seal(a, b, "integrity");
  const p = parties(a, b);

  const mutations: Sealed[] = [
    { ...sealed, ciphertext: flip(sealed.ciphertext, 0) },
    { ...sealed, ciphertext: flip(sealed.ciphertext, 9) },
    { ...sealed, iv: flip(sealed.iv) },
    { ...sealed, salt: flip(sealed.salt) },
    { ...sealed, ciphertext: sealed.ciphertext.slice(0, -2) },
  ];
  for (const m of mutations) {
    assert.equal(await b.exchange.open(p, m), null);
  }
  assert.equal(await b.exchange.open(p, sealed), "integrity");
});

test("binds message id, sender, and recipient as associated data", async () => {
  const a = await holder();
  const b = await holder();
  const c = await holder();
  const sealed = await seal(a, b, "bound", "m1");

  assert.equal(
    await b.exchange.open({ ...parties(a, b), id: "m2" }, sealed),
    null,
  );
  assert.equal(
    await b.exchange.open(
      { ...parties(a, b), from: c.identity.identity },
      sealed,
    ),
    null,
  );
  assert.equal(
    await b.exchange.open(
      { ...parties(a, b), to: c.identity.identity },
      sealed,
    ),
    null,
  );

  const base = associatedData(parties(a, b, "m1"));
  assert.ok(base);
  assert.notDeepEqual(associatedData(parties(a, b, "m2")), base);
  assert.notDeepEqual(associatedData(parties(b, a, "m1")), base);
  assert.equal(associatedData({ ...parties(a, b), id: "" }), null);
  assert.equal(associatedData({ ...parties(a, b), from: "bad" }), null);
  assert.notDeepEqual(
    associatedData(parties(a, b, "ab")),
    associatedData({ ...parties(a, b, "a"), id: "a" }),
  );
});

test("rejects malformed envelopes and wrong key roles without throwing", async () => {
  const a = await holder();
  const b = await holder();
  const sealed = await seal(a, b, "x");
  const p = parties(a, b);

  for (const bad of [
    { ...sealed, salt: "" },
    { ...sealed, salt: sealed.salt + "A" },
    { ...sealed, iv: sealed.iv + "=" },
    { ...sealed, iv: "+" + sealed.iv.slice(1) },
    { ...sealed, ciphertext: "" },
    { ...sealed, ciphertext: encodeBase64Url(new Uint8Array(tagSize)) },
    { ...sealed, ciphertext: "not base64!" },
    { ...sealed, ciphertext: "A".repeat(10000) },
  ]) {
    assert.equal(await b.exchange.open(p, bad), null);
  }

  assert.equal(await a.exchange.seal(parties(b, a), "wrong sender key"), null);
  assert.equal(await a.exchange.open(parties(b, a), sealed), null);
  assert.equal(
    await b.exchange.open(
      { ...p, fromKey: new Uint8Array(exchangeKeySize) },
      sealed,
    ),
    null,
  );
});

test("handles the maximum body size", async () => {
  const a = await holder();
  const b = await holder();
  const body = "a".repeat(maxBodySize);
  const sealed = await seal(a, b, body);

  assert.equal(
    decodeBase64Url(sealed.ciphertext, maxCiphertextSize)?.length,
    maxCiphertextSize,
  );
  assert.equal(await b.exchange.open(parties(a, b), sealed), body);
});

test("released keys can no longer encrypt, decrypt, or bind", async () => {
  const a = await holder();
  const b = await holder();
  const sealed = await seal(a, b, "before release");

  b.exchange.release();
  b.exchange.release();
  assert.equal(b.exchange.released, true);
  assert.equal(await b.exchange.open(parties(a, b), sealed), null);

  a.exchange.release();
  assert.equal(await a.exchange.seal(parties(a, b), "after"), null);

  a.identity.release();
  const fresh = await ExchangeKey.generate();
  assert.equal(await fresh.bind(a.identity), null);
});

test("a regenerated key cannot open messages sealed for the old key", async () => {
  const a = await holder();
  const b = await holder();
  const sealed = await seal(a, b, "old key");
  const rotated: Holder = {
    identity: b.identity,
    exchange: await ExchangeKey.generate(),
  };

  assert.equal(await rotated.exchange.open(parties(a, b), sealed), null);
  assert.equal(await rotated.exchange.open(parties(a, rotated), sealed), null);
});
