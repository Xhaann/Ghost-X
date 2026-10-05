import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { IdentityKey, isIdentity, parseIdentity, verify } from "./identity.ts";

const groupOrder = BigInt(
  "7237005577332262213973186563042994240857116359379907606001950938285454250989",
);

const bytes = (text: string) => new TextEncoder().encode(text);

function flipLowBit(text: string): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = chars.indexOf(text.at(-1) ?? "");
  return text.slice(0, -1) + chars[last ^ 1];
}

function malleate(signature: string): string {
  const raw = decodeBase64Url(signature, 64);
  assert.ok(raw);
  let s = BigInt(0);
  for (let i = 63; i >= 32; i--) {
    s = (s << BigInt(8)) | BigInt(raw[i]);
  }
  s += groupOrder;
  for (let i = 32; i < 64; i++) {
    raw[i] = Number(s & BigInt(0xff));
    s >>= BigInt(8);
  }
  return encodeBase64Url(raw);
}

test("generates a canonical public identity", async () => {
  const key = await IdentityKey.generate();

  assert.equal(key.identity.length, 43);
  assert.match(key.identity, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(isIdentity(key.identity), true);
  assert.equal(encodeBase64Url(parseIdentity(key.identity)!), key.identity);
});

test("generates unique identities", async () => {
  const keys = await Promise.all(
    Array.from({ length: 100 }, () => IdentityKey.generate()),
  );
  assert.equal(new Set(keys.map((key) => key.identity)).size, keys.length);
});

test("signs and verifies", async () => {
  const key = await IdentityKey.generate();
  const data = bytes("ghostx test message");

  const signature = await key.sign(data);

  assert.ok(signature);
  assert.equal(signature.length, 86);
  assert.equal(await verify(key.identity, data, signature), true);
});

test("signs deterministically for identical bytes", async () => {
  const key = await IdentityKey.generate();

  const first = await key.sign(bytes("same"));
  const second = await key.sign(bytes("same"));

  assert.equal(first, second);
  assert.notEqual(first, await key.sign(bytes("other")));
});

test("rejects a modified message", async () => {
  const key = await IdentityKey.generate();
  const signature = await key.sign(bytes("ghostx test message"));

  assert.equal(
    await verify(key.identity, bytes("ghostx test messagE"), signature),
    false,
  );
  assert.equal(await verify(key.identity, bytes(""), signature), false);
});

test("rejects a signature from another identity", async () => {
  const [key, other] = await Promise.all([
    IdentityKey.generate(),
    IdentityKey.generate(),
  ]);
  const data = bytes("ghostx test message");

  assert.equal(await verify(other.identity, data, await key.sign(data)), false);
  assert.equal(await verify(key.identity, data, await other.sign(data)), false);
});

test("rejects malformed signatures", async () => {
  const key = await IdentityKey.generate();
  const data = bytes("ghostx test message");
  const signature = await key.sign(data);
  assert.ok(signature);

  const invalid: unknown[] = [
    undefined,
    null,
    42,
    {},
    "",
    signature.slice(0, -1),
    signature + "A",
    signature + "==",
    "A".repeat(1 << 20),
    signature.slice(0, 5) + "*" + signature.slice(6),
    "+" + signature.slice(1),
    flipLowBit(signature),
    malleate(signature),
    "A".repeat(86),
  ];
  for (const candidate of invalid) {
    assert.equal(
      await verify(key.identity, data, candidate),
      false,
      `accepted ${String(candidate).slice(0, 20)}`,
    );
  }
});

test("rejects malformed identities", async () => {
  const key = await IdentityKey.generate();
  const data = bytes("ghostx test message");
  const signature = await key.sign(data);

  const invalid: unknown[] = [
    undefined,
    null,
    7,
    [],
    "",
    key.identity.slice(0, -1),
    key.identity + "A",
    key.identity + "=",
    " " + key.identity.slice(1),
    "+" + key.identity.slice(1),
    key.identity.slice(0, 10) + "." + key.identity.slice(11),
    flipLowBit(key.identity),
    "A".repeat(1 << 20),
  ];
  for (const candidate of invalid) {
    assert.equal(parseIdentity(candidate), null);
    assert.equal(isIdentity(candidate), false);
    assert.equal(await verify(candidate, data, signature), false);
  }
});

test("exposes only the public identity", async () => {
  const key = await IdentityKey.generate();

  assert.deepEqual(Object.keys(key), ["identity"]);
  assert.equal(JSON.stringify(key), JSON.stringify({ identity: key.identity }));
  assert.equal("privateKey" in key, false);
  assert.ok(!String(Object.getOwnPropertyNames(key)).includes("private"));
});

test("stops signing after release", async () => {
  const key = await IdentityKey.generate();
  const identity = key.identity;

  assert.equal(key.released, false);
  key.release();
  key.release();

  assert.equal(key.released, true);
  assert.equal(await key.sign(bytes("x")), null);
  assert.equal(key.identity, identity);
});

test("handles concurrent signing and verification", async () => {
  const key = await IdentityKey.generate();
  const messages = Array.from({ length: 50 }, (_, i) => bytes(`message ${i}`));

  const signatures = await Promise.all(messages.map((m) => key.sign(m)));
  const results = await Promise.all(
    messages.map((m, i) => verify(key.identity, m, signatures[i])),
  );
  const crossed = await Promise.all(
    messages.map((m, i) =>
      verify(key.identity, m, signatures[(i + 1) % signatures.length]),
    ),
  );

  assert.ok(results.every(Boolean));
  assert.ok(crossed.every((result) => !result));
});

test("round-trips base64url strictly", () => {
  for (const size of [1, 2, 3, 31, 32, 33, 64]) {
    const raw = crypto.getRandomValues(new Uint8Array(size));
    const text = encodeBase64Url(raw);
    assert.deepEqual(decodeBase64Url(text, size), raw);
    assert.equal(decodeBase64Url(text, size + 1), null);
    assert.equal(decodeBase64Url(text + "=", size), null);
  }
});
