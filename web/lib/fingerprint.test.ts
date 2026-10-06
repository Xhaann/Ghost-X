import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { ExchangeKey, keyBindingMessage, verifyBundle } from "./encryption.ts";
import {
  digitGroups,
  fingerprint,
  fingerprintSize,
  isCanonicalExchangeKey,
  isCanonicalIdentityKey,
} from "./fingerprint.ts";
import { IdentityKey } from "./identity.ts";

async function holder() {
  const [identity, exchange] = await Promise.all([
    IdentityKey.generate(),
    ExchangeKey.generate(),
  ]);
  return { identity, exchange };
}

function expected(identity: string, key: string) {
  const hash = createHash("sha512")
    .update("ghostx/fingerprint/v1\0")
    .update(Buffer.from(identity, "base64url"))
    .update(Buffer.from(key, "base64url"))
    .digest();
  const digits = Array.from({ length: digitGroups }, (_, g) =>
    String(Number(hash.readUIntBE(g * 5, 5) % 100000)).padStart(5, "0"),
  ).join(" ");
  return { value: hash.toString("base64url"), digits };
}

function bytes(fill: (raw: Uint8Array) => void): string {
  const raw = new Uint8Array(32);
  fill(raw);
  return encodeBase64Url(raw);
}

test("matches an independent SHA-512 over the canonical public keys", async () => {
  for (let i = 0; i < 20; i++) {
    const { identity, exchange } = await holder();
    const print = await fingerprint(identity.identity, exchange.publicKey);
    assert.deepEqual(print, expected(identity.identity, exchange.publicKey));
    assert.equal(decodeBase64Url(print?.value, fingerprintSize)?.length, 64);
    assert.match(print?.digits ?? "", /^\d{5}( \d{5}){7}$/);
  }
});

test("is deterministic and depends only on the identity and its bound key", async () => {
  const a = await holder();
  const b = await holder();
  const first = await fingerprint(a.identity.identity, a.exchange.publicKey);
  const again = await fingerprint(
    `${a.identity.identity}`,
    a.exchange.publicKey.slice(),
  );
  assert.deepEqual(first, again);

  const bundle = await a.exchange.bind(a.identity);
  assert.ok(bundle);
  assert.ok(await verifyBundle(bundle));
  assert.deepEqual(await fingerprint(bundle.identity, bundle.key), first);

  const otherIdentity = await fingerprint(
    b.identity.identity,
    a.exchange.publicKey,
  );
  const otherKey = await fingerprint(a.identity.identity, b.exchange.publicKey);
  const swapped = await fingerprint(a.exchange.publicKey, a.identity.identity);
  for (const other of [otherIdentity, otherKey]) {
    assert.ok(other);
    assert.notEqual(other.value, first?.value);
    assert.notEqual(other.digits, first?.digits);
  }
  assert.ok(swapped === null || swapped.value !== first?.value);
  assert.equal(fingerprint.length, 2);
});

test("distinguishes many keys in both the full and displayed form", async () => {
  const holders = await Promise.all(Array.from({ length: 40 }, holder));
  const prints = await Promise.all(
    holders.map((h) => fingerprint(h.identity.identity, h.exchange.publicKey)),
  );
  assert.equal(new Set(prints.map((p) => p?.value)).size, holders.length);
  assert.equal(new Set(prints.map((p) => p?.digits)).size, holders.length);
});

test("rejects malformed and non-canonical key encodings", async () => {
  const { identity, exchange } = await holder();
  const valid = [identity.identity, exchange.publicKey] as const;
  const prime = BigInt(2) ** BigInt(255) - BigInt(19);
  const p = prime.toString(16).padStart(64, "0");
  const le = (hex: string) =>
    bytes((raw) => raw.set(Buffer.from(hex, "hex").reverse()));
  const plus = (n: number) => le((prime + BigInt(n)).toString(16));

  const badKeys = [
    "",
    "A",
    `${exchange.publicKey}=`,
    `${exchange.publicKey}A`,
    exchange.publicKey.slice(1),
    exchange.publicKey.replace(/.$/, "+"),
    `${exchange.publicKey.slice(0, -1)}/`,
    le(p),
    plus(1),
    plus(18),
    bytes((raw) => {
      raw[31] = 0x80;
    }),
    null,
    42,
    { key: exchange.publicKey },
  ];
  for (const key of badKeys) {
    assert.equal(await fingerprint(valid[0], key), null, String(key));
  }
  const badIdentities = [
    "",
    `${identity.identity}=`,
    identity.identity.slice(1),
    le(p),
    plus(5),
    bytes((raw) => {
      raw[0] = 1;
      raw[31] = 0x80;
    }),
    null,
  ];
  for (const id of badIdentities) {
    assert.equal(await fingerprint(id, valid[1]), null, String(id));
  }

  const last = decodeBase64Url(exchange.publicKey, 32);
  assert.ok(last);
  last[31] |= 0x80;
  assert.equal(isCanonicalExchangeKey(last), false);
  const nonCanonical = encodeBase64Url(last);
  const signature = await identity.sign(
    keyBindingMessage(identity.identity, last),
  );
  assert.ok(signature);
  assert.equal(
    await verifyBundle({
      identity: identity.identity,
      key: nonCanonical,
      signature,
    }),
    null,
  );
  last[31] &= 0x7f;
  const canonicalSignature = await identity.sign(
    keyBindingMessage(identity.identity, last),
  );
  assert.ok(
    await verifyBundle({
      identity: identity.identity,
      key: encodeBase64Url(last),
      signature: canonicalSignature ?? "",
    }),
  );
  const below = Buffer.from(p, "hex").reverse();
  below[0] -= 1;
  assert.equal(isCanonicalExchangeKey(below), true);
  assert.equal(isCanonicalIdentityKey(below), true);
  assert.equal(isCanonicalIdentityKey(new Uint8Array(31)), false);
});

test("exposes only public material", async () => {
  const { identity, exchange } = await holder();
  const print = await fingerprint(identity.identity, exchange.publicKey);
  assert.deepEqual(Object.keys(print ?? {}).sort(), ["digits", "value"]);
  const pkcs8Like = /BEGIN|PRIVATE|"d":/;
  assert.ok(!pkcs8Like.test(JSON.stringify(print)));
  assert.deepEqual(print, expected(identity.identity, exchange.publicKey));
});
