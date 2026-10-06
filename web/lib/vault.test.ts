import assert from "node:assert/strict";
import { test } from "node:test";
import { ExchangeKey, verifyBundle } from "./encryption.ts";
import { IdentityKey, verify } from "./identity.ts";
import { memoryStore } from "./testing.ts";
import { type Unlocked, loadVault, vaultVersion } from "./vault.ts";

async function ready(store: ReturnType<typeof memoryStore>): Promise<Unlocked> {
  const state = await loadVault(store);
  assert.equal(state.status, "ready");
  return state as Unlocked;
}

function stored(store: ReturnType<typeof memoryStore>) {
  return store.data.get("vault:keys") as Record<string, unknown>;
}

async function sameIdentity(a: Unlocked, b: Unlocked): Promise<void> {
  assert.equal(a.keys.identity.identity, b.keys.identity.identity);
  assert.equal(a.keys.exchange.publicKey, b.keys.exchange.publicKey);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await b.keys.identity.sign(challenge);
  assert.equal(
    await verify(a.keys.identity.identity, challenge, signature),
    true,
  );
  const peer = await ExchangeKey.generate();
  const peerIdentity = await IdentityKey.generate();
  const parties = {
    id: "m1",
    from: peerIdentity.identity,
    to: a.keys.identity.identity,
    fromKey: peer.publicRaw,
    toKey: a.keys.exchange.publicRaw,
  };
  const sealed = await peer.seal(parties, "continuity");
  assert.ok(sealed);
  assert.equal(await b.keys.exchange.open(parties, sealed), "continuity");
}

test("a fresh installation creates and stores non-extractable keys", async () => {
  const store = memoryStore();
  const first = await ready(store);

  assert.equal(first.created, true);
  const record = stored(store);
  assert.deepEqual(Object.keys(record).sort(), [
    "exchange",
    "exchangeKey",
    "identity",
    "integrity",
    "signing",
    "v",
  ]);
  assert.equal(record.v, vaultVersion);
  assert.equal(record.identity, first.keys.identity.identity);
  assert.equal(record.exchangeKey, first.keys.exchange.publicKey);
  for (const name of ["signing", "exchange", "integrity"]) {
    const key = record[name] as CryptoKey;
    assert.ok(key instanceof CryptoKey);
    assert.equal(key.extractable, false);
    for (const format of ["raw", "pkcs8", "jwk"] as const) {
      await assert.rejects(crypto.subtle.exportKey(format, key));
    }
  }
  assert.equal(
    JSON.stringify(record),
    JSON.stringify({
      v: vaultVersion,
      identity: record.identity,
      signing: {},
      exchangeKey: record.exchangeKey,
      exchange: {},
      integrity: {},
    }),
  );
});

test("a reload restores the identical identity and exchange key", async () => {
  const store = memoryStore();
  const first = await ready(store);
  const writes = store.writes;

  for (let i = 0; i < 3; i++) {
    const again = await ready(store);
    assert.equal(again.created, false);
    await sameIdentity(first, again);
    const bundle = await again.keys.exchange.bind(again.keys.identity);
    assert.ok(bundle);
    assert.deepEqual(await verifyBundle(bundle), first.keys.exchange.publicRaw);
  }
  assert.equal(store.writes, writes);
});

test("concurrent initialization creates exactly one identity", async () => {
  const store = memoryStore();
  const results = await Promise.all(
    Array.from({ length: 8 }, () => ready(store)),
  );

  assert.equal(results.filter((r) => r.created).length, 1);
  assert.equal(new Set(results.map((r) => r.keys.identity.identity)).size, 1);
  assert.equal(new Set(results.map((r) => r.keys.exchange.publicKey)).size, 1);
  for (const result of results) {
    await sameIdentity(results[0], result);
  }
  assert.equal(store.writes, 1);
});

test("corrupted or substituted key material fails closed without overwriting", async () => {
  const base = memoryStore();
  await ready(base);
  const original = stored(base);
  const other = memoryStore();
  await ready(other);
  const foreign = stored(other);
  const extractable = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const ecdh = (await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const aes = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const weakMac = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-1", length: 256 },
    false,
    ["sign", "verify"],
  );

  const loose = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const looseExchange = (await crypto.subtle.generateKey(
    { name: "X25519" },
    true,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const raw = async (key: CryptoKey) =>
    Buffer.from(await crypto.subtle.exportKey("raw", key)).toString(
      "base64url",
    );
  const { v: _v, ...withoutVersion } = original;
  const cases: Record<string, unknown> = {
    "future version": { ...original, v: vaultVersion + 1 },
    "string version": { ...original, v: String(vaultVersion) },
    "missing version": withoutVersion,
    "unexpected field": { ...original, extra: 1 },
    "invalid identity": { ...original, identity: "not-an-identity" },
    "substituted identity": { ...original, identity: foreign.identity },
    "substituted signing key": { ...original, signing: foreign.signing },
    "substituted exchange key": {
      ...original,
      exchangeKey: foreign.exchangeKey,
    },
    "substituted exchange private key": {
      ...original,
      exchange: foreign.exchange,
    },
    "extractable signing key": {
      ...original,
      signing: extractable.privateKey,
    },
    "public key as private": { ...original, signing: extractable.publicKey },
    "extractable matching signing key": {
      ...original,
      identity: await raw(loose.publicKey),
      signing: loose.privateKey,
    },
    "extractable matching exchange key": {
      ...original,
      exchangeKey: await raw(looseExchange.publicKey),
      exchange: looseExchange.privateKey,
    },
    "wrong exchange algorithm": { ...original, exchange: ecdh.privateKey },
    "wrong integrity algorithm": { ...original, integrity: aes },
    "weak integrity hash": { ...original, integrity: weakMac },
    "raw bytes instead of key": {
      ...original,
      exchange: new Uint8Array(32),
    },
    "malformed exchange key": { ...original, exchangeKey: "AAAA" },
    "null record": null,
    "array record": [original],
    "string record": "keys",
  };
  for (const [name, record] of Object.entries(cases)) {
    const store = memoryStore();
    store.data.set("vault:keys", record);
    const state = await loadVault(store);
    assert.equal(state.status, "corrupted", name);
    assert.equal(store.writes, 0, name);
    assert.equal(store.data.get("vault:keys"), record, name);
  }
});

test("only an explicit reset produces a different identity", async () => {
  const store = memoryStore();
  const first = await ready(store);
  store.data.set("messages:x", { v: 1 });

  await store.clear();
  assert.equal(store.data.size, 0);
  const fresh = await ready(store);
  assert.equal(fresh.created, true);
  assert.notEqual(fresh.keys.identity.identity, first.keys.identity.identity);
  assert.notEqual(fresh.keys.exchange.publicKey, first.keys.exchange.publicKey);

  const again = await ready(store);
  assert.equal(again.created, false);
  await sameIdentity(fresh, again);
});
