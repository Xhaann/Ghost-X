import assert from "node:assert/strict";
import { test } from "node:test";
import { ExchangeKey, verifyBundle } from "./encryption.ts";
import { verify } from "./identity.ts";
import { legacyParty, legacySeal, memoryStore } from "./testing.ts";
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
  const peer = await legacyParty();
  const parties = {
    id: "m1",
    from: peer.identity.identity,
    to: a.keys.identity.identity,
    fromKey: peer.publicRaw,
    toKey: a.keys.exchange.publicRaw,
  };
  const sealed = await legacySeal(
    parties,
    peer.privateKey,
    a.keys.exchange.publicRaw,
    "continuity",
  );
  assert.equal(await b.keys.exchange.openLegacy(parties, sealed), "continuity");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const local = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    a.storage,
    new TextEncoder().encode("local"),
  );
  assert.equal(
    new TextDecoder().decode(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv }, b.storage, local),
    ),
    "local",
  );
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
    "storage",
    "v",
  ]);
  assert.equal(record.v, vaultVersion);
  assert.equal(record.identity, first.keys.identity.identity);
  assert.equal(record.exchangeKey, first.keys.exchange.publicKey);
  for (const name of ["signing", "exchange", "integrity", "storage"]) {
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
      storage: {},
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
  const shortAes = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 128 },
    false,
    ["encrypt", "decrypt"],
  );
  const looseAes = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
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
    "missing storage key": (() => {
      const { storage: _s, ...rest } = original;
      return rest;
    })(),
    "storage key with wrong algorithm": { ...original, storage: weakMac },
    "short storage key": { ...original, storage: shortAes },
    "extractable storage key": { ...original, storage: looseAes },
    "v1 record with storage key": { ...original, v: 1 },
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

function legacyOf(record: Record<string, unknown>): Record<string, unknown> {
  const { storage: _s, ...rest } = record;
  return { ...rest, v: 1 };
}

test("migrates a valid v1 vault to v2 exactly once", async () => {
  const origin = memoryStore();
  const first = await ready(origin);
  const v1 = legacyOf(stored(origin));
  const store = memoryStore();
  store.data.set("vault:keys", v1);

  const migrated = await ready(store);
  assert.equal(migrated.created, false);
  assert.equal(migrated.keys.identity.identity, first.keys.identity.identity);
  assert.equal(migrated.keys.exchange.publicKey, first.keys.exchange.publicKey);
  const record = stored(store);
  assert.equal(record.v, vaultVersion);
  assert.ok(record.storage instanceof CryptoKey);
  assert.equal((record.storage as CryptoKey).extractable, false);
  assert.equal(store.writes, 1);

  const again = await ready(store);
  await sameIdentity(migrated, again);
  assert.equal(store.writes, 1);
  assert.deepEqual(
    Object.values(record).filter((v) => v instanceof CryptoKey).length,
    4,
  );
});

test("concurrent v1 migrations converge on one storage key", async () => {
  const origin = memoryStore();
  await ready(origin);
  const store = memoryStore();
  store.data.set("vault:keys", legacyOf(stored(origin)));
  const results = await Promise.all(
    Array.from({ length: 6 }, () => ready(store)),
  );
  assert.equal(store.writes, 1);
  for (const result of results) {
    await sameIdentity(results[0], result);
  }
});

test("an interrupted migration leaves the v1 vault intact for a later retry", async () => {
  const origin = memoryStore();
  const first = await ready(origin);
  const v1 = legacyOf(stored(origin));
  const store = memoryStore();
  store.data.set("vault:keys", v1);
  const failing = {
    ...store,
    swap: async () => {
      throw new Error("write interrupted");
    },
  };
  await assert.rejects(loadVault(failing));
  assert.deepEqual(store.data.get("vault:keys"), v1);
  assert.equal(store.writes, 0);
  const retried = await ready(store);
  assert.equal(retried.keys.identity.identity, first.keys.identity.identity);
  assert.equal(stored(store).v, vaultVersion);
});

test("corrupted v1 vaults fail closed without migration", async () => {
  const origin = memoryStore();
  await ready(origin);
  const v1 = legacyOf(stored(origin));
  const other = memoryStore();
  await ready(other);
  const { integrity: _i, ...noIntegrity } = v1;
  for (const [name, record] of Object.entries({
    "substituted identity": { ...v1, identity: stored(other).identity },
    "missing integrity": noIntegrity,
    "extra field": { ...v1, extra: true },
    "substituted exchange key": {
      ...v1,
      exchangeKey: stored(other).exchangeKey,
    },
  })) {
    const store = memoryStore();
    store.data.set("vault:keys", record);
    assert.equal((await loadVault(store)).status, "corrupted", name);
    assert.equal(store.writes, 0, name);
    assert.equal(store.data.get("vault:keys"), record, name);
  }
});
