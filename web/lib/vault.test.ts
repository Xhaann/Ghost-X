import assert from "node:assert/strict";
import { test } from "node:test";
import { deriveDeviceId } from "./device.ts";
import { ExchangeKey } from "./encryption.ts";
import { IdentityKey, verify } from "./identity.ts";
import { legacyParty, legacySeal, memoryStore } from "./testing.ts";
import {
  type Unlocked,
  createVault,
  linkVault,
  loadVault,
  vaultVersion,
} from "./vault.ts";

type Store = ReturnType<typeof memoryStore>;

function ready(state: Awaited<ReturnType<typeof loadVault>>): Unlocked {
  assert.equal(state.status, "ready");
  return state as Unlocked;
}

function stored(store: Store) {
  return store.data.get("vault:keys") as Record<string, unknown>;
}

async function sameDevice(a: Unlocked, b: Unlocked): Promise<void> {
  assert.equal(a.keys.identity, b.keys.identity);
  assert.equal(a.keys.deviceId, b.keys.deviceId);
  assert.equal(a.keys.device.identity, b.keys.device.identity);
  assert.equal(a.keys.exchange.publicKey, b.keys.exchange.publicKey);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await b.keys.device.sign(challenge);
  assert.equal(
    await verify(a.keys.device.identity, challenge, signature),
    true,
  );
  if (a.keys.root) {
    const rootSignature = await b.keys.root?.sign(challenge);
    assert.equal(await verify(a.keys.identity, challenge, rootSignature), true);
  }
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

async function previousVault(version: 1 | 2): Promise<Record<string, unknown>> {
  const root = await IdentityKey.create();
  const exchange = await ExchangeKey.create();
  const integrity = await crypto.subtle.generateKey(
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign", "verify"],
  );
  const record: Record<string, unknown> = {
    v: version,
    identity: root.key.identity,
    signing: root.privateKey,
    exchangeKey: exchange.key.publicKey,
    exchange: exchange.privateKey,
    integrity,
  };
  if (version === 2) {
    record.storage = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }
  return record;
}

test("an empty store requires an explicit create or link", async () => {
  const store = memoryStore();
  assert.deepEqual(await loadVault(store), { status: "empty" });
  assert.equal(store.writes, 0);
});

test("creating an identity stores separate non-extractable root, device, and exchange keys", async () => {
  const store = memoryStore();
  const first = ready(await createVault(store));
  assert.equal(first.created, true);
  assert.ok(first.keys.root);
  assert.notEqual(first.keys.device.identity, first.keys.identity);
  assert.equal(
    first.keys.deviceId,
    await deriveDeviceId(first.keys.identity, first.keys.device.identity),
  );
  const record = stored(store);
  assert.deepEqual(Object.keys(record).sort(), [
    "device",
    "deviceKey",
    "exchange",
    "exchangeKey",
    "identity",
    "integrity",
    "root",
    "storage",
    "v",
  ]);
  assert.equal(record.v, vaultVersion);
  assert.notEqual(record.root, record.device);
  for (const name of ["root", "device", "exchange", "integrity", "storage"]) {
    const key = record[name] as CryptoKey;
    assert.ok(key instanceof CryptoKey, name);
    assert.equal(key.extractable, false, name);
    for (const format of ["raw", "pkcs8", "jwk"] as const) {
      await assert.rejects(crypto.subtle.exportKey(format, key));
    }
  }
  const again = ready(await loadVault(store));
  assert.equal(again.created, false);
  await sameDevice(first, again);
});

test("linking creates a device with its own keys and no root key", async () => {
  const origin = ready(await createVault(memoryStore()));
  const store = memoryStore();
  const linked = ready(await linkVault(store, origin.keys.identity));
  assert.equal(linked.keys.identity, origin.keys.identity);
  assert.equal(linked.keys.root, null);
  assert.equal(stored(store).root, null);
  assert.notEqual(linked.keys.deviceId, origin.keys.deviceId);
  assert.notEqual(linked.keys.device.identity, origin.keys.device.identity);
  assert.notEqual(
    linked.keys.exchange.publicKey,
    origin.keys.exchange.publicKey,
  );
  await sameDevice(linked, ready(await loadVault(store)));
  assert.equal(
    (await linkVault(memoryStore(), "not-an-identity")).status,
    "corrupted",
  );
});

test("concurrent creation installs exactly one device", async () => {
  const store = memoryStore();
  const results = (
    await Promise.all(Array.from({ length: 8 }, () => createVault(store)))
  ).map(ready);
  assert.equal(results.filter((r) => r.created).length, 1);
  assert.equal(new Set(results.map((r) => r.keys.deviceId)).size, 1);
  for (const result of results) {
    await sameDevice(results[0], result);
  }
  assert.equal(store.writes, 1);
});

test("corrupted or substituted key material fails closed without overwriting", async () => {
  const base = memoryStore();
  ready(await createVault(base));
  const original = stored(base);
  const other = memoryStore();
  ready(await createVault(other));
  const foreign = stored(other);
  const linkedStore = memoryStore();
  ready(await linkVault(linkedStore, original.identity as string));
  const linked = stored(linkedStore);
  const extractable = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const raw = async (key: CryptoKey) =>
    Buffer.from(await crypto.subtle.exportKey("raw", key)).toString(
      "base64url",
    );
  const { v: _v, ...withoutVersion } = original;
  const cases: Record<string, unknown> = {
    "future version": { ...original, v: vaultVersion + 1 },
    "missing version": withoutVersion,
    "unexpected field": { ...original, extra: 1 },
    "invalid identity": { ...original, identity: "not-an-identity" },
    "substituted identity": { ...original, identity: foreign.identity },
    "substituted root key": { ...original, root: foreign.root },
    "substituted device key": { ...original, device: foreign.device },
    "substituted device public key": {
      ...original,
      deviceKey: foreign.deviceKey,
    },
    "root key used as device key": {
      ...original,
      device: original.root,
      deviceKey: original.identity,
    },
    "linked device claiming the root": { ...linked, root: foreign.root },
    "substituted exchange key": {
      ...original,
      exchangeKey: foreign.exchangeKey,
    },
    "substituted exchange private key": {
      ...original,
      exchange: foreign.exchange,
    },
    "extractable device key": {
      ...original,
      device: extractable.privateKey,
      deviceKey: await raw(extractable.publicKey),
    },
    "raw bytes instead of key": { ...original, device: new Uint8Array(32) },
    "missing storage key": (() => {
      const { storage: _s, ...rest } = original;
      return rest;
    })(),
    "null record": null,
    "array record": [original],
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

test("a reset produces a genuinely new identity and device", async () => {
  const store = memoryStore();
  const first = ready(await createVault(store));
  await store.clear();
  assert.equal((await loadVault(store)).status, "empty");
  const fresh = ready(await createVault(store));
  assert.notEqual(fresh.keys.identity, first.keys.identity);
  assert.notEqual(fresh.keys.deviceId, first.keys.deviceId);
  assert.notEqual(fresh.keys.exchange.publicKey, first.keys.exchange.publicKey);
});

for (const version of [1, 2] as const) {
  test(`migrates a v${version} vault into a root device exactly once`, async () => {
    const previous = await previousVault(version);
    const store = memoryStore();
    store.data.set("vault:keys", previous);
    const migrated = ready(await loadVault(store));
    assert.equal(migrated.created, false);
    assert.equal(migrated.keys.identity, previous.identity);
    assert.equal(migrated.keys.exchange.publicKey, previous.exchangeKey);
    assert.ok(migrated.keys.root);
    assert.notEqual(migrated.keys.device.identity, migrated.keys.identity);
    const record = stored(store);
    assert.equal(record.v, vaultVersion);
    assert.equal(store.writes, 1);
    await sameDevice(migrated, ready(await loadVault(store)));
    assert.equal(store.writes, 1);

    const peer = await legacyParty();
    const parties = {
      id: "m1",
      from: peer.identity.identity,
      to: migrated.keys.identity,
      fromKey: peer.publicRaw,
      toKey: migrated.keys.exchange.publicRaw,
    };
    const sealed = await legacySeal(
      parties,
      peer.privateKey,
      migrated.keys.exchange.publicRaw,
      "continuity",
    );
    assert.equal(
      await migrated.keys.exchange.openLegacy(parties, sealed),
      "continuity",
    );
  });
}

test("concurrent migrations converge on one device", async () => {
  const store = memoryStore();
  store.data.set("vault:keys", await previousVault(2));
  const results = (
    await Promise.all(Array.from({ length: 6 }, () => loadVault(store)))
  ).map(ready);
  assert.equal(new Set(results.map((r) => r.keys.deviceId)).size, 1);
  for (const result of results) {
    await sameDevice(results[0], result);
  }
});

test("an interrupted migration leaves the previous vault intact", async () => {
  const previous = await previousVault(1);
  const store = memoryStore();
  store.data.set("vault:keys", previous);
  const failing = {
    ...store,
    swap: async () => {
      throw new Error("write interrupted");
    },
  };
  await assert.rejects(loadVault(failing));
  assert.equal(store.data.get("vault:keys"), previous);
  const retried = ready(await loadVault(store));
  assert.equal(retried.keys.identity, previous.identity);
});

test("corrupted previous vaults fail closed without migration", async () => {
  const previous = await previousVault(2);
  const other = await previousVault(2);
  for (const [name, record] of Object.entries({
    "substituted identity": { ...previous, identity: other.identity },
    "substituted exchange key": { ...previous, exchangeKey: other.exchangeKey },
    "extra field": { ...previous, extra: true },
  })) {
    const store = memoryStore();
    store.data.set("vault:keys", record);
    assert.equal((await loadVault(store)).status, "corrupted", name);
    assert.equal(store.writes, 0, name);
  }
});
