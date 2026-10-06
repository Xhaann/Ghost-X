import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { ExchangeKey } from "./encryption.ts";
import {
  type ResponderKeys,
  initiate,
  respond,
  verifyPrekey,
} from "./handshake.ts";
import { IdentityKey } from "./identity.ts";
import {
  PrekeyStore,
  consumedLimit,
  lowWater,
  maxLocalOnetime,
  parsePrekeys,
  poolSize,
  signedLifetime,
} from "./prekeys.ts";
import { memoryStore } from "./testing.ts";
import { type Unlocked, loadVault } from "./vault.ts";

type Store = ReturnType<typeof memoryStore>;

async function owner(store: Store = memoryStore()) {
  const state = await loadVault(store);
  assert.equal(state.status, "ready");
  const unlocked = state as Unlocked;
  const prekeys = await PrekeyStore.open(
    store,
    unlocked.keys,
    unlocked.integrity,
  );
  assert.ok(prekeys);
  return { store, ...unlocked, prekeys };
}

function record(store: Store) {
  return store.data.get("vault:prekeys") as Record<string, unknown>;
}

async function initiation(
  target: Awaited<ReturnType<typeof owner>>,
  useOnetime = true,
) {
  const a = {
    identity: await IdentityKey.generate(),
    exchange: await ExchangeKey.generate(),
  };
  const publication = await target.prekeys.publication();
  assert.ok(publication);
  const staticKey = target.keys.exchange.publicRaw;
  const signed = await verifyPrekey(
    "signed",
    target.keys.identity.identity,
    staticKey,
    publication.device,
    publication.signed,
  );
  const first = publication.onetime[0];
  const onetime = useOnetime
    ? await verifyPrekey(
        "onetime",
        target.keys.identity.identity,
        staticKey,
        publication.device,
        first,
      )
    : null;
  assert.ok(signed);
  const started = await initiate(a, {
    identity: target.keys.identity.identity,
    staticKey,
    device: publication.device,
    signed: { id: publication.signed.id, key: signed },
    onetime: onetime ? { id: first.id, key: onetime } : null,
  });
  assert.ok(started);
  const run = (keys: ResponderKeys) =>
    respond(target.keys, keys, {
      from: a.identity.identity,
      fromStatic: a.exchange.publicRaw,
      ...started.initiation,
    });
  return { a, started, run };
}

test("creates a bounded, signed, non-extractable prekey inventory once", async () => {
  const b = await owner();
  const stored = record(b.store);
  assert.ok(parsePrekeys(stored));
  assert.equal((stored.onetime as unknown[]).length, poolSize);
  const keys = [stored.signed, ...(stored.onetime as unknown[])].map(
    (slot) => (slot as { privateKey: CryptoKey }).privateKey,
  );
  for (const key of keys) {
    assert.equal(key.extractable, false);
    await assert.rejects(crypto.subtle.exportKey("pkcs8", key));
  }
  const publication = await b.prekeys.publication();
  assert.ok(publication);
  assert.equal(publication.device, b.prekeys.device);
  assert.equal(publication.onetime.length, poolSize);
  for (const p of [publication.signed, ...publication.onetime]) {
    assert.deepEqual(Object.keys(p).sort(), ["id", "key", "signature"]);
  }
  assert.ok(!JSON.stringify(publication).includes("privateKey"));
  const again = await PrekeyStore.open(b.store, b.keys, b.integrity);
  assert.ok(again);
  assert.equal(again.device, b.prekeys.device);
  assert.deepEqual(again.inventory, b.prekeys.inventory);

  const concurrent = memoryStore();
  const vault = await loadVault(concurrent);
  const u = vault as Unlocked;
  const stores = await Promise.all(
    Array.from({ length: 5 }, () =>
      PrekeyStore.open(concurrent, u.keys, u.integrity),
    ),
  );
  assert.equal(new Set(stores.map((s) => s?.device)).size, 1);
});

test("consumes a one-time prekey exactly once, even across concurrent tabs", async () => {
  const b = await owner();
  const tab = await PrekeyStore.open(b.store, b.keys, b.integrity);
  assert.ok(tab);
  const { started, run } = await initiation(b);
  const onetime = started.initiation.onetime as number;
  const results = await Promise.all([
    b.prekeys.consume(started.initiation.signed, onetime, run),
    tab.consume(started.initiation.signed, onetime, run),
  ]);
  assert.equal(results.filter((r) => r.status === "consumed").length, 1);
  assert.ok(!b.prekeys.inventory.onetime.includes(onetime));
  const replay = await b.prekeys.consume(
    started.initiation.signed,
    onetime,
    run,
  );
  assert.notEqual(replay.status, "consumed");
  const reopened = await PrekeyStore.open(b.store, b.keys, b.integrity);
  assert.ok(reopened && !reopened.inventory.onetime.includes(onetime));
});

test("replays without a one-time prekey are rejected by the consumed record", async () => {
  const b = await owner();
  const { started, run } = await initiation(b, false);
  const first = await b.prekeys.consume(started.initiation.signed, null, run);
  assert.equal(first.status, "consumed");
  assert.equal(
    (await b.prekeys.consume(started.initiation.signed, null, run)).status,
    "replay",
  );
  assert.equal(b.prekeys.inventory.onetime.length, poolSize);
});

test("failed derivations never consume key material", async () => {
  const b = await owner();
  const { started } = await initiation(b);
  const before = b.prekeys.inventory;
  const outcome = await b.prekeys.consume(
    started.initiation.signed,
    started.initiation.onetime,
    async () => null,
  );
  assert.equal(outcome.status, "rejected");
  assert.deepEqual(b.prekeys.inventory, before);
  assert.equal(
    (await b.prekeys.consume(99, null, async () => ({ id: "x" }))).status,
    "rejected",
  );
  assert.equal(
    (await b.prekeys.consume(before.signed, 9999, async () => ({ id: "x" })))
      .status,
    "rejected",
  );
});

test("replenishes below the low-water mark within a bounded inventory", async () => {
  const b = await owner();
  assert.equal(await b.prekeys.replenish(lowWater), false);
  assert.equal(await b.prekeys.replenish(lowWater - 1), true);
  const ids = b.prekeys.inventory.onetime;
  assert.equal(
    ids.length,
    Math.min(maxLocalOnetime, poolSize + poolSize - (lowWater - 1)),
  );
  assert.equal(new Set(ids).size, ids.length);
  for (let i = 0; i < 5; i++) {
    await b.prekeys.replenish(0);
  }
  const after = b.prekeys.inventory.onetime;
  assert.equal(after.length, maxLocalOnetime);
  assert.deepEqual(
    after,
    [...after].sort((x, y) => x - y),
  );
  assert.ok(after[0] > 1);
});

test("signed prekeys rotate on use with exactly one previous key retained", async () => {
  const b = await owner();
  const first = b.prekeys.inventory.signed;
  for (let i = 0; i < signedLifetime; i++) {
    const { started, run } = await initiation(b, false);
    assert.equal(
      (await b.prekeys.consume(started.initiation.signed, null, run)).status,
      "consumed",
    );
  }
  assert.equal(b.prekeys.inventory.signed, first + 1);
  assert.equal(b.prekeys.inventory.previous, first);
  assert.equal(await b.prekeys.rotate(), true);
  assert.equal(b.prekeys.inventory.previous, first + 1);
  const stored = record(b.store);
  assert.ok((stored.consumed as string[]).length <= consumedLimit);
  assert.ok(
    ![stored.signed, stored.previous].some(
      (s) => (s as { id: number }).id === first,
    ),
  );
});

test("corrupted prekey state fails closed without touching the identity", async () => {
  const b = await owner();
  const original = record(b.store);
  const cases: Record<string, unknown> = {
    "mac flipped": { ...original, mac: encodeBase64Url(new Uint8Array(32)) },
    "device changed": {
      ...original,
      device: encodeBase64Url(new Uint8Array(16)),
    },
    "consumed cleared": { ...original, consumed: ["AAAAAAAAAAAAAAAAAAAAAA"] },
    "onetime removed": { ...original, onetime: [] },
    "signed id": {
      ...original,
      signed: { ...(original.signed as object), id: 9 },
    },
    "future version": { ...original, v: 2 },
    "extra field": { ...original, extra: 1 },
    "duplicate onetime": {
      ...original,
      onetime: [
        (original.onetime as unknown[])[0],
        (original.onetime as unknown[])[0],
      ],
    },
    "extractable key": {
      ...original,
      signed: {
        ...(original.signed as object),
        privateKey: (
          (await crypto.subtle.generateKey({ name: "X25519" }, true, [
            "deriveBits",
          ])) as CryptoKeyPair
        ).privateKey,
      },
    },
    string: "prekeys",
  };
  for (const [name, value] of Object.entries(cases)) {
    b.store.data.set("vault:prekeys", value);
    assert.equal(
      await PrekeyStore.open(b.store, b.keys, b.integrity),
      null,
      name,
    );
    const vault = await loadVault(b.store);
    assert.equal(vault.status, "ready", name);
    assert.equal(
      (vault as Unlocked).keys.identity.identity,
      b.keys.identity.identity,
      name,
    );
    assert.equal(b.store.data.get("vault:prekeys"), value, name);
  }
});

function flipped(text: string): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[0] ^= 1;
  return encodeBase64Url(bytes);
}
