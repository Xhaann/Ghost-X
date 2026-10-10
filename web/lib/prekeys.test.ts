import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  type ResponderKeys,
  initiate,
  respond,
  verifyPrekey,
} from "./handshake.ts";
import {
  PrekeyStore,
  consumedLimit,
  legacyPrekeysVersion,
  lowWater,
  maxDirect,
  maxLocalOnetime,
  parsePrekeys,
  poolSize,
  prekeysVersion,
  signedLifetime,
} from "./prekeys.ts";
import { memoryStore } from "./testing.ts";
import { type Unlocked, createVault, loadVault } from "./vault.ts";
import type { DeviceEntry } from "./device.ts";

type Store = ReturnType<typeof memoryStore>;

async function owner(store: Store = memoryStore()) {
  const existing = await loadVault(store);
  const state =
    existing.status === "empty" ? await createVault(store) : existing;
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
  const initiator = (await createVault(memoryStore())) as Unlocked;
  const a = initiator.keys;
  const publication = await target.prekeys.publication();
  assert.ok(publication);
  const device: DeviceEntry = {
    id: target.keys.deviceId,
    signing: target.keys.device.identity,
    exchange: target.keys.exchange.publicKey,
  };
  assert.equal(publication.device, device.id);
  const signed = await verifyPrekey(
    "signed",
    target.keys.identity,
    device,
    publication.signed,
  );
  const first = publication.onetime[0];
  const onetime = useOnetime
    ? await verifyPrekey("onetime", target.keys.identity, device, first)
    : null;
  assert.ok(signed);
  const started = await initiate(a, {
    identity: target.keys.identity,
    device,
    signed: { id: publication.signed.id, key: signed },
    onetime: onetime ? { id: first.id, key: onetime } : null,
  });
  assert.ok(started);
  const run = (keys: ResponderKeys) =>
    respond(target.keys, keys, {
      from: a.identity,
      fromDevice: {
        id: a.deviceId,
        signing: a.device.identity,
        exchange: a.exchange.publicKey,
      },
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
  const u = (await createVault(concurrent)) as Unlocked;
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
    "future version": { ...original, v: prekeysVersion + 1 },
    "missing direct pool": (({ direct: _, ...rest }) => rest)(original),
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
    assert.equal((vault as Unlocked).keys.identity, b.keys.identity, name);
    assert.equal(b.store.data.get("vault:prekeys"), value, name);
  }
});

function flipped(text: string): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[0] ^= 1;
  return encodeBase64Url(bytes);
}

test("a previous single-device prekey state is replaced by one bound to this device", async () => {
  const b = await owner();
  const original = record(b.store);
  b.store.data.set("vault:prekeys", {
    ...original,
    v: 1,
    device: encodeBase64Url(new Uint8Array(16)),
  });
  const fresh = await PrekeyStore.open(b.store, b.keys, b.integrity);
  assert.ok(fresh);
  assert.equal(fresh.device, b.keys.deviceId);
  assert.equal(record(b.store).v, prekeysVersion);
  const publication = await fresh.publication();
  assert.ok(publication);
  assert.ok(
    await verifyPrekey(
      "signed",
      b.keys.identity,
      {
        id: b.keys.deviceId,
        signing: b.keys.device.identity,
        exchange: b.keys.exchange.publicKey,
      },
      publication.signed,
    ),
  );
  assert.equal(
    await verifyPrekey(
      "signed",
      b.keys.identity,
      {
        id: b.keys.deviceId,
        signing: b.keys.identity,
        exchange: b.keys.exchange.publicKey,
      },
      publication.signed,
    ),
    null,
  );
});

async function legacyRecord(b: Awaited<ReturnType<typeof owner>>) {
  const { direct: _, mac: __, ...rest } = record(b.store);
  const state: Record<string, unknown> = { ...rest, v: legacyPrekeysVersion };
  const slot = (value: unknown) =>
    value === null
      ? null
      : [(value as { id: number }).id, (value as { key: string }).key];
  const values = new TextEncoder().encode(
    JSON.stringify([
      state.v,
      state.device,
      state.nextSigned,
      state.nextOnetime,
      state.uses,
      slot(state.signed),
      slot(state.previous),
      (state.onetime as unknown[]).map(slot),
      state.consumed,
    ]),
  );
  const context = new TextEncoder().encode("ghostx/prekeys/v2\0");
  const input = new Uint8Array(context.length + values.length);
  input.set(context);
  input.set(values, context.length);
  const mac = await crypto.subtle.sign("HMAC", b.integrity, input);
  return { ...state, mac: encodeBase64Url(new Uint8Array(mac)) };
}

test("a version 2 prekey record migrates in place and keeps every key", async () => {
  const b = await owner();
  const before = record(b.store);
  b.store.data.set("vault:prekeys", await legacyRecord(b));
  const reopened = await PrekeyStore.open(b.store, b.keys, b.integrity);
  assert.ok(reopened);
  const after = record(b.store);
  assert.equal(after.v, prekeysVersion);
  assert.deepEqual(after.direct, []);
  assert.deepEqual(after.signed, before.signed);
  assert.deepEqual(after.onetime, before.onetime);
  assert.equal(after.nextOnetime, before.nextOnetime);

  const tampered = await legacyRecord(b);
  b.store.data.set("vault:prekeys", { ...tampered, uses: 7 });
  assert.equal(await PrekeyStore.open(b.store, b.keys, b.integrity), null);
});

test("direct prekeys are never published, are single use, and ids are never reused", async () => {
  const b = await owner();
  const published = await b.prekeys.publication();
  assert.ok(published);
  const publishedIds = published.onetime.map((p) => p.id);
  const device: DeviceEntry = {
    id: b.keys.deviceId,
    signing: b.keys.device.identity,
    exchange: b.keys.exchange.publicKey,
  };
  const bundle = await b.prekeys.reserve();
  assert.ok(bundle?.onetime);
  assert.equal(bundle.device, b.keys.deviceId);
  assert.ok(!publishedIds.includes(bundle.onetime.id));
  assert.ok(
    await verifyPrekey("onetime", b.keys.identity, device, bundle.onetime),
  );
  assert.ok(
    await verifyPrekey("signed", b.keys.identity, device, bundle.signed),
  );
  const again = await b.prekeys.publication();
  assert.deepEqual(
    again?.onetime.map((p) => p.id),
    publishedIds,
    "a reserved prekey never enters the published pool",
  );

  const signedKey = await verifyPrekey(
    "signed",
    b.keys.identity,
    device,
    bundle.signed,
  );
  const onetimeKey = await verifyPrekey(
    "onetime",
    b.keys.identity,
    device,
    bundle.onetime,
  );
  assert.ok(signedKey && onetimeKey);
  const start = async () => {
    const initiator = (await createVault(memoryStore())) as Unlocked;
    const started = await initiate(initiator.keys, {
      identity: b.keys.identity,
      device,
      signed: { id: bundle.signed.id, key: signedKey },
      onetime: { id: bundle.onetime!.id, key: onetimeKey },
    });
    assert.ok(started);
    return (keys: ResponderKeys) =>
      respond(b.keys, keys, {
        from: initiator.keys.identity,
        fromDevice: {
          id: initiator.keys.deviceId,
          signing: initiator.keys.device.identity,
          exchange: initiator.keys.exchange.publicKey,
        },
        ...started.initiation,
      });
  };
  const other = await PrekeyStore.open(b.store, b.keys, b.integrity);
  assert.ok(other);
  const [first, second] = [await start(), await start()];
  const outcomes = await Promise.all([
    b.prekeys.consume(bundle.signed.id, bundle.onetime.id, first),
    other.consume(bundle.signed.id, bundle.onetime.id, second),
  ]);
  assert.deepEqual(
    outcomes.map((o) => o.status).sort(),
    ["consumed", "rejected"],
    "concurrent consumption resolves to exactly one session",
  );
  const retry = await b.prekeys.consume(
    bundle.signed.id,
    bundle.onetime.id,
    await start(),
  );
  assert.equal(retry.status, "rejected", "a consumed prekey never returns");
  assert.deepEqual(record(b.store).direct, []);

  const next = await b.prekeys.reserve();
  assert.ok(next?.onetime && next.onetime.id > bundle.onetime.id);
  const ids = [next.onetime.id];
  for (let i = 0; i < maxDirect + 3; i++) {
    const reserved = await b.prekeys.reserve();
    assert.ok(reserved?.onetime);
    ids.push(reserved.onetime.id);
  }
  const kept = (record(b.store).direct as { id: number }[]).map((d) => d.id);
  assert.equal(kept.length, maxDirect, "the direct pool is bounded");
  assert.deepEqual(
    kept,
    ids.slice(-maxDirect),
    "the oldest reservations are evicted",
  );
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.every((id) => !publishedIds.includes(id)));
});

test("fuzzed prekey records and consumption inputs never corrupt or bypass the store", async () => {
  const b = await owner();
  await b.prekeys.reserve();
  const original = record(b.store);
  const before = await b.prekeys.publication();
  assert.ok(before);
  const names = Object.keys(original);
  const junk: unknown[] = [
    null,
    0,
    -1,
    1.5,
    2 ** 40,
    "",
    "x",
    [],
    {},
    true,
    NaN,
  ];
  let seed = 0x9e3779b9;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const rounds = Number(process.env.FUZZ_ITERATIONS ?? 300);
  for (let i = 0; i < rounds; i++) {
    const mutated: Record<string, unknown> = { ...original };
    const name = names[random(names.length)];
    switch (random(4)) {
      case 0:
        delete mutated[name];
        break;
      case 1:
        mutated[name] = junk[random(junk.length)];
        break;
      case 2:
        mutated[name] = original[names[random(names.length)]];
        break;
      default:
        mutated[`k${random(3)}`] = junk[random(junk.length)];
    }
    b.store.data.set("vault:prekeys", mutated);
    const opened = await PrekeyStore.open(b.store, b.keys, b.integrity);
    if (opened) {
      assert.deepEqual(
        (await opened.publication())?.onetime.map((p) => p.id),
        before.onetime.map((p) => p.id),
      );
    }
  }
  b.store.data.set("vault:prekeys", original);
  const store = await PrekeyStore.open(b.store, b.keys, b.integrity);
  assert.ok(store);
  for (let i = 0; i < rounds; i++) {
    const signed = junk[random(junk.length)] as number;
    const onetime = junk[random(junk.length)] as number | null;
    let used = false;
    const outcome = await store.consume(signed, onetime, async () => {
      used = true;
      return null;
    });
    assert.notEqual(outcome.status, "consumed");
    assert.equal(used, false, "invalid ids never reach key agreement");
  }
  assert.deepEqual(
    record(b.store),
    original,
    "rejected input never changes state",
  );
});
