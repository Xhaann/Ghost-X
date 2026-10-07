import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  type DeviceEntry,
  type Roster,
  deriveDeviceId,
  rosterFingerprint,
  signRoster,
} from "./device.ts";
import { ExchangeKey } from "./encryption.ts";
import type { Fingerprint } from "./fingerprint.ts";
import { IdentityKey } from "./identity.ts";
import { memoryStore } from "./testing.ts";
import { Trust, parseTrustRecord, trustVersion } from "./trust.ts";
import { type Unlocked, createVault } from "./vault.ts";

type Store = ReturnType<typeof memoryStore>;

async function local(): Promise<{ store: Store; integrity: CryptoKey }> {
  const store = memoryStore();
  const state = await createVault(store);
  assert.equal(state.status, "ready");
  return { store, integrity: (state as Unlocked).integrity };
}

async function newDevice(identity: string): Promise<DeviceEntry> {
  const [signing, exchange] = await Promise.all([
    IdentityKey.generate(),
    ExchangeKey.generate(),
  ]);
  const id = await deriveDeviceId(identity, signing.identity);
  assert.ok(id);
  return { id, signing: signing.identity, exchange: exchange.publicKey };
}

type Peer = {
  root: IdentityKey;
  identity: string;
  devices: DeviceEntry[];
  version: number;
  next: (
    devices?: DeviceEntry[],
  ) => Promise<{ roster: Roster; print: Fingerprint }>;
};

async function peer(): Promise<Peer & { roster: Roster; print: Fingerprint }> {
  const root = await IdentityKey.generate();
  const p: Peer = {
    root,
    identity: root.identity,
    devices: [await newDevice(root.identity)],
    version: 0,
    next: async (devices) => {
      if (devices) {
        p.devices = devices;
      }
      p.version += 1;
      const roster = await signRoster(root, p.version, p.devices);
      assert.ok(roster);
      const print = await rosterFingerprint(roster);
      assert.ok(print);
      return { roster, print };
    },
  };
  return { ...p, ...(await p.next()), next: p.next };
}

function flip(text: string, index = 0): string {
  const raw = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(raw);
  raw[index] ^= 1;
  return encodeBase64Url(raw);
}

function stored(store: Store, identity: string) {
  return store.data.get(`trust:${identity}`) as
    Record<string, unknown> | undefined;
}

test("a new identity is never trusted automatically and its roster version is pinned", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  assert.equal(trust.view(b.identity).state, "unavailable");
  assert.deepEqual(await trust.observe(b.roster), b.roster);
  assert.deepEqual(trust.view(b.identity), {
    identity: b.identity,
    state: "unverified",
    current: b.print,
    verified: null,
  });
  await trust.flush();
  const record = stored(store, b.identity);
  assert.equal(record?.status, "observed");
  assert.equal(record?.version, 1);
  assert.equal(record?.fingerprint, null);
  assert.equal(trust.pinned(b.identity), 1);
});

test("explicit verification binds to the exact roster fingerprint and persists", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  const c = await peer();
  await trust.observe(b.roster);
  for (const wrong of [
    c.print.value,
    b.print.digits,
    flip(b.print.value),
    flip(b.print.value, 63),
    "",
    b.identity,
  ]) {
    assert.equal(await trust.verify(b.identity, wrong), false);
  }
  assert.equal(await trust.verify(c.identity, c.print.value), false);
  assert.equal(trust.view(b.identity).state, "unverified");
  assert.equal(await trust.verify(b.identity, b.print.value), true);
  assert.equal(trust.view(b.identity).state, "verified");
  assert.deepEqual(trust.view(b.identity).verified, b.print);
  const record = stored(store, b.identity);
  assert.deepEqual(Object.keys(record ?? {}).sort(), [
    "fingerprint",
    "identity",
    "mac",
    "status",
    "v",
    "version",
  ]);
  const reloaded = await Trust.open(store, integrity);
  assert.equal(reloaded.rejected, 0);
  assert.equal(reloaded.view(b.identity).state, "unavailable");
  await reloaded.observe(b.roster);
  assert.equal(reloaded.view(b.identity).state, "verified");
});

test("adding or removing a device invalidates verification until re-verified", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  await trust.observe(b.roster);
  assert.equal(await trust.verify(b.identity, b.print.value), true);

  const added = await b.next([...b.devices, await newDevice(b.identity)]);
  await trust.observe(added.roster);
  assert.equal(trust.view(b.identity).state, "changed");
  assert.deepEqual(trust.view(b.identity).current, added.print);
  assert.deepEqual(trust.view(b.identity).verified, b.print);
  await trust.flush();
  assert.equal(stored(store, b.identity)?.status, "changed");
  const reloaded = await Trust.open(store, integrity);
  assert.equal(reloaded.view(b.identity).state, "changed");
  await reloaded.observe(added.roster);
  assert.equal(await reloaded.verify(b.identity, b.print.value), false);
  assert.equal(await reloaded.verify(b.identity, added.print.value), true);
  assert.equal(reloaded.view(b.identity).state, "verified");

  const removed = await b.next(b.devices.slice(0, 1));
  await reloaded.observe(removed.roster);
  assert.equal(reloaded.view(b.identity).state, "changed");
});

test("an older roster is never accepted after a newer one, even across reloads", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  const first = { roster: b.roster, print: b.print };
  const second = await b.next([...b.devices, await newDevice(b.identity)]);
  assert.ok(await trust.observe(second.roster));
  assert.equal(await trust.observe(first.roster), null);
  assert.deepEqual(trust.view(b.identity).current, second.print);
  await trust.flush();
  const reloaded = await Trust.open(store, integrity);
  assert.equal(reloaded.pinned(b.identity), 2);
  assert.equal(await reloaded.observe(first.roster), null);
  assert.equal(reloaded.view(b.identity).state, "unavailable");
  assert.ok(await reloaded.observe(second.roster));
});

test("forged, foreign, or equivocating rosters are ignored", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  const c = await peer();
  for (const bad of [
    { ...b.roster, signature: flip(b.roster.signature, 3) },
    { ...b.roster, identity: c.identity },
    { ...b.roster, version: 5 },
    { ...b.roster, devices: c.roster.devices },
    null,
    "roster",
  ]) {
    assert.equal(await trust.observe(bad), null);
  }
  assert.equal(trust.view(b.identity).state, "unavailable");
  assert.ok(await trust.observe(b.roster));
  const equivocation = {
    roster: (await signRoster(b.root, b.roster.version, [
      await newDevice(b.identity),
    ])) as Roster,
  };
  assert.equal(equivocation.roster.version, b.roster.version);
  assert.equal(await trust.observe(equivocation.roster), null);
  assert.deepEqual(trust.view(b.identity).current, b.print);
});

test("corrupted trust records never increase trust", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  await trust.observe(b.roster);
  await trust.verify(b.identity, b.print.value);
  const original = stored(store, b.identity) as Record<string, unknown>;
  const other = await peer();
  for (const [name, record] of Object.entries({
    mac: { ...original, mac: flip(original.mac as string) },
    fingerprint: { ...original, fingerprint: other.print.value },
    version: { ...original, version: 99 },
    status: { ...original, status: "observed" },
    identity: { ...original, identity: other.identity },
    extra: { ...original, extra: 1 },
    "future version": { ...original, v: trustVersion + 1 },
  })) {
    store.data.set(`trust:${b.identity}`, record);
    const reopened = await Trust.open(store, integrity);
    await reopened.observe(b.roster);
    assert.notEqual(reopened.view(b.identity).state, "verified", name);
    assert.equal(reopened.rejected, 1, name);
  }
  assert.equal(parseTrustRecord(b.identity, original)?.status, "verified");
  assert.equal(parseTrustRecord(other.identity, original), null);
});

test("a previous single-key verification is migrated as changed, never as verified", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const legacyFingerprint = encodeBase64Url(
    crypto.getRandomValues(new Uint8Array(64)),
  );
  const legacyKey = (await ExchangeKey.generate()).publicKey;
  const values = [1, b.identity, "verified", legacyKey, legacyFingerprint];
  const body = new TextEncoder().encode(JSON.stringify(values));
  const context = new TextEncoder().encode("ghostx/trust/v1\0");
  const input = new Uint8Array(context.length + body.length);
  input.set(context);
  input.set(body, context.length);
  const mac = encodeBase64Url(
    new Uint8Array(await crypto.subtle.sign("HMAC", integrity, input)),
  );
  store.data.set(`trust:${b.identity}`, {
    v: 1,
    identity: b.identity,
    status: "verified",
    key: legacyKey,
    fingerprint: legacyFingerprint,
    mac,
  });
  const trust = await Trust.open(store, integrity);
  assert.equal(trust.rejected, 0);
  await trust.observe(b.roster);
  assert.equal(trust.view(b.identity).state, "changed");
  assert.equal(trust.view(b.identity).verified?.value, legacyFingerprint);
  assert.equal(stored(store, b.identity)?.v, trustVersion);
  store.data.set(`trust:${b.identity}`, {
    v: 1,
    identity: b.identity,
    status: "verified",
    key: legacyKey,
    fingerprint: legacyFingerprint,
    mac: flip(mac),
  });
  const forged = await Trust.open(store, integrity);
  assert.equal(forged.rejected, 1);
});

test("a stale tab cannot overwrite a newer verification decision", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const tab1 = await Trust.open(store, integrity);
  const tab2 = await Trust.open(store, integrity);
  await tab1.observe(b.roster);
  await tab2.observe(b.roster);
  assert.equal(await tab1.verify(b.identity, b.print.value), true);
  assert.equal(await tab2.verify(b.identity, b.print.value), false);
  await tab2.refresh(b.identity);
  assert.equal(tab2.view(b.identity).state, "verified");
});

test("fuzzed trust records never restore as verified", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  await trust.observe(b.roster);
  await trust.verify(b.identity, b.print.value);
  const original = stored(store, b.identity) as Record<string, unknown>;
  const names = Object.keys(original);
  const values: unknown[] = [
    null,
    0,
    1,
    2,
    "",
    "verified",
    "changed",
    "observed",
    [],
    {},
    b.print.digits,
  ];
  let seed = 0x2545f491;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 1500);
  for (let i = 0; i < iterations; i++) {
    const mutated: Record<string, unknown> = { ...original };
    for (let s = 0; s <= random(3); s++) {
      const name = names[random(names.length)];
      const choice = random(3);
      if (choice === 0) {
        delete mutated[name];
      } else if (choice === 1) {
        mutated[name] = values[random(values.length)];
      } else {
        mutated[name] = original[names[random(names.length)]];
      }
    }
    store.data.set(`trust:${b.identity}`, mutated);
    const reopened = await Trust.open(store, integrity);
    await reopened.observe(b.roster);
    if (reopened.view(b.identity).state === "verified") {
      assert.deepEqual(mutated, original);
    }
  }
});
