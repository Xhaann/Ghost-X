import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  type Roster,
  createLinkRequest,
  deriveDeviceId,
  linkLifetime,
  linkSkew,
  rosterFingerprint,
  rosterMessage,
  signRoster,
  verifyLinkRequest,
  verifyRoster,
} from "./device.ts";
import { Devices } from "./devices.ts";
import type { Client } from "./client.ts";
import { memoryStore } from "./testing.ts";
import { type Unlocked, createVault, linkVault, loadVault } from "./vault.ts";

function now(): number {
  return Math.floor(Date.now() / 1000);
}

async function root() {
  const store = memoryStore();
  const vault = (await createVault(store)) as Unlocked;
  const devices = await Devices.open(store, vault.keys);
  assert.ok(devices && vault.keys.root);
  return { store, keys: vault.keys, devices };
}

async function linked(identity: string) {
  const store = memoryStore();
  const vault = (await linkVault(store, identity)) as Unlocked;
  const devices = await Devices.open(store, vault.keys);
  assert.ok(devices);
  return { store, keys: vault.keys, devices };
}

function server(): Client & { rosters: Map<string, Roster> } {
  const rosters = new Map<string, Roster>();
  const client = {
    rosters,
    request: async (message: { type: string; payload: unknown }) => {
      if (message.type === "register") {
        const roster = (await verifyRoster(message.payload)) as Roster;
        const current = rosters.get(roster.identity);
        if (current && roster.version <= current.version) {
          return roster.version === current.version &&
            roster.signature === current.signature
            ? {
                type: "registered",
                id: "r",
                payload: { version: roster.version },
              }
            : { type: "error", id: "r", payload: { code: "stale_roster" } };
        }
        rosters.set(roster.identity, roster);
        return {
          type: "registered",
          id: "r",
          payload: { version: roster.version },
        };
      }
      if (message.type === "devices") {
        const roster = rosters.get(
          (message.payload as { identity: string }).identity,
        );
        return roster
          ? { type: "devices", id: "d", payload: roster }
          : {
              type: "error",
              id: "d",
              payload: { code: "recipient_unavailable" },
            };
      }
      return null;
    },
  };
  return client as unknown as Client & { rosters: Map<string, Roster> };
}

function flip(text: string, size: number, index: number): string {
  const bytes = decodeBase64Url(text, size);
  assert.ok(bytes);
  bytes[index] ^= 1;
  return encodeBase64Url(bytes);
}

test("device ids are derived from the identity and the device key", async () => {
  const a = await root();
  const b = await root();
  assert.equal(
    await deriveDeviceId(a.keys.identity, a.keys.device.identity),
    a.keys.deviceId,
  );
  assert.notEqual(
    await deriveDeviceId(b.keys.identity, a.keys.device.identity),
    a.keys.deviceId,
  );
  assert.equal(await deriveDeviceId("bad", a.keys.device.identity), null);
});

test("rosters are bound to the root identity and every device field", async () => {
  const a = await root();
  const other = await root();
  const second = await linked(a.keys.identity);
  const roster = await signRoster(a.keys.root!, 2, [
    a.devices.own,
    second.devices.own,
  ]);
  assert.ok(roster);
  assert.ok(await verifyRoster(roster));
  const entry = roster.devices[0];
  const mutations: Record<string, Roster> = {
    identity: { ...roster, identity: other.keys.identity },
    version: { ...roster, version: 3 },
    "device id": {
      ...roster,
      devices: [{ ...entry, id: flip(entry.id, 16, 0) }, roster.devices[1]],
    },
    "device signing key": {
      ...roster,
      devices: [
        { ...entry, signing: other.keys.device.identity },
        roster.devices[1],
      ],
    },
    "device exchange key": {
      ...roster,
      devices: [
        { ...entry, exchange: other.keys.exchange.publicKey },
        roster.devices[1],
      ],
    },
    signature: { ...roster, signature: flip(roster.signature, 64, 5) },
    "dropped device": { ...roster, devices: [roster.devices[0]] },
    "duplicate device": { ...roster, devices: [entry, entry] },
    "reordered devices": {
      ...roster,
      devices: [roster.devices[1], roster.devices[0]],
    },
    "foreign device": { ...roster, devices: [entry, other.devices.own] },
    "identity key as device key": {
      ...roster,
      devices: [{ ...entry, signing: roster.identity }, roster.devices[1]],
    },
  };
  for (const [name, value] of Object.entries(mutations)) {
    assert.equal(await verifyRoster(value), null, name);
  }
  for (const value of [
    null,
    [],
    { ...roster, extra: 1 },
    { ...roster, devices: [] },
    { ...roster, version: 0 },
    { ...roster, version: 2 ** 31 },
    { ...roster, devices: [{ ...entry, extra: 1 }] },
  ]) {
    assert.equal(await verifyRoster(value), null, JSON.stringify(value));
  }
  const otherRoot = await signRoster(other.keys.root!, 1, [a.devices.own]);
  assert.equal(otherRoot, null);
});

test("roster fingerprints change whenever the device set changes", async () => {
  const a = await root();
  const second = await linked(a.keys.identity);
  const one = await signRoster(a.keys.root!, 1, [a.devices.own]);
  const two = await signRoster(a.keys.root!, 2, [
    a.devices.own,
    second.devices.own,
  ]);
  assert.ok(one && two);
  const [p1, p2, p3] = await Promise.all([
    rosterFingerprint(one),
    rosterFingerprint(two),
    rosterFingerprint({ ...one, version: 7 }),
  ]);
  assert.notEqual(p1?.value, p2?.value);
  assert.equal(p1?.value, p3?.value);
});

test("link requests prove possession, are fresh, and bind the identity", async () => {
  const a = await root();
  const other = await root();
  const second = await linked(a.keys.identity);
  const code = await second.devices.linkRequest();
  assert.ok(code);
  const parsed = await verifyLinkRequest(code, now());
  assert.ok(parsed);
  assert.equal(parsed.identity, a.keys.identity);
  assert.deepEqual(parsed.device, second.devices.own);
  assert.equal(await a.devices.linkRequest(), null);

  const raw = decodeBase64Url(code, 168);
  assert.ok(raw);
  for (const index of [0, 40, 70, 100, 120, 167]) {
    const tampered = raw.slice();
    tampered[index] ^= 1;
    assert.equal(
      await verifyLinkRequest(encodeBase64Url(tampered), now()),
      null,
      `byte ${index}`,
    );
  }
  const swapped = raw.slice();
  swapped.set(decodeBase64Url(other.keys.identity, 32)!, 0);
  assert.equal(await verifyLinkRequest(encodeBase64Url(swapped), now()), null);
  assert.equal(await verifyLinkRequest(code, now() + linkLifetime + 1), null);
  const early = await createLinkRequest(
    a.keys.identity,
    second.keys.device,
    second.keys.exchange.publicRaw,
    now() + linkSkew + 5,
  );
  assert.equal(await verifyLinkRequest(early, now()), null);
  const rootDevice = await createLinkRequest(
    a.keys.identity,
    a.keys.root!,
    second.keys.exchange.publicRaw,
    now(),
  );
  assert.equal(await verifyLinkRequest(rootDevice, now()), null);
  for (const bad of ["", "x", code + "A", code.slice(1), 42, null]) {
    assert.equal(await verifyLinkRequest(bad, now()), null);
  }
});

test("only the root device authorizes, once, and only for its own identity", async () => {
  const a = await root();
  const other = await root();
  const client = server();
  assert.equal(await a.devices.sync(client), "authorized");
  const second = await linked(a.keys.identity);
  assert.equal(await second.devices.sync(client), "pending");
  const code = await second.devices.linkRequest();
  assert.ok(code);

  assert.deepEqual(await second.devices.authorize(client, code), {
    ok: false,
    reason: "not_root",
  });
  assert.deepEqual(await other.devices.authorize(client, code), {
    ok: false,
    reason: "other_identity",
  });
  const result = await a.devices.authorize(client, code);
  assert.ok(result.ok);
  assert.equal(result.roster.version, 2);
  assert.deepEqual(await a.devices.authorize(client, code), {
    ok: false,
    reason: "already_authorized",
  });
  assert.equal(await second.devices.sync(client), "authorized");
  assert.equal(second.devices.roster?.version, 2);

  const extra = [];
  for (let i = 0; i < 2; i++) {
    const device = await linked(a.keys.identity);
    const request = await device.devices.linkRequest();
    assert.ok(request);
    assert.ok((await a.devices.authorize(client, request)).ok);
    extra.push(device);
  }
  const fifth = await linked(a.keys.identity);
  assert.deepEqual(
    await a.devices.authorize(client, (await fifth.devices.linkRequest())!),
    {
      ok: false,
      reason: "device_limit",
    },
  );
  assert.deepEqual(await a.devices.revoke(client, a.keys.deviceId), {
    ok: false,
    reason: "invalid_request",
  });
});

test("revocation is adopted monotonically and cannot be rolled back", async () => {
  const a = await root();
  const client = server();
  await a.devices.sync(client);
  const second = await linked(a.keys.identity);
  const authorized = await a.devices.authorize(
    client,
    (await second.devices.linkRequest())!,
  );
  assert.ok(authorized.ok);
  await second.devices.sync(client);
  const revoked = await a.devices.revoke(client, second.keys.deviceId);
  assert.ok(revoked.ok);
  assert.equal(await second.devices.sync(client), "revoked");
  assert.equal(await second.devices.adopt(authorized.roster), false);
  assert.equal(second.devices.status, "revoked");
  const reopened = await Devices.open(second.store, second.keys);
  assert.equal(reopened?.status, "revoked");
  assert.equal(await a.devices.adopt(authorized.roster), false);
  assert.equal(a.devices.roster?.version, revoked.roster.version);
});

test("a stranger's roster or a rootless forgery is never adopted", async () => {
  const a = await root();
  const other = await root();
  const second = await linked(a.keys.identity);
  assert.equal(await second.devices.adopt(other.devices.roster), false);
  const forged = await signRoster(other.keys.root!, 1, [second.devices.own]);
  assert.equal(forged, null);
  assert.equal(second.devices.status, "pending");
  assert.equal(
    await a.devices.adopt({ ...a.devices.roster!, version: 9 }),
    false,
  );
});

test("a stored roster that does not verify fails closed", async () => {
  const a = await root();
  const roster = a.store.data.get("vault:roster") as Roster;
  a.store.data.set("vault:roster", { ...roster, version: roster.version + 1 });
  assert.equal(await Devices.open(a.store, a.keys), null);
  const other = await root();
  a.store.data.set("vault:roster", other.devices.roster);
  assert.equal(await Devices.open(a.store, a.keys), null);
  assert.equal((await loadVault(a.store)).status, "ready");
});

async function rootSigned(
  root: { sign(data: Uint8Array): Promise<string | null> },
  identity: string,
  version: number,
  devices: Roster["devices"],
): Promise<Roster> {
  const message = rosterMessage(identity, version, devices);
  assert.ok(message);
  const signature = await root.sign(message);
  assert.ok(signature);
  return { identity, version, devices, signature };
}

test("correctly signed rosters are still rejected when malformed", async () => {
  const a = await root();
  const second = await linked(a.keys.identity);
  const ordered = [a.devices.own, second.devices.own].sort((x, y) =>
    x.id < y.id ? -1 : 1,
  );
  const sorted = await rootSigned(a.keys.root!, a.keys.identity, 2, ordered);
  assert.ok(await verifyRoster(sorted));
  const reversed = await rootSigned(
    a.keys.root!,
    a.keys.identity,
    2,
    [...ordered].reverse(),
  );
  assert.equal(await verifyRoster(reversed), null, "non-canonical order");
  const identityId = await deriveDeviceId(a.keys.identity, a.keys.identity);
  assert.ok(identityId);
  const rootAsDevice = await rootSigned(a.keys.root!, a.keys.identity, 2, [
    {
      id: identityId,
      signing: a.keys.identity,
      exchange: second.keys.exchange.publicKey,
    },
  ]);
  assert.equal(
    await verifyRoster(rootAsDevice),
    null,
    "identity key as device",
  );
});

test("an authorized device never adopts an equivocating, foreign, or self-excluding roster", async () => {
  const a = await root();
  const other = await root();
  const client = server();
  await a.devices.sync(client);
  const second = await linked(a.keys.identity);
  const third = await linked(a.keys.identity);
  const granted = await a.devices.authorize(
    client,
    (await second.devices.linkRequest())!,
  );
  assert.ok(granted.ok);
  assert.equal(await second.devices.sync(client), "authorized");
  const version = granted.roster.version;

  const equivocation = await signRoster(a.keys.root!, version, [
    a.devices.own,
    second.devices.own,
    third.devices.own,
  ]);
  assert.ok(equivocation);
  assert.notEqual(equivocation.signature, granted.roster.signature);
  assert.equal(await second.devices.adopt(equivocation), false);
  assert.equal(await a.devices.adopt(equivocation), false);
  assert.equal(second.devices.roster?.signature, granted.roster.signature);

  const foreign = await signRoster(other.keys.root!, version + 3, [
    other.devices.own,
  ]);
  assert.ok(foreign);
  assert.equal(await second.devices.adopt(foreign), false);
  assert.equal(second.devices.status, "authorized");
  assert.equal(second.devices.roster?.identity, a.keys.identity);

  const withoutRoot = await signRoster(a.keys.root!, version + 1, [
    second.devices.own,
  ]);
  assert.ok(withoutRoot);
  assert.equal(await a.devices.adopt(withoutRoot), false);
  assert.equal(a.devices.status, "authorized");
  assert.equal(a.devices.roster?.version, version);
});
