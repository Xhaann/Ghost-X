import assert from "node:assert/strict";
import { test } from "node:test";
import { rosterFingerprint } from "./device.ts";
import { pairAddress } from "./pairs.ts";
import { createMessageId } from "./protocol.ts";
import {
  type SecureDevice,
  freePort,
  linkedDevice,
  secureDevice,
  startServer,
  stopServer,
  useServer,
} from "./testing.ts";

useServer();

type Json = Record<string, unknown>;

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function frames(list: string[], type: string): Json[] {
  return list
    .map((raw) => JSON.parse(raw) as Json)
    .filter((frame) => frame.type === type);
}

function deliveries(d: SecureDevice): Json[] {
  return frames(d.received, "message").map((f) => f.payload as Json);
}

function address(d: SecureDevice): string {
  return pairAddress(d.id, d.deviceId);
}

function bodies(d: SecureDevice): (string | null)[] {
  return d.inbox.map((m) => m.body);
}

async function identity(port: number): Promise<[SecureDevice, SecureDevice]> {
  const first = await secureDevice(port);
  const second = await linkedDevice(port, first);
  return [first, second];
}

async function connected(from: SecureDevice, to: string, count: number) {
  await from.pairing.establish(to);
  await until(
    () => from.pairing.established(to).length === count,
    `${count} sessions`,
  );
}

async function ratchet(d: SecureDevice, peer: SecureDevice): Promise<string> {
  return (
    (await d.pairs.transact(address(peer), async (s) => ({
      state: s,
      value: JSON.stringify([s.receiving?.n ?? null, s.skipped.length]),
    }))) ?? "none"
  );
}

test("one send reaches every authorized recipient device through independent sessions", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const [b1, b2] = await identity(port);
  assert.equal(b1.id, b2.id);
  assert.notEqual(b1.deviceId, b2.deviceId);
  assert.equal(b2.keys.root, null);
  await connected(a, b1.id, 2);

  const secret = "fan out to every device";
  const result = await a.messenger.send(b1.id, secret);
  assert.deepEqual(result, { ok: true, devices: 2 });
  const send = frames(a.sent, "send").at(-1)?.payload as Json;
  const envelopes = send.envelopes as Json[];
  assert.deepEqual(
    envelopes.map((e) => e.device).sort(),
    [b1.deviceId, b2.deviceId].sort(),
  );
  assert.notEqual(envelopes[0].ciphertext, envelopes[1].ciphertext);

  for (const d of [b1, b2]) {
    await until(() => bodies(d).includes(secret), "every device decrypts");
    assert.deepEqual(d.inbox, [{ id: send.id, from: a.id, body: secret }]);
    assert.deepEqual(
      deliveries(d).map((m) => [m.from, m.device]),
      [[a.id, a.deviceId]],
    );
    assert.equal(d.pairs.id(address(a)), a.pairs.id(address(d)));
  }
  assert.notEqual(a.pairs.id(address(b1)), a.pairs.id(address(b2)));

  await until(() => a.receipts.length === 2, "a receipt per device");
  assert.deepEqual(
    a.receipts.map((r) => [r.device, r.id, r.status]).sort(),
    [
      [b1.deviceId, send.id, "delivered"],
      [b2.deviceId, send.id, "delivered"],
    ].sort(),
  );

  const encoded = Buffer.from(secret).toString("base64url");
  for (const d of [a, b1, b2]) {
    for (const frame of d.frames) {
      assert.ok(!frame.includes(secret) && !frame.includes(encoded));
    }
    const rest = JSON.stringify([...d.store.data.entries()]);
    assert.ok(!rest.includes(secret) && !rest.includes(encoded));
  }
});

test("each sender device has its own session and is identified by device", async () => {
  const port = await freePort();
  await startServer(port);
  const [a1, a2] = await identity(port);
  const b = await secureDevice(port);
  assert.deepEqual(await a1.messenger.send(b.id, "from one"), {
    ok: true,
    devices: 1,
  });
  assert.deepEqual(await a2.messenger.send(b.id, "from two"), {
    ok: true,
    devices: 1,
  });
  await until(() => b.inbox.length === 2, "both arrive");
  assert.deepEqual(bodies(b).sort(), ["from one", "from two"]);
  assert.ok(b.inbox.every((m) => m.from === a1.id));
  assert.deepEqual(
    deliveries(b)
      .map((m) => m.device)
      .sort(),
    [a1.deviceId, a2.deviceId].sort(),
  );
  assert.notEqual(b.pairs.id(address(a1)), b.pairs.id(address(a2)));
  assert.equal(b.pairs.id(address(a1)), a1.pairs.id(address(b)));
  assert.equal(b.pairs.id(address(a2)), a2.pairs.id(address(b)));
  assert.equal(a1.pairs.state(address(b)), "established");
  assert.equal(a2.pairs.state(address(b)), "established");
});

test("ciphertext for one device never opens on another device or under another sender device", async () => {
  const port = await freePort();
  await startServer(port);
  const [a1, a2] = await identity(port);
  const [b1, b2] = await identity(port);
  await connected(a1, b1.id, 2);
  await connected(a2, b1.id, 2);
  await a1.messenger.send(b1.id, "for both");
  await a2.messenger.send(b1.id, "from a2");
  for (const d of [b1, b2]) {
    await until(() => d.inbox.length === 2, "genuine deliveries");
  }
  const forB1 = deliveries(b1).find((m) => m.device === a1.deviceId);
  assert.ok(forB1);
  const before = [await ratchet(b2, a1), await ratchet(b2, a2)];
  const forgeries: Json[] = [
    { ...forB1, id: createMessageId() },
    { ...forB1, id: createMessageId(), device: a2.deviceId },
  ];
  for (const payload of forgeries) {
    b2.deliver(JSON.stringify({ type: "message", payload }));
  }
  await until(() => b2.inbox.length === 4, "forgeries processed");
  assert.deepEqual(bodies(b2).slice(2), [null, null]);
  assert.deepEqual([await ratchet(b2, a1), await ratchet(b2, a2)], before);
  b1.deliver(
    JSON.stringify({
      type: "message",
      payload: { ...forB1, id: createMessageId(), device: a2.deviceId },
    }),
  );
  await until(() => b1.inbox.length === 3, "rebound sender processed");
  assert.equal(b1.inbox[2].body, null);
});

test("revocation disconnects only the revoked device, stops its delivery, and changes verification", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const [b1, b2] = await identity(port);
  await connected(a, b1.id, 2);
  assert.ok(b1.devices.roster);
  const before = await rosterFingerprint(b1.devices.roster);
  assert.ok(before);
  assert.equal(await a.trust.verify(b1.id, before.value), true);

  const revoked = await b1.devices.revoke(b1.client, b2.deviceId);
  assert.ok(revoked.ok);
  assert.deepEqual(
    revoked.roster.devices.map((d) => d.id),
    [b1.deviceId],
  );
  await until(() => b2.auth.state === "revoked", "revoked device notices");
  assert.equal(b2.devices.status, "revoked");
  assert.equal(b2.messenger.state.active, false);
  assert.equal(b1.auth.state, "authenticated");
  assert.equal(b1.messenger.state.active, true);

  const result = await a.messenger.send(b1.id, "after revocation");
  assert.deepEqual(result, { ok: true, devices: 1 });
  const envelopes = (frames(a.sent, "send").at(-1)?.payload as Json)
    .envelopes as Json[];
  assert.deepEqual(
    envelopes.map((e) => e.device),
    [b1.deviceId],
  );
  await until(() => bodies(b1).includes("after revocation"), "b1 receives");
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.ok(!bodies(b2).includes("after revocation"));
  assert.equal(a.trust.view(b1.id).state, "changed");
  const after = await rosterFingerprint(revoked.roster);
  assert.ok(after);
  assert.equal(await a.trust.verify(b1.id, after.value), true);

  const forged = await b2.client.request({ type: "fetch", payload: {} });
  assert.ok(forged?.type === "error");
  assert.equal(forged.payload.code, "authentication_required");
});

test("an offline device receives its queued copy on return with a receipt for each device", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const [b1, b2] = await identity(port);
  await connected(a, b1.id, 2);
  const storeB2 = b2.store;
  await b2.shutdown();

  const result = await a.messenger.send(b1.id, "while b2 is away");
  assert.deepEqual(result, { ok: true, devices: 2 });
  await until(() => bodies(b1).includes("while b2 is away"), "online copy");
  await until(() => a.receipts.length === 1, "online receipt");
  assert.equal(a.receipts[0].device, b1.deviceId);

  const back = await secureDevice(port, { store: storeB2 });
  assert.equal(back.deviceId, b2.deviceId);
  await until(() => bodies(back).includes("while b2 is away"), "queued copy");
  await until(() => a.receipts.length === 2, "offline receipt");
  assert.deepEqual(
    a.receipts.map((r) => r.device).sort(),
    [b1.deviceId, b2.deviceId].sort(),
  );
  assert.ok(a.receipts.every((r) => r.status === "delivered"));
});

test("a revoked device's queue is purged and it can never rejoin, even after a server restart", async () => {
  const port = await freePort();
  let server = await startServer(port);
  const a = await secureDevice(port);
  const [b1, b2] = await identity(port);
  await connected(a, b1.id, 2);
  const storeB2 = b2.store;
  await b2.shutdown();
  assert.deepEqual(await a.messenger.send(b1.id, "queued for b2"), {
    ok: true,
    devices: 2,
  });
  await until(() => bodies(b1).includes("queued for b2"), "b1 copy");
  const revoked = await b1.devices.revoke(b1.client, b2.deviceId);
  assert.ok(revoked.ok);

  await stopServer(server);
  server = await startServer(port);
  const back = await secureDevice(port, { store: storeB2, wait: false });
  await until(() => back.auth.state === "revoked", "still revoked");
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.deepEqual(back.inbox, []);
  assert.equal(frames(back.received, "message").length, 0);
  assert.equal(frames(back.received, "authenticated").length, 0);

  await until(() => b1.auth.state === "authenticated", "b1 reconnects");
  const reregister = await b1.client.request({
    type: "register",
    payload: revoked.roster,
  });
  assert.equal(reregister?.type, "registered");
  const relink = await b1.devices.authorize(
    b1.client,
    (await back.devices.linkRequest()) ?? "",
  );
  assert.equal(relink.ok, false);
  assert.deepEqual(
    b1.devices.roster?.devices.map((d) => d.id),
    [b1.deviceId],
  );
});

test("a device revoked between sealing and sending is dropped without re-encrypting", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const [b1, b2] = await identity(port);
  await connected(a, b1.id, 2);
  const original = a.client.request.bind(a.client);
  let raced = false;
  a.client.request = (async (...args: Parameters<typeof original>) => {
    if (args[0].type === "send" && !raced) {
      raced = true;
      const revoked = await b1.devices.revoke(b1.client, b2.deviceId);
      assert.ok(revoked.ok);
    }
    return original(...args);
  }) as typeof original;

  const result = await a.messenger.send(b1.id, "sealed before revocation");
  assert.deepEqual(result, { ok: true, devices: 1 });
  const attempts = frames(a.sent, "send").map((f) => f.payload as Json);
  assert.equal(attempts.length, 2);
  const [first, retry] = attempts.map((p) => p.envelopes as Json[]);
  assert.deepEqual(
    first.map((e) => e.device).sort(),
    [b1.deviceId, b2.deviceId].sort(),
  );
  assert.deepEqual(
    retry.map((e) => e.device),
    [b1.deviceId],
  );
  assert.equal(attempts[0].id, attempts[1].id);
  assert.equal(
    retry[0].ciphertext,
    first.find((e) => e.device === b1.deviceId)?.ciphertext,
  );
  const stale = frames(a.received, "error").map((f) => f.payload as Json);
  assert.deepEqual(stale, [{ code: "stale_devices" }]);
  await until(() => bodies(b1).includes("sealed before revocation"), "b1");
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.ok(!bodies(b2).includes("sealed before revocation"));
});
