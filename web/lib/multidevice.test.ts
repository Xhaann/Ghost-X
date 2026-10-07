import assert from "node:assert/strict";
import { test } from "node:test";
import { rosterFingerprint } from "./device.ts";
import { Outbox } from "./outbox.ts";
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
  assert.deepEqual(result, { ok: true, devices: 2, pending: 0 });
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
    pending: 0,
  });
  assert.deepEqual(await a2.messenger.send(b.id, "from two"), {
    ok: true,
    devices: 1,
    pending: 0,
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
  assert.deepEqual(result, { ok: true, devices: 1, pending: 0 });
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
  assert.deepEqual(result, { ok: true, devices: 2, pending: 0 });
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
    pending: 0,
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
  assert.deepEqual(result, { ok: true, devices: 1, pending: 0 });
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

test("a revoked device's retained session is deleted and its messages are refused even if a server delivers them", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const [b1, b2] = await identity(port);
  await connected(a, b1.id, 2);
  await b2.messenger.send(a.id, "before revocation");
  await until(() => bodies(a).includes("before revocation"), "genuine");
  const revoked = await b1.devices.revoke(b1.client, b2.deviceId);
  assert.ok(revoked.ok);
  assert.equal(await a.messenger.lookup(b1.id), true);
  await until(() => a.pairs.state(address(b2)) === "none", "session pruned");
  assert.equal(a.pairs.state(address(b1)), "established");

  const id = createMessageId();
  const sealed = await b2.pairing.seal(
    a.id,
    a.deviceId,
    id,
    "after revocation",
  );
  assert.ok(sealed, "the revoked device still holds its own ratchet");
  const initiations = frames(a.sent, "bundle").length;
  a.deliver(
    JSON.stringify({
      type: "message",
      payload: {
        id,
        from: b1.id,
        device: b2.deviceId,
        ciphertext: Buffer.from(sealed).toString("base64url"),
      },
    }),
  );
  await until(() => a.inbox.length === 2, "forged delivery processed");
  assert.equal(a.inbox[1].body, null);
  assert.ok(!bodies(a).includes("after revocation"));
  assert.equal(frames(a.sent, "bundle").length, initiations);

  await a.shutdown();
  const reloaded = await secureDevice(port, { store: a.store });
  assert.equal(reloaded.pairs.state(address(b2)), "none");
  assert.equal(reloaded.pairs.state(address(b1)), "established");
  await b1.messenger.send(a.id, "still talking");
  await until(() => bodies(reloaded).includes("still talking"), "b1 continues");
});

test("a message claiming a device outside the sender's verified roster is refused without starting a session", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = [await secureDevice(port), await secureDevice(port)];
  await b.messenger.send(a.id, "genuine");
  await until(() => bodies(a).includes("genuine"), "genuine");
  const stranger = await secureDevice(port);
  const forged = deliveries(a)[0];
  const bundles = frames(a.sent, "bundle").length;
  a.deliver(
    JSON.stringify({
      type: "message",
      payload: { ...forged, id: createMessageId(), device: stranger.deviceId },
    }),
  );
  await until(() => a.inbox.length === 2, "forged processed");
  assert.equal(a.inbox[1].body, null);
  assert.equal(frames(a.sent, "bundle").length, bundles);
  assert.equal(a.pairs.state(`${b.id}/${stranger.deviceId}`), "none");
});

function sends(d: SecureDevice): Json[] {
  return frames(d.sent, "send").map((f) => f.payload as Json);
}

function addressed(d: SecureDevice, id: string): string[] {
  return sends(d)
    .filter((p) => p.id === id)
    .flatMap((p) => (p.envelopes as Json[]).map((e) => e.device as string))
    .sort();
}

test("a device linked just before a send still receives that message", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const b1 = await secureDevice(port);
  await a.messenger.send(b1.id, "before linking");
  await until(() => bodies(b1).includes("before linking"), "b1");
  const b2 = await linkedDevice(port, b1);
  const result = await a.messenger.send(b1.id, "right after linking");
  assert.ok(result.ok);
  assert.equal(result.devices + result.pending, 2);
  await until(() => bodies(b2).includes("right after linking"), "b2 copy");
  const id = sends(a).at(-1)?.id as string;
  assert.deepEqual(addressed(a, id), [b1.deviceId, b2.deviceId].sort());
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.deepEqual(
    bodies(b1).filter((b) => b === "right after linking"),
    ["right after linking"],
  );
  assert.deepEqual(bodies(b2), ["right after linking"]);
  await until(() => a.outbox.size === 0, "outbox drained");
  await until(
    () => a.receipts.filter((r) => r.id === id).length === 2,
    "receipts",
  );
});

test("the first message reaches a recipient device that was offline at first contact", async () => {
  const port = await freePort();
  await startServer(port);
  const [b1, b2] = await identity(port);
  const storeB2 = b2.store;
  await b2.shutdown();
  const a = await secureDevice(port);
  const result = await a.messenger.send(b1.id, "first contact");
  assert.deepEqual(result, { ok: true, devices: 1, pending: 1 });
  assert.equal(a.outbox.size, 1);
  const raw = JSON.stringify([...a.store.data.entries()]);
  assert.ok(!raw.includes("first contact"));
  assert.ok(!raw.includes(Buffer.from("first contact").toString("base64url")));
  await until(() => bodies(b1).includes("first contact"), "b1");
  const back = await secureDevice(port, { store: storeB2 });
  await until(() => bodies(back).includes("first contact"), "b2 after return");
  await until(() => a.outbox.size === 0, "outbox drained");
  const id = sends(a)[0].id as string;
  await until(
    () => a.receipts.filter((r) => r.id === id).length === 2,
    "both receipts",
  );
  assert.deepEqual(
    a.receipts.map((r) => r.device).sort(),
    [b1.deviceId, b2.deviceId].sort(),
  );
});

test("a first message to an identity with no device online is held and delivered later", async () => {
  const port = await freePort();
  await startServer(port);
  const b = await secureDevice(port);
  const store = b.store;
  await b.shutdown();
  const a = await secureDevice(port);
  const result = await a.messenger.send(b.id, "nobody online");
  assert.deepEqual(result, { ok: true, devices: 0, pending: 1 });
  assert.equal(frames(a.sent, "send").length, 0);
  const back = await secureDevice(port, { store });
  await until(
    () => bodies(back).includes("nobody online"),
    "delivered after return",
  );
  await until(
    () => a.receipts.some((r) => r.status === "delivered"),
    "receipt",
  );
});

test("a reply from a secondary device reaches every device of the original sender", async () => {
  const port = await freePort();
  await startServer(port);
  const [a1, a2] = await identity(port);
  const [b1, b2] = await identity(port);
  await a1.messenger.send(b1.id, "hello from a1");
  for (const d of [b1, b2]) {
    await until(() => bodies(d).includes("hello from a1"), "b devices");
  }
  const reply = await b2.messenger.send(a1.id, "reply from b2");
  assert.ok(reply.ok);
  assert.equal(reply.devices + reply.pending, 2);
  for (const d of [a1, a2]) {
    await until(() => bodies(d).includes("reply from b2"), "every a device");
  }
  const first = await a2.messenger.send(b1.id, "first from a2");
  assert.ok(first.ok);
  assert.equal(first.devices + first.pending, 2);
  for (const d of [b1, b2]) {
    await until(() => bodies(d).includes("first from a2"), "every b device");
  }
  for (const d of [a1, a2, b1, b2]) {
    assert.equal(new Set(d.inbox.map((m) => m.id)).size, d.inbox.length);
  }
});

test("a pending device path survives a sender reload", async () => {
  const port = await freePort();
  await startServer(port);
  const [b1, b2] = await identity(port);
  const storeB2 = b2.store;
  await b2.shutdown();
  const a = await secureDevice(port);
  assert.deepEqual(await a.messenger.send(b1.id, "survives reload"), {
    ok: true,
    devices: 1,
    pending: 1,
  });
  const storeA = a.store;
  await a.shutdown();
  const persisted = await Outbox.open(storeA, a.storage);
  assert.deepEqual(
    persisted.paths().map((p) => p.device),
    [b2.deviceId],
  );
  const back = await secureDevice(port, { store: storeB2 });
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.ok(!bodies(back).includes("survives reload"));
  const reloaded = await secureDevice(port, { store: storeA });
  await until(
    () => bodies(back).includes("survives reload"),
    "flushed after reload",
  );
  await until(() => reloaded.outbox.size === 0, "drained");
});

test("a pending path to a device revoked before establishment is dropped, never sent", async () => {
  const port = await freePort();
  await startServer(port);
  const [b1, b2] = await identity(port);
  await b2.shutdown();
  const a = await secureDevice(port);
  assert.deepEqual(await a.messenger.send(b1.id, "not for b2"), {
    ok: true,
    devices: 1,
    pending: 1,
  });
  assert.ok((await b1.devices.revoke(b1.client, b2.deviceId)).ok);
  assert.equal(await a.messenger.lookup(b1.id), true);
  await until(() => a.outbox.size === 0, "dropped with the revocation");
  assert.deepEqual(
    sends(a).flatMap((p) => (p.envelopes as Json[]).map((e) => e.device)),
    [b1.deviceId],
  );
});

test("a device path that never establishes expires with an explicit receipt", async () => {
  const port = await freePort();
  await startServer(port);
  const [b1, b2] = await identity(port);
  await b2.shutdown();
  let now = Date.now();
  const a = await secureDevice(port, { now: () => now });
  const result = await a.messenger.send(b1.id, "never established");
  assert.deepEqual(result, { ok: true, devices: 1, pending: 1 });
  const id = sends(a)[0].id as string;
  now += 72 * 60 * 60 * 1000;
  a.messenger.stop();
  a.messenger.start();
  await until(
    () =>
      a.receipts.some(
        (r) => r.device === b2.deviceId && r.status === "expired",
      ),
    "expired receipt",
  );
  assert.deepEqual(
    a.receipts.find((r) => r.device === b2.deviceId),
    { to: b1.id, device: b2.deviceId, id, status: "expired" },
  );
  assert.equal(a.outbox.size, 0);
});

test("simultaneous first messages between two multi-device identities arrive exactly once everywhere", async () => {
  const port = await freePort();
  await startServer(port);
  const [a1, a2] = await identity(port);
  const [b1, b2] = await identity(port);
  const [fromA, fromB] = await Promise.all([
    a1.messenger.send(b1.id, "simultaneous a"),
    b2.messenger.send(a1.id, "simultaneous b"),
  ]);
  assert.ok(fromA.ok && fromB.ok);
  for (const d of [b1, b2]) {
    await until(
      () => bodies(d).includes("simultaneous a"),
      "a's message everywhere",
    );
  }
  for (const d of [a1, a2]) {
    await until(
      () => bodies(d).includes("simultaneous b"),
      "b's message everywhere",
    );
  }
  await new Promise((resolve) => setTimeout(resolve, 300));
  for (const d of [a1, a2, b1, b2]) {
    assert.equal(d.inbox.filter((m) => m.body !== null).length, 1);
    assert.ok(d.inbox.every((m) => m.body !== null));
  }
  for (const x of [a1, a2]) {
    for (const y of [b1, b2]) {
      const here = x.pairs.id(address(y));
      if (here !== null) {
        assert.equal(
          here,
          y.pairs.id(address(x)),
          "both ends share one session",
        );
      }
    }
  }
});

test("a revoked device is refused after a reload even before its session is pruned", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const [b1, b2] = await identity(port);
  await connected(a, b1.id, 2);
  await b2.messenger.send(a.id, "before");
  await until(() => bodies(a).includes("before"), "genuine");
  await a.shutdown();
  assert.ok((await b1.devices.revoke(b1.client, b2.deviceId)).ok);
  const reloaded = await secureDevice(port, { store: a.store });
  assert.equal(reloaded.pairs.state(address(b2)), "established");
  assert.equal(reloaded.rosters.cached(b1.id), null);
  const id = createMessageId();
  const sealed = await b2.pairing.seal(a.id, a.deviceId, id, "after reload");
  assert.ok(sealed);
  reloaded.deliver(
    JSON.stringify({
      type: "message",
      payload: {
        id,
        from: b1.id,
        device: b2.deviceId,
        ciphertext: Buffer.from(sealed).toString("base64url"),
      },
    }),
  );
  await until(() => reloaded.inbox.length === 1, "processed");
  assert.equal(reloaded.inbox[0].body, null);
  await until(() => reloaded.pairs.state(address(b2)) === "none", "pruned");
});

test("an initiation crossing a response in flight never splits a session", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const b = await secureDevice(port);
  a.delay(["bundle"]);
  const fromA = a.messenger.send(b.id, "from a");
  await until(() => frames(a.sent, "bundle").length === 1, "bundle requested");
  const fromB = await b.messenger.send(a.id, "from b");
  assert.ok(fromB.ok);
  await until(() => a.pairs.state(address(b)) === "established", "a responded");
  a.release();
  assert.ok((await fromA).ok);
  await until(() => bodies(b).includes("from a"), "b receives");
  await until(() => bodies(a).includes("from b"), "a receives");
  await new Promise((resolve) => setTimeout(resolve, 300));
  assert.equal(a.pairs.id(address(b)), b.pairs.id(address(a)));
  assert.equal(frames(a.sent, "initiate").length, 0);
  await a.messenger.send(b.id, "after");
  await b.messenger.send(a.id, "and back");
  await until(() => bodies(b).includes("after"), "continues");
  await until(() => bodies(a).includes("and back"), "both ways");
  assert.ok([...a.inbox, ...b.inbox].every((m) => m.body !== null));
});

test("a send the server rejects leaves no pending device paths behind", async () => {
  const port = await freePort();
  await startServer(port);
  const [b1, b2] = await identity(port);
  await b2.shutdown();
  const a = await secureDevice(port);
  await a.messenger.send(b1.id, "establish b1");
  await a.outbox.remove(a.outbox.paths());
  const original = a.client.request.bind(a.client);
  a.client.request = (async (...args: Parameters<typeof original>) =>
    args[0].type === "send"
      ? { type: "error", payload: { code: "queue_full" } }
      : original(...args)) as typeof original;
  assert.deepEqual(await a.messenger.send(b1.id, "rejected"), {
    ok: false,
    reason: "queue_full",
  });
  assert.equal(a.outbox.size, 0);
  assert.ok(!JSON.stringify([...a.store.data.keys()]).includes("outbox"));
});

test("an older pending message is delivered before a newer one to the same device", async () => {
  const port = await freePort();
  await startServer(port);
  const [b1, b2] = await identity(port);
  const storeB2 = b2.store;
  await b2.shutdown();
  const a = await secureDevice(port);
  assert.deepEqual(await a.messenger.send(b1.id, "older"), {
    ok: true,
    devices: 1,
    pending: 1,
  });
  const original = a.client.request.bind(a.client);
  let blocking = true;
  let refused = 0;
  a.client.request = (async (...args: Parameters<typeof original>) => {
    const [message] = args;
    if (
      blocking &&
      message.type === "send" &&
      message.payload.envelopes.length === 1 &&
      message.payload.envelopes[0].device === b2.deviceId
    ) {
      refused += 1;
      return { type: "error", payload: { code: "rate_limited" } };
    }
    return original(...args);
  }) as typeof original;
  const back = await secureDevice(port, { store: storeB2 });
  await until(() => refused > 0, "flush refused");
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(a.outbox.size, 1);
  assert.deepEqual(bodies(back), []);
  assert.equal(refused, 1, "a refused flush must not retry in a loop");
  blocking = false;
  assert.ok((await a.messenger.send(b1.id, "newer")).ok);
  await until(() => bodies(back).length === 2, "both arrive");
  assert.deepEqual(bodies(back), ["older", "newer"]);
  assert.equal(a.outbox.size, 0);
});
