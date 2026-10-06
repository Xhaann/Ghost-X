import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import type { Client } from "./client.ts";
import { ExchangeKey, type KeyBundle } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import { type MessengerOptions, maxPendingDecryptions } from "./messenger.ts";
import { maxBodySize, sessionIdSize } from "./protocol.ts";
import {
  type MemoryStore,
  type SecureDevice,
  freePort,
  memoryStore,
  secureDevice,
  startServer,
  stopServer,
  useServer,
} from "./testing.ts";
import { loadVault } from "./vault.ts";

useServer();

type Peer = SecureDevice;

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

async function stranger(): Promise<string> {
  return (await IdentityKey.generate()).identity;
}

async function identityStore(): Promise<MemoryStore> {
  const store = memoryStore();
  assert.equal((await loadVault(store)).status, "ready");
  return store;
}

function deviceOf(source: MemoryStore): MemoryStore {
  const store = memoryStore();
  store.data.set("vault:keys", source.data.get("vault:keys"));
  return store;
}

async function conflictingDevice(source: MemoryStore): Promise<MemoryStore> {
  const store = memoryStore();
  const fresh = await ExchangeKey.create();
  store.data.set("vault:keys", {
    ...(source.data.get("vault:keys") as Json),
    exchangeKey: fresh.key.publicKey,
    exchange: fresh.privateKey,
  });
  return store;
}

async function peer(
  port: number,
  identity?: MemoryStore,
  options: MessengerOptions & { wait?: boolean } = {},
): Promise<Peer> {
  const { wait, ...messenger } = options;
  return secureDevice(port, {
    store: identity ? deviceOf(identity) : memoryStore(),
    messenger,
    wait,
  });
}

async function barrier(p: Peer): Promise<void> {
  const reply = await p.client.request({
    type: "ping",
    payload: { sentAt: 1 },
  });
  assert.equal(reply?.type, "pong");
}

function frames(list: string[], type: string): Json[] {
  return list
    .map((raw) => JSON.parse(raw) as Json)
    .filter((frame) => frame.type === type);
}

function lastDelivery(p: Peer): Json {
  const all = frames(p.received, "message");
  assert.ok(all.length > 0);
  return structuredClone(all.at(-1)?.payload as Json);
}

function inject(p: Peer, payload: Json) {
  p.deliver(JSON.stringify({ type: "message", payload }));
}

async function keyReply(p: Peer, identity: string) {
  const reply = await p.client.request({ type: "key", payload: { identity } });
  assert.ok(reply && reply.type === "key");
  return reply.payload;
}

function flipText(text: string, index = 0): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 1;
  return encodeBase64Url(bytes);
}

function sessionOf(p: Peer) {
  return p.messenger.session;
}

function bodies(p: Peer): (string | null)[] {
  return p.inbox.map((m) => m.body);
}

test("activates only after publishing the static key and establishing a session", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);

  const types = a.sent.map((raw) => JSON.parse(raw).type);
  const order = ["authenticate", "publish", "session", "prekeys"].map((t) =>
    types.indexOf(t),
  );
  assert.ok(
    order.every((index, i) => index >= 0 && (i === 0 || index > order[i - 1])),
    types.join(),
  );
  const offer = frames(a.sent, "session")[0].payload as Json;
  assert.deepEqual(Object.keys(offer).sort(), [
    "epoch",
    "key",
    "session",
    "signature",
  ]);
  assert.equal(offer.epoch, 0);
  assert.equal(decodeBase64Url(offer.session, sessionIdSize)?.length, 16);
  assert.notEqual(offer.key, a.keys.exchange.publicKey);
  assert.deepEqual(a.messenger.session, {
    session: offer.session,
    epochs: [0],
  });
  assert.deepEqual(
    a.states.map((s) => s.active),
    [true],
  );
});

test("refuses to send before a session is established", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port, undefined, { wait: false });
  a.messenger.stop();
  assert.deepEqual(await a.messenger.send(await stranger(), "x"), {
    ok: false,
    reason: "authentication_required",
  });
  assert.equal(sessionOf(a), null);
  assert.equal(frames(a.sent, "send").length, 0);
});

test("delivers end-to-end encrypted messages with only ephemeral session keys on the wire", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const secret = "the server must never read this 🔒";

  assert.deepEqual(
    await a.messenger.send(b.keys.identity.identity, secret, "m1"),
    { ok: true },
  );
  await until(() => b.inbox.length === 1, "delivery");
  assert.deepEqual(b.inbox, [
    { id: "m1", from: a.keys.identity.identity, body: secret },
  ]);

  const send = frames(a.sent, "send")[0].payload as Json;
  assert.deepEqual(Object.keys(send).sort(), ["envelopes", "epoch", "to"]);
  const envelopes = send.envelopes as Json[];
  assert.equal(envelopes.length, 1);
  assert.deepEqual(Object.keys(envelopes[0]).sort(), [
    "ciphertext",
    "epoch",
    "iv",
    "salt",
    "session",
  ]);
  assert.equal(envelopes[0].session, b.messenger.session?.session);
  const delivered = lastDelivery(b);
  assert.deepEqual(delivered.envelope, envelopes[0]);
  assert.equal(
    (delivered.sender as Json).session,
    a.messenger.session?.session,
  );
  assert.equal(delivered.key, a.keys.exchange.publicKey);

  const encoded = encodeBase64Url(new TextEncoder().encode(secret));
  for (const frame of [...a.sent, ...a.received, ...b.sent, ...b.received]) {
    assert.ok(!frame.includes(secret), "plaintext crossed the wire");
    assert.ok(!frame.includes(encoded), "encoded plaintext crossed the wire");
  }

  assert.deepEqual(
    await b.messenger.send(a.keys.identity.identity, "reply", "r1"),
    { ok: true },
  );
  await until(() => a.inbox.length === 1, "reply");
  assert.equal(a.inbox[0].body, "reply");
});

test("only the device holding the ratchet session can read messages to its identity", async () => {
  const port = await freePort();
  await startServer(port);
  const bIdentity = await identityStore();
  const a = await peer(port);
  const b1 = await peer(port, bIdentity);
  const b2 = await peer(port, bIdentity);
  assert.equal(b1.id, b2.id);
  assert.notEqual(b1.messenger.session?.session, b2.messenger.session?.session);

  assert.deepEqual(await a.messenger.send(b1.id, "both", "m1"), { ok: true });
  await until(() => b1.inbox.length === 1 && b2.inbox.length === 1, "fanout");
  assert.deepEqual(
    [b1.inbox[0].body, b2.inbox[0].body].sort(),
    ["both", null].sort(),
  );
  const envelopes = (frames(a.sent, "send")[0].payload as Json)
    .envelopes as Json[];
  assert.equal(envelopes.length, 2);
  assert.notEqual(envelopes[0].ciphertext, envelopes[1].ciphertext);

  const reader = b1.inbox[0].body === "both" ? b1 : b2;
  const other = reader === b1 ? b2 : b1;
  const delivered = lastDelivery(reader);
  inject(other, {
    ...delivered,
    id: "x2",
    envelope: {
      ...(delivered.envelope as Json),
      session: other.messenger.session?.session,
    },
  });
  await until(() => other.inbox.length === 2, "cross-device processed");
  assert.equal(other.inbox[1].body, null);
});

test("a second session cannot bind a different static key", async () => {
  const port = await freePort();
  await startServer(port);
  const first = await identityStore();
  await peer(port, first);
  const conflicting = await secureDevice(port, {
    store: await conflictingDevice(first),
    wait: false,
  });
  await barrier(conflicting);
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(conflicting.messenger.state.active, false);
  assert.equal(sessionOf(conflicting), null);
  assert.equal(frames(conflicting.sent, "session").length, 0);
});

test("reports unavailable recipients and invalid input without sending", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const absent = await stranger();
  const frameCount = frames(a.sent, "send").length;

  assert.deepEqual(await a.messenger.send(absent, "x"), {
    ok: false,
    reason: "recipient_unavailable",
  });
  for (const [to, body, reason] of [
    ["bad", "x", "invalid_payload"],
    [a.id, "to myself", "invalid_payload"],
    [absent, "", "invalid_payload"],
    [absent, "a\u0000", "invalid_payload"],
    [absent, "a".repeat(maxBodySize + 1), "message_too_large"],
  ] as const) {
    assert.deepEqual(await a.messenger.send(to, body), { ok: false, reason });
  }
  assert.equal(frames(a.sent, "send").length, frameCount);
});

test("tampered, misdirected, or rebound deliveries never decrypt", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const c = await peer(port);

  b.hold(true);
  await a.messenger.send(b.keys.identity.identity, "original", "m1");
  await until(() => frames(b.received, "message").length === 1, "held");
  b.hold(false);
  const good = lastDelivery(b);
  await a.messenger.send(c.keys.identity.identity, "for c", "m2");
  await until(() => c.inbox.length === 1, "c delivery");
  const forC = lastDelivery(c);
  await c.messenger.send(b.keys.identity.identity, "from c", "m3");
  await until(() => b.inbox.length === 1, "c to b");
  const fromC = lastDelivery(b);

  const envelope = good.envelope as Json;
  const sender = good.sender as Json;
  const otherSession = (fromC.sender as Json).session;
  const mutations: Record<string, Json> = {
    ciphertext: {
      ...good,
      envelope: {
        ...envelope,
        ciphertext: flipText(envelope.ciphertext as string),
      },
    },
    "ciphertext tail": {
      ...good,
      envelope: {
        ...envelope,
        ciphertext: flipText(envelope.ciphertext as string, 20),
      },
    },
    nonce: {
      ...good,
      envelope: { ...envelope, iv: flipText(envelope.iv as string) },
    },
    salt: {
      ...good,
      envelope: { ...envelope, salt: flipText(envelope.salt as string) },
    },
    "message id": { ...good, id: "other" },
    "sender identity": {
      ...good,
      from: c.keys.identity.identity,
      key: fromC.key,
      signature: fromC.signature,
      sender: fromC.sender,
    },
    "sender static key": { ...good, key: fromC.key },
    "static binding": { ...good, signature: fromC.signature },
    "sender session": { ...good, sender: { ...sender, session: otherSession } },
    "sender epoch": { ...good, sender: { ...sender, epoch: 1 } },
    "sender ephemeral key": {
      ...good,
      sender: { ...sender, key: (fromC.sender as Json).key },
    },
    "session binding": {
      ...good,
      sender: { ...sender, signature: (fromC.sender as Json).signature },
    },
    "whole session of another identity": { ...good, sender: fromC.sender },
    "recipient epoch": { ...good, envelope: { ...envelope, epoch: 1 } },
    "another identity's envelope": {
      ...forC,
      id: "c9",
      envelope: { ...(forC.envelope as Json), session: envelope.session },
    },
  };
  for (const [name, payload] of Object.entries(mutations)) {
    const before = b.inbox.length;
    inject(b, payload);
    await until(() => b.inbox.length === before + 1, name);
    assert.equal(b.inbox.at(-1)?.body, null, name);
  }
  const before = b.inbox.length;
  inject(b, good);
  await until(() => b.inbox.length === before + 1, "control");
  assert.equal(b.inbox.at(-1)?.body, "original");
  inject(b, {
    ...good,
    id: "z1",
    envelope: { ...envelope, session: encodeBase64Url(new Uint8Array(16)) },
  });
  await barrier(b);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(b.inbox.length, before + 1);
});

test("replayed deliveries are dropped and old-session ciphertext is not accepted", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  await a.messenger.send(b.keys.identity.identity, "once", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  const frame = lastDelivery(b);

  inject(b, frame);
  inject(b, frame);
  await barrier(b);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(bodies(b), ["once"]);

  b.messenger.stop();
  b.messenger.start();
  await until(() => b.messenger.state.active, "re-established");
  assert.notEqual(
    b.messenger.session?.session,
    (frame.envelope as Json).session,
  );
  inject(b, frame);
  inject(b, {
    ...frame,
    id: "m1b",
    envelope: {
      ...(frame.envelope as Json),
      session: b.messenger.session?.session,
    },
  });
  await barrier(b);
  await until(() => b.inbox.length === 2, "rebound processed");
  assert.deepEqual(bodies(b), ["once", null]);
});

test("concurrent copies of an unseen delivery decrypt only once", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  b.hold(true);
  await a.messenger.send(b.keys.identity.identity, "exactly once", "m1");
  await until(() => frames(b.received, "message").length === 1, "held");
  b.hold(false);
  const frame = lastDelivery(b);
  inject(b, frame);
  inject(b, frame);
  inject(b, frame);
  await barrier(b);
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.deepEqual(bodies(b), ["exactly once"]);
});

test("rotates session keys deterministically and keeps messaging", async () => {
  const port = await freePort();
  await startServer(port);
  const options = { rotationLimit: 3, previousLimit: 2 };
  const a = await peer(port, undefined, options);
  const b = await peer(port, undefined, options);
  const sessionA = a.messenger.session?.session;

  for (let i = 0; i < 12; i++) {
    const [from, to] = i % 2 === 0 ? [a, b] : [b, a];
    assert.deepEqual(
      await from.messenger.send(to.keys.identity.identity, `msg ${i}`, `m${i}`),
      { ok: true },
      `message ${i}`,
    );
    await until(() => to.inbox.length === Math.floor(i / 2) + 1, `rx ${i}`);
    assert.equal(to.inbox.at(-1)?.body, `msg ${i}`);
  }
  const rotations = frames(a.sent, "session").map(
    (f) => (f.payload as Json).epoch,
  );
  assert.ok(rotations.length >= 4, `rotations ${rotations}`);
  assert.deepEqual(
    rotations,
    rotations.map((_, i) => i),
  );
  assert.ok(
    frames(a.sent, "session").every(
      (f) => (f.payload as Json).session === sessionA,
    ),
  );
  const keysUsed = new Set(
    frames(a.sent, "session").map((f) => (f.payload as Json).key),
  );
  assert.equal(keysUsed.size, rotations.length);
  const sendEpochs = frames(a.sent, "send").map(
    (f) => (f.payload as Json).epoch as number,
  );
  assert.ok(sendEpochs.at(-1)! > 0);
  const epochs = a.messenger.session?.epochs ?? [];
  assert.ok(epochs.length >= 1 && epochs.length <= 2);
  assert.equal(Math.max(...epochs), rotations.at(-1));
  assert.deepEqual(
    bodies(b),
    [0, 2, 4, 6, 8, 10].map((i) => `msg ${i}`),
  );
});

test("previous epochs are discarded after the grace limit", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port, undefined, {
    rotationLimit: 1000,
    previousLimit: 2,
  });
  await a.messenger.send(b.keys.identity.identity, "before", "m0");
  await until(() => b.inbox.length === 1, "first");
  const atEpoch0 = lastDelivery(b);

  assert.equal(await b.messenger.rotate(), true);
  assert.deepEqual(b.messenger.session?.epochs, [0, 1]);
  inject(b, { ...atEpoch0, id: "late" });
  await until(() => b.inbox.length === 2, "late");
  assert.equal(b.inbox[1].body, null);

  await a.messenger.send(b.keys.identity.identity, "after 1", "m1");
  await a.messenger.send(b.keys.identity.identity, "after 2", "m2");
  await until(() => b.inbox.length === 4, "after");
  assert.deepEqual(b.messenger.session?.epochs, [1]);
  assert.equal(await b.messenger.rotate(), true);
  assert.equal(await b.messenger.rotate(), true);
  assert.deepEqual(b.messenger.session?.epochs, [2, 3]);
  assert.deepEqual(bodies(b), ["before", null, "after 1", "after 2"]);
});

test("in-flight messages to the previous epoch still decrypt", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port, undefined, { rotationLimit: 1000 });
  const original = a.client.request.bind(a.client);
  let rotated = false;
  a.client.request = (async (...args: Parameters<Client["request"]>) => {
    if (args[0].type === "send" && !rotated) {
      rotated = true;
      assert.equal(await b.messenger.rotate(), true);
    }
    return original(...args);
  }) as Client["request"];
  assert.deepEqual(
    await a.messenger.send(b.keys.identity.identity, "in flight", "m1"),
    { ok: true },
  );
  await until(() => b.inbox.length === 1, "delivery");
  assert.deepEqual(bodies(b), ["in flight"]);
  assert.equal((lastDelivery(b).envelope as Json).epoch, 0);
  assert.deepEqual(b.messenger.session?.epochs, [0, 1]);
});

test("simultaneous and repeated rotation requests stay consistent", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port, undefined, { rotationLimit: 1000 });
  const b = await peer(port, undefined, { rotationLimit: 1000 });

  const results = await Promise.all([
    a.messenger.rotate(),
    a.messenger.rotate(),
    b.messenger.rotate(),
    a.messenger.send(b.keys.identity.identity, "during", "d1"),
    b.messenger.send(a.keys.identity.identity, "during too", "d2"),
  ]);
  assert.deepEqual(results.slice(0, 3), [true, false, true]);
  await until(() => a.inbox.length === 1 && b.inbox.length === 1, "both");
  assert.deepEqual([bodies(a), bodies(b)], [["during too"], ["during"]]);
  assert.deepEqual(
    frames(a.sent, "session").map((f) => (f.payload as Json).epoch),
    [0, 1],
  );
  for (let i = 0; i < 3; i++) {
    assert.equal(await a.messenger.rotate(), true);
  }
  assert.deepEqual(a.messenger.session?.epochs, [3, 4]);
  assert.deepEqual(
    await a.messenger.send(b.keys.identity.identity, "after", "d3"),
    { ok: true },
  );
  await until(() => b.inbox.length === 2, "after");
});

test("a rejected rotation fails closed", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const original = a.client.request.bind(a.client);
  a.client.request = (async (...args: Parameters<Client["request"]>) => {
    if (args[0].type === "session") {
      return { type: "error", id: "x", payload: { code: "stale_session" } };
    }
    return original(...args);
  }) as Client["request"];
  assert.equal(await a.messenger.rotate(), false);
  assert.equal(a.messenger.state.active, false);
  assert.equal(sessionOf(a), null);
  assert.deepEqual(await a.messenger.send(a.keys.identity.identity, "x"), {
    ok: false,
    reason: "authentication_required",
  });
});

test("reconnect establishes a fresh session with new ephemeral keys", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const first = frames(a.sent, "session")[0].payload as Json;
  await a.messenger.send(b.keys.identity.identity, "before", "m1");
  await until(() => b.inbox.length === 1, "before");
  const old = lastDelivery(b);

  await stopServer(server);
  await until(
    () => !a.messenger.state.active && !b.messenger.state.active,
    "down",
  );
  assert.equal(sessionOf(a), null);
  await startServer(port);
  await until(() => a.messenger.state.active && b.messenger.state.active, "up");

  const offers = frames(a.sent, "session").map((f) => f.payload as Json);
  const second = offers.at(-1) as Json;
  assert.equal(second.epoch, 0);
  assert.notEqual(second.session, first.session);
  assert.notEqual(second.key, first.key);
  assert.equal(a.messenger.session?.session, second.session);

  inject(b, old);
  inject(b, {
    ...old,
    id: "m9",
    envelope: {
      ...(old.envelope as Json),
      session: b.messenger.session?.session,
    },
  });
  await until(() => b.inbox.length === 2, "stale processed");
  assert.deepEqual(bodies(b), ["before", null]);
  assert.deepEqual(
    await a.messenger.send(b.keys.identity.identity, "after", "m2"),
    { ok: true },
  );
  await until(() => b.inbox.length === 3, "after");
  assert.equal(b.inbox[2].body, "after");
});

test("server rejects raw plaintext and static-key sends", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  for (const payload of [
    { to: b.keys.identity.identity, body: "plaintext" },
    {
      to: b.keys.identity.identity,
      salt: encodeBase64Url(new Uint8Array(32)),
      iv: encodeBase64Url(new Uint8Array(12)),
      ciphertext: encodeBase64Url(new Uint8Array(32)),
    },
  ]) {
    const reply = await a.client.request({
      type: "send",
      payload: payload as never,
    });
    assert.deepEqual(reply, {
      type: "error",
      id: reply?.id,
      payload: { code: "invalid_payload" },
    });
  }
  await barrier(b);
  assert.deepEqual(b.inbox, []);
});

test("emits nothing when inactive or stopped", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  await a.messenger.send(b.keys.identity.identity, "first", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  const frame = lastDelivery(b);
  b.messenger.stop();
  inject(b, { ...frame, id: "m2" });
  await barrier(b);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(b.inbox.length, 1);
  assert.equal(sessionOf(b), null);
});

test("bounds pending decryptions", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  await a.messenger.send(b.keys.identity.identity, "seed", "m0");
  await until(() => b.inbox.length === 1, "seed");
  const frame = lastDelivery(b);
  for (let i = 0; i < maxPendingDecryptions + 20; i++) {
    inject(b, { ...frame, id: `f${i}` });
  }
  await until(
    () => b.inbox.length === maxPendingDecryptions + 21,
    "all processed",
  );
  assert.ok(b.inbox.slice(1).every((m) => m.body === null));
});

test("starts only once", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  a.messenger.start();
  b.messenger.start();
  await barrier(a);
  assert.equal(frames(a.sent, "session").length, 1);
  await a.messenger.send(b.keys.identity.identity, "once", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  await barrier(b);
  assert.equal(b.inbox.length, 1);
});

test("refuses to encrypt to substituted static or session keys", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const c = await peer(port);
  const cBundle = await c.keys.exchange.bind(c.keys.identity);
  assert.ok(cBundle);
  const observed: string[] = [];
  a.messenger.onKey((bundle) => observed.push(bundle.key));

  const genuine = await keyReply(a, b.keys.identity.identity);
  const cSession = (await keyReply(a, c.keys.identity.identity)).sessions[0];
  assert.ok(cSession);
  const replies = [
    { ...genuine, key: cBundle.key, signature: cBundle.signature },
    { ...genuine, sessions: [cSession] },
    { ...genuine, sessions: [{ ...genuine.sessions[0], epoch: 1 }] },
    { ...genuine, sessions: [{ ...genuine.sessions[0], key: cSession.key }] },
    {
      ...genuine,
      sessions: [{ ...genuine.sessions[0], session: cSession.session }],
    },
    { ...genuine, sessions: [genuine.sessions[0], cSession] },
  ];

  const original = a.client.request.bind(a.client);
  for (const payload of replies) {
    a.client.request = (async (...args: Parameters<Client["request"]>) => {
      if (args[0].type === "key") {
        return { type: "key", id: "q", payload };
      }
      return original(...args);
    }) as Client["request"];
    const sendsBefore = frames(a.sent, "send").length;
    assert.deepEqual(
      await a.messenger.send(b.keys.identity.identity, "secret"),
      { ok: false, reason: "encryption_failed" },
    );
    assert.equal(frames(a.sent, "send").length, sendsBefore);
  }
  a.client.request = original;
  await barrier(b);
  await barrier(c);
  assert.deepEqual(b.inbox, []);
  assert.deepEqual(c.inbox, []);
  assert.ok(!observed.includes(cBundle.key));
});

test("reports only verified static key bundles from lookups, sends, and deliveries", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const c = await peer(port);
  const seen: string[] = [];
  const names = new Map([
    [b.keys.exchange.publicKey, "b"],
    [c.keys.exchange.publicKey, "c"],
  ]);
  a.messenger.onKey((bundle: KeyBundle) => {
    const name = names.get(bundle.key) ?? "unknown";
    const owner = name === "b" ? b : c;
    seen.push(`${name}:${bundle.identity === owner.keys.identity.identity}`);
  });

  assert.equal(await a.messenger.lookup(b.keys.identity.identity), true);
  assert.equal(await a.messenger.lookup("not-an-identity"), false);
  assert.equal(await a.messenger.lookup(await stranger()), false);
  assert.deepEqual(
    await a.messenger.send(c.keys.identity.identity, "x", "s1"),
    { ok: true },
  );
  await b.messenger.send(a.keys.identity.identity, "y", "d1");
  await until(() => a.inbox.length === 1, "delivery");
  inject(a, { ...lastDelivery(a), id: "d2", key: c.keys.exchange.publicKey });
  await until(() => a.inbox.length === 2, "forged processed");
  assert.deepEqual(seen, ["b:true", "c:true", "b:true"]);

  a.messenger.stop();
  assert.equal(await a.messenger.lookup(b.keys.identity.identity), false);
  assert.equal(seen.length, 3);
});

test("the ratchet continues across outer-session rotation and reconnect", async () => {
  const port = await freePort();
  await startServer(port);
  const options = { rotationLimit: 1000 };
  const a = await peer(port, undefined, options);
  const b = await peer(port, undefined, options);

  assert.deepEqual(await a.messenger.send(b.id, "first", "x1"), { ok: true });
  await until(() => b.inbox.length === 1, "first");
  const reader = b;
  assert.equal(reader.inbox[0].body, "first");
  const old = lastDelivery(reader);

  assert.equal(await a.messenger.rotate(), true);
  assert.equal(await reader.messenger.rotate(), true);
  assert.deepEqual(await a.messenger.send(b.id, "after rotation", "x2"), {
    ok: true,
  });
  await until(() => reader.inbox.length === 2, "after rotation");
  assert.equal(reader.inbox[1].body, "after rotation");
  assert.deepEqual(await reader.messenger.send(a.id, "reply", "y1"), {
    ok: true,
  });
  await until(() => a.inbox.length === 1, "reply");
  assert.equal(a.inbox[0].body, "reply");

  const outer = reader.messenger.session?.session;
  reader.messenger.stop();
  reader.messenger.start();
  await until(() => reader.messenger.state.active, "fresh outer session");
  assert.notEqual(reader.messenger.session?.session, outer);
  inject(reader, old);
  inject(reader, {
    ...old,
    envelope: {
      ...(old.envelope as Json),
      session: reader.messenger.session?.session,
    },
  });
  assert.deepEqual(await a.messenger.send(b.id, "after reconnect", "x3"), {
    ok: true,
  });
  await until(() => reader.inbox.length === 3, "after reconnect");
  assert.equal(reader.inbox.at(-1)?.body, "after reconnect");
  assert.deepEqual(
    reader.inbox.map((m) => m.body),
    ["first", "after rotation", "after reconnect"],
  );
});
