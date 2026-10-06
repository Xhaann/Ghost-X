import assert from "node:assert/strict";
import { test } from "node:test";
import { Authenticator } from "./auth.ts";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { Client } from "./client.ts";
import { ExchangeKey, type KeyBundle } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import {
  type Incoming,
  Messenger,
  type MessengerOptions,
  type MessengerState,
  maxPendingDecryptions,
} from "./messenger.ts";
import { maxBodySize, sessionIdSize } from "./protocol.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  freePort,
  startServer,
  stopServer,
  track,
  useServer,
  waitFor,
} from "./testing.ts";

useServer();

type Keys = { identity: IdentityKey; exchange: ExchangeKey };

type Peer = {
  client: Client;
  keys: Keys;
  messenger: Messenger;
  inbox: Incoming[];
  states: MessengerState[];
  sent: string[];
  received: string[];
  deliver: (data: string) => void;
  hold: (held: boolean) => void;
};

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

async function keys(): Promise<Keys> {
  const [identity, exchange] = await Promise.all([
    IdentityKey.generate(),
    ExchangeKey.generate(),
  ]);
  return { identity, exchange };
}

async function peer(
  port: number,
  own?: Keys,
  options: MessengerOptions & { wait?: boolean } = {},
): Promise<Peer> {
  const transport = track(
    new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
  );
  const sent: string[] = [];
  const received: string[] = [];
  const listeners: ((data: string) => void)[] = [];
  let held = false;
  const send = transport.send.bind(transport);
  transport.send = (data: string) => {
    sent.push(data);
    return send(data);
  };
  transport.onData((data) => received.push(data));
  const onData = transport.onData.bind(transport);
  transport.onData = (listener: (data: string) => void) => {
    listeners.push(listener);
    return onData((data) => {
      if (!(held && data.includes('"type":"message"'))) {
        listener(data);
      }
    });
  };
  const client = track(new Client(transport));
  const k = own ?? (await keys());
  const auth = new Authenticator(client, k.identity);
  const messenger = new Messenger(
    client,
    auth,
    k.identity,
    k.exchange,
    options,
  );
  track({ close: () => messenger.stop() });
  track({ close: () => auth.stop() });
  const inbox: Incoming[] = [];
  const states: MessengerState[] = [];
  messenger.onMessage((message) => inbox.push(message));
  messenger.onState((state) => states.push(state));
  auth.start();
  messenger.start();
  client.open();
  await waitFor(client, "connected");
  if (options.wait !== false) {
    await until(() => messenger.state.active, "messenger active");
  }
  return {
    client,
    keys: k,
    messenger,
    inbox,
    states,
    sent,
    received,
    deliver: (data) => listeners.forEach((listener) => listener(data)),
    hold: (value) => {
      held = value;
    },
  };
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
  assert.deepEqual(types.slice(-3), ["authenticate", "publish", "session"]);
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
  const k = await keys();
  const a = await peer(port, k, { wait: false });
  a.messenger.stop();
  assert.deepEqual(await a.messenger.send(k.identity.identity, "x"), {
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

test("each session of the recipient identity gets its own independently keyed envelope", async () => {
  const port = await freePort();
  await startServer(port);
  const bKeys = await keys();
  const a = await peer(port);
  const b1 = await peer(port, bKeys);
  const b2 = await peer(port, bKeys);
  assert.notEqual(b1.messenger.session?.session, b2.messenger.session?.session);

  assert.deepEqual(
    await a.messenger.send(bKeys.identity.identity, "both", "m1"),
    { ok: true },
  );
  for (const b of [b1, b2]) {
    await until(() => b.inbox.length === 1, "delivery");
    await barrier(b);
    assert.deepEqual(bodies(b), ["both"]);
  }
  const envelopes = (frames(a.sent, "send")[0].payload as Json)
    .envelopes as Json[];
  assert.equal(envelopes.length, 2);
  assert.notEqual(envelopes[0].ciphertext, envelopes[1].ciphertext);
  assert.notEqual(envelopes[0].salt, envelopes[1].salt);

  const forB1 = lastDelivery(b1);
  inject(b2, { ...forB1, id: "x1" });
  inject(b2, {
    ...forB1,
    id: "x2",
    envelope: {
      ...(forB1.envelope as Json),
      session: b2.messenger.session?.session,
    },
  });
  await until(() => b2.inbox.length === 2, "cross-session processed");
  assert.deepEqual(bodies(b2), ["both", null]);
});

test("a second session cannot bind a different static key", async () => {
  const port = await freePort();
  await startServer(port);
  const first = await keys();
  await peer(port, first);
  const conflicting = await peer(
    port,
    { identity: first.identity, exchange: await ExchangeKey.generate() },
    { wait: false },
  );
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
  const absent = await keys();
  const frameCount = frames(a.sent, "send").length;

  assert.deepEqual(await a.messenger.send(absent.identity.identity, "x"), {
    ok: false,
    reason: "recipient_unavailable",
  });
  for (const [to, body, reason] of [
    ["bad", "x", "invalid_payload"],
    [absent.identity.identity, "", "invalid_payload"],
    [absent.identity.identity, "a\u0000", "invalid_payload"],
    [
      absent.identity.identity,
      "a".repeat(maxBodySize + 1),
      "message_too_large",
    ],
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
  const absent = await keys();
  assert.equal(await a.messenger.lookup(absent.identity.identity), false);
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

test("two sessions per identity stay isolated through rotation and reconnect", async () => {
  const port = await freePort();
  await startServer(port);
  const aKeys = await keys();
  const bKeys = await keys();
  const options = { rotationLimit: 1000 };
  const a1 = await peer(port, aKeys, options);
  const a2 = await peer(port, aKeys, options);
  const b1 = await peer(port, bKeys, options);
  const b2 = await peer(port, bKeys, options);
  const idA = aKeys.identity.identity;
  const idB = bKeys.identity.identity;
  const sessions = [a1, a2, b1, b2].map((p) => p.messenger.session?.session);
  assert.equal(new Set(sessions).size, 4);

  assert.deepEqual(await a1.messenger.send(idB, "a1 to b", "x1"), { ok: true });
  await until(() => b1.inbox.length === 1 && b2.inbox.length === 1, "fanout");
  const toB1 = lastDelivery(b1);
  const toB2 = lastDelivery(b2);
  assert.notEqual(
    (toB1.envelope as Json).ciphertext,
    (toB2.envelope as Json).ciphertext,
  );

  assert.equal(await a1.messenger.rotate(), true);
  assert.equal(await b1.messenger.rotate(), true);
  assert.deepEqual(a2.messenger.session?.epochs, [0]);
  assert.deepEqual(b2.messenger.session?.epochs, [0]);
  assert.deepEqual(await a2.messenger.send(idB, "a2 to b", "x2"), { ok: true });
  assert.deepEqual(await a1.messenger.send(idB, "a1 rotated", "x3"), {
    ok: true,
  });
  await until(
    () => b1.inbox.length === 3 && b2.inbox.length === 3,
    "after rotation",
  );
  assert.deepEqual(bodies(b1), ["a1 to b", "a2 to b", "a1 rotated"]);
  assert.deepEqual(bodies(b2), ["a1 to b", "a2 to b", "a1 rotated"]);
  assert.equal(await a2.messenger.rotate(), true);
  assert.equal(await b2.messenger.rotate(), true);
  assert.deepEqual(await b2.messenger.send(idA, "b2 to a", "y1"), { ok: true });
  await until(() => a1.inbox.length === 1 && a2.inbox.length === 1, "back");
  assert.deepEqual([bodies(a1), bodies(a2)], [["b2 to a"], ["b2 to a"]]);

  const crossSession = {
    ...toB1,
    id: "z1",
    envelope: {
      ...(toB1.envelope as Json),
      session: b2.messenger.session?.session,
    },
  };
  inject(b2, crossSession);
  inject(b2, toB2);
  const toA = lastDelivery(a1);
  inject(b1, {
    ...toA,
    id: "z2",
    envelope: {
      ...(toA.envelope as Json),
      session: b1.messenger.session?.session,
    },
  });
  await until(() => b2.inbox.length === 4 && b1.inbox.length === 4, "cross");
  assert.equal(b2.inbox.at(-1)?.body, null);
  assert.equal(b1.inbox.at(-1)?.body, null);

  const oldB1 = b1.messenger.session?.session;
  b1.messenger.stop();
  b1.messenger.start();
  await until(() => b1.messenger.state.active, "b1 fresh");
  assert.notEqual(b1.messenger.session?.session, oldB1);
  assert.deepEqual(b1.messenger.session?.epochs, [0]);
  assert.deepEqual(b2.messenger.session?.epochs, [0, 1]);
  inject(b1, {
    ...toB1,
    id: "z3",
    envelope: {
      ...(toB1.envelope as Json),
      session: b1.messenger.session?.session,
    },
  });
  assert.deepEqual(await a2.messenger.send(idB, "after reconnect", "x4"), {
    ok: true,
  });
  await until(
    () => b1.inbox.length === 6 && b2.inbox.length === 5,
    "reconnected",
  );
  assert.equal(b1.inbox[4].body, null);
  assert.equal(b1.inbox[5].body, "after reconnect");
  assert.equal(b2.inbox[4].body, "after reconnect");
  assert.equal(
    frames(a2.sent, "send")
      .map((f) => ((f.payload as Json).envelopes as Json[]).length)
      .at(-1),
    2,
  );
});
