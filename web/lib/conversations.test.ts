import { encodeBase64Url } from "./base64.ts";
import assert from "node:assert/strict";
import { type TestContext, test } from "node:test";
import type { Client } from "./client.ts";
import {
  type ConversationsState,
  Conversations,
  type HistoryPort,
  type MessageSource,
  type SettledDelivery,
  maxConversations,
  maxMessages,
} from "./conversations.ts";
import { IdentityKey } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type {
  MessengerState,
  Receipt,
  Receiver,
  SendResult,
} from "./messenger.ts";
import type { Messenger } from "./messenger.ts";
import { outboxLifetime } from "./outbox.ts";
import { createMessageId, maxBodySize } from "./protocol.ts";
import {
  type SecureDevice,
  freePort,
  secureDevice,
  startServer,
  stopServer,
  track,
  useServer,
} from "./testing.ts";

useServer();

const DEVICE = encodeBase64Url(new Uint8Array(16));

type Incoming = { id: string; from: string; body: string | null };

class Source implements MessageSource {
  state: MessengerState = { active: true };
  readonly states = new Listeners<MessengerState>();
  receiver: Receiver | null = null;
  readonly sent: {
    to: string;
    body: string;
    id: string;
    resolve: (result: SendResult) => void;
  }[] = [];

  onState(listener: (state: MessengerState) => void) {
    return this.states.add(listener);
  }

  receive(receiver: Receiver) {
    this.receiver = receiver;
    return () => {
      this.receiver = null;
    };
  }

  send(to: string, body: string, id: string): Promise<SendResult> {
    return new Promise((resolve) => this.sent.push({ to, body, id, resolve }));
  }

  async deliver(message: Incoming): Promise<boolean> {
    if (!this.receiver) {
      return false;
    }
    if (message.body === null) {
      this.receiver.reject(message);
      return true;
    }
    if (this.receiver.has(message.from, message.id)) {
      return true;
    }
    return this.receiver.accept({ ...message, body: message.body });
  }

  async receipt(receipt: Receipt): Promise<boolean> {
    return this.receiver ? this.receiver.settle(receipt) : false;
  }

  setActive(active: boolean) {
    this.state = { active };
    this.states.emit(this.state);
  }
}

async function identities(n: number): Promise<string[]> {
  const keys = await Promise.all(
    Array.from({ length: n }, () => IdentityKey.generate()),
  );
  return keys.map((key) => key.identity);
}

async function setup() {
  const [self, b, c] = await identities(3);
  const source = new Source();
  const store = new Conversations(source, self);
  const log: ConversationsState[] = [];
  store.onState((state) => log.push(state));
  store.start();
  return { self, b, c, source, store, log };
}

function conversation(store: Conversations, identity: string) {
  return store.state.conversations.find((c) => c.identity === identity);
}

function bodies(store: Conversations, identity: string): (string | null)[] {
  return conversation(store, identity)?.messages.map((m) => m.body) ?? [];
}

function accepted(store: Conversations, body: string) {
  const attempt = store.send(body);
  assert.equal(attempt.accepted, true);
  return attempt as Extract<typeof attempt, { accepted: true }>;
}

test("starts empty", async () => {
  const { store } = await setup();
  assert.deepEqual(store.state, {
    connected: true,
    active: null,
    conversations: [],
  });
});

test("opens a conversation only for a real identity", async () => {
  const { store, b } = await setup();

  assert.equal(store.open("not-an-identity"), false);
  assert.equal(store.open(b + "A"), false);
  assert.equal(store.state.conversations.length, 0);

  assert.equal(store.open(b), true);
  assert.equal(store.state.active, b);
  assert.deepEqual(conversation(store, b)?.messages, []);
  assert.equal(conversation(store, b)?.unread, 0);

  assert.equal(store.open(b), true);
  assert.equal(store.state.conversations.length, 1);
});

test("a received message creates the sender's conversation", async () => {
  const { store, source, self, b } = await setup();

  await source.deliver({ id: "r1", from: b, body: "hi" });

  const conv = conversation(store, b);
  assert.equal(store.state.conversations.length, 1);
  assert.deepEqual(conv?.messages, [
    {
      id: "r1",
      from: b,
      to: self,
      body: "hi",
      sequence: 1,
      direction: "received",
    },
  ]);
  assert.equal(conv?.unread, 1);
  assert.equal(store.state.active, null);
});

test("a sent message lands in the active conversation as sending", async () => {
  const { store, source, self, b } = await setup();
  store.open(b);

  const attempt = accepted(store, "hello");

  assert.equal(source.sent.length, 1);
  assert.deepEqual(
    { to: source.sent[0].to, body: source.sent[0].body, id: source.sent[0].id },
    { to: b, body: "hello", id: attempt.id },
  );
  const [message] = conversation(store, b)?.messages ?? [];
  assert.equal(message.direction, "sent");
  assert.ok(message.direction === "sent");
  assert.equal(message.delivery, "sending");
  assert.equal(message.from, self);
  assert.equal(message.to, b);
  assert.equal(message.id, attempt.id);
});

test("classifies direction from the local identity", async () => {
  const { store, source, self, b } = await setup();
  store.open(b);
  accepted(store, "out");
  await source.deliver({ id: "r1", from: b, body: "in" });

  const messages = conversation(store, b)?.messages ?? [];
  assert.deepEqual(
    messages.map((m) => [m.direction, m.from, m.to]),
    [
      ["sent", self, b],
      ["received", b, self],
    ],
  );
});

test("keeps conversations isolated and preserves them across switches", async () => {
  const { store, source, b, c } = await setup();

  store.open(b);
  accepted(store, "to b");
  store.open(c);
  accepted(store, "to c");
  await source.deliver({ id: "rb", from: b, body: "from b" });
  await source.deliver({ id: "rc", from: c, body: "from c" });
  store.open(b);

  assert.deepEqual(bodies(store, b), ["to b", "from b"]);
  assert.deepEqual(bodies(store, c), ["to c", "from c"]);
  assert.equal(source.sent[0].to, b);
  assert.equal(source.sent[1].to, c);
});

test("switches and closes the active conversation", async () => {
  const { store, b, c } = await setup();

  store.open(b);
  assert.equal(store.state.active, b);
  store.open(c);
  assert.equal(store.state.active, c);
  store.close();
  assert.equal(store.state.active, null);
  assert.equal(store.state.conversations.length, 2);
  assert.deepEqual(store.send("x"), {
    accepted: false,
    reason: "no_conversation",
  });
});

test("tracks unread for inactive conversations only", async () => {
  const { store, source, b, c } = await setup();
  store.open(c);

  await source.deliver({ id: "1", from: b, body: "a" });
  await source.deliver({ id: "2", from: b, body: "b" });
  await source.deliver({ id: "3", from: c, body: "c" });

  assert.equal(conversation(store, b)?.unread, 2);
  assert.equal(conversation(store, c)?.unread, 0);

  store.open(b);
  assert.equal(conversation(store, b)?.unread, 0);
  await source.deliver({ id: "4", from: b, body: "d" });
  assert.equal(conversation(store, b)?.unread, 0);
  await source.deliver({ id: "5", from: c, body: "e" });
  assert.equal(conversation(store, c)?.unread, 1);
});

test("ignores duplicate message ids", async () => {
  const { store, source, b, log } = await setup();

  for (let i = 0; i < 5; i++) {
    await source.deliver({ id: "dup", from: b, body: "same" });
  }
  const emissions = log.length;
  await source.deliver({ id: "dup", from: b, body: "different body" });

  assert.deepEqual(bodies(store, b), ["same"]);
  assert.equal(conversation(store, b)?.unread, 1);
  assert.equal(log.length, emissions);
});

test("records undecryptable messages without fabricated text", async () => {
  const { store, source, b } = await setup();

  await source.deliver({ id: "bad", from: b, body: null });
  await source.deliver({ id: "bad", from: b, body: null });
  await source.deliver({ id: "good", from: b, body: "readable" });

  const messages = conversation(store, b)?.messages ?? [];
  assert.deepEqual(
    messages.map((m) => [m.id, m.direction, m.body]),
    [
      ["bad", "received", null],
      ["good", "received", "readable"],
    ],
  );
  assert.equal(conversation(store, b)?.unread, 2);
});

test("does not duplicate a self-addressed message", async () => {
  const { store, source, self } = await setup();
  store.open(self);
  const attempt = accepted(store, "note");

  await source.deliver({ id: attempt.id, from: self, body: "note" });

  assert.deepEqual(bodies(store, self), ["note"]);
});

test("orders messages deterministically by arrival", async () => {
  const { store, source, b } = await setup();
  store.open(b);

  const first = accepted(store, "1");
  await source.deliver({ id: "r", from: b, body: "2" });
  const third = accepted(store, "3");
  source.sent[1].resolve({ ok: true, devices: 1, pending: 0 });
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  await Promise.all([first.delivery, third.delivery]);

  const messages = conversation(store, b)?.messages ?? [];
  assert.deepEqual(
    messages.map((m) => m.body),
    ["1", "2", "3"],
  );
  const sequences = messages.map((m) => m.sequence);
  assert.deepEqual(
    sequences,
    [...sequences].sort((x, y) => x - y),
  );
  assert.equal(new Set(sequences).size, sequences.length);
});

test("server acceptance is queued and only a receipt marks a message delivered", async () => {
  const { store, source, b, c } = await setup();
  store.open(b);
  const first = accepted(store, "first");
  const second = accepted(store, "second");
  const third = accepted(store, "third");

  source.sent[1].resolve({ ok: true, devices: 1, pending: 0 });
  assert.equal(await second.delivery, "queued");

  const delivery = () =>
    (conversation(store, b)?.messages ?? []).map((m) =>
      m.direction === "sent" ? m.delivery : m.direction,
    );
  assert.deepEqual(delivery(), ["sending", "queued", "sending"]);

  assert.equal(
    await source.receipt({
      to: b,
      device: DEVICE,
      id: second.id,
      status: "delivered",
    }),
    true,
  );
  assert.deepEqual(delivery(), ["sending", "delivered", "sending"]);
  await source.receipt({
    to: c,
    device: DEVICE,
    id: second.id,
    status: "expired",
  });
  await source.receipt({
    to: b,
    device: DEVICE,
    id: second.id,
    status: "expired",
  });
  assert.deepEqual(delivery(), ["sending", "delivered", "sending"]);

  await source.receipt({
    to: b,
    device: DEVICE,
    id: third.id,
    status: "delivered",
  });
  source.sent[2].resolve({ ok: true, devices: 1, pending: 0 });
  assert.equal(await third.delivery, "delivered");

  source.sent[0].resolve({ ok: false, reason: "recipient_unavailable" });
  assert.equal(await first.delivery, "unavailable");
  assert.deepEqual(delivery(), ["unavailable", "delivered", "delivered"]);
  await source.receipt({
    to: b,
    device: DEVICE,
    id: first.id,
    status: "delivered",
  });
  assert.deepEqual(delivery(), ["delivered", "delivered", "delivered"]);
});

test("an expiry receipt marks a queued message not delivered", async () => {
  const { store, source, b } = await setup();
  store.open(b);
  const attempt = accepted(store, "late");
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  assert.equal(await attempt.delivery, "queued");
  await source.receipt({
    to: b,
    device: DEVICE,
    id: attempt.id,
    status: "expired",
  });
  const [message] = conversation(store, b)?.messages ?? [];
  assert.ok(message.direction === "sent");
  assert.equal(message.delivery, "expired");
});

test("a message held only on this device is pending until a relay accepts it", async () => {
  const { store, source, b } = await setup();
  store.open(b);
  const held = accepted(store, "held locally");
  const partial = accepted(store, "partly relayed");
  source.sent[0].resolve({ ok: true, devices: 0, pending: 1 });
  source.sent[1].resolve({ ok: true, devices: 1, pending: 1 });
  assert.equal(await held.delivery, "pending");
  assert.equal(await partial.delivery, "queued");
  const delivery = () =>
    (conversation(store, b)?.messages ?? []).map((m) =>
      m.direction === "sent" ? m.delivery : "received",
    );
  assert.deepEqual(delivery(), ["pending", "queued"]);
  assert.ok(await source.receiver?.relayed?.({ to: b, id: held.id }));
  assert.deepEqual(delivery(), ["queued", "queued"]);
  await source.receipt({
    to: b,
    device: DEVICE,
    id: held.id,
    status: "delivered",
  });
  assert.deepEqual(delivery(), ["delivered", "queued"]);
  assert.ok(await source.receiver?.relayed?.({ to: b, id: held.id }));
  assert.deepEqual(delivery(), ["delivered", "queued"], "never regresses");
});

test("maps other failures to failed without touching other messages", async () => {
  const { store, source, b, c } = await setup();
  store.open(c);
  const toC = accepted(store, "c");
  store.open(b);
  const results: SendResult[] = [
    { ok: false, reason: "internal_error" },
    { ok: false, reason: "not_sent" },
    { ok: false, reason: "authentication_required" },
    { ok: false, reason: "invalid_payload" },
  ];
  const attempts = results.map((_, i) => accepted(store, `b${i}`));
  results.forEach((result, i) => source.sent[i + 1].resolve(result));
  await Promise.all(attempts.map((a) => a.delivery));
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  await toC.delivery;

  const states = (id: string) =>
    (conversation(store, id)?.messages ?? []).map((m) =>
      m.direction === "sent" ? m.delivery : "received",
    );
  assert.deepEqual(states(b), ["failed", "failed", "failed", "failed"]);
  assert.deepEqual(states(c), ["queued"]);
});

test("rejects empty, invalid, and oversized messages without adding them", async () => {
  const { store, source, b } = await setup();
  store.open(b);

  assert.deepEqual(store.send(""), {
    accepted: false,
    reason: "invalid_payload",
  });
  assert.deepEqual(store.send("a\u0000b"), {
    accepted: false,
    reason: "invalid_payload",
  });
  assert.deepEqual(store.send("a".repeat(maxBodySize + 1)), {
    accepted: false,
    reason: "message_too_large",
  });
  assert.equal(accepted(store, "a".repeat(maxBodySize)).accepted, true);

  assert.equal(source.sent.length, 1);
  assert.equal(conversation(store, b)?.messages.length, 1);
});

test("refuses to send while disconnected but keeps history", async () => {
  const { store, source, b } = await setup();
  store.open(b);
  accepted(store, "before");

  source.setActive(false);
  assert.equal(store.state.connected, false);
  assert.deepEqual(store.send("while down"), {
    accepted: false,
    reason: "authentication_required",
  });
  source.setActive(true);

  assert.equal(store.state.connected, true);
  assert.deepEqual(bodies(store, b), ["before"]);
  assert.equal(source.sent.length, 1);
});

test("starts once and stops cleanly like a StrictMode remount", async () => {
  const [self, b] = await identities(2);
  const source = new Source();
  const first = new Conversations(source, self);
  const firstLog: ConversationsState[] = [];
  first.onState((state) => firstLog.push(state));
  first.start();
  first.start();
  first.stop();
  const second = new Conversations(source, self);
  second.start();
  second.start();

  await source.deliver({ id: "r1", from: b, body: "once" });

  assert.deepEqual(bodies(second, b), ["once"]);
  assert.deepEqual(first.state.conversations, []);
  assert.equal(firstLog.at(-1)?.conversations.length, 0);
  const emitted = firstLog.length;
  await source.deliver({ id: "r2", from: b, body: "later" });
  source.setActive(false);
  assert.equal(firstLog.length, emitted);
  assert.equal(first.open(b), false);
});

test("ignores results that settle after stop", async () => {
  const { store, source, b, log } = await setup();
  store.open(b);
  const attempt = accepted(store, "pending");

  store.stop();
  const emitted = log.length;
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  assert.equal(await attempt.delivery, "queued");

  assert.equal(log.length, emitted);
  assert.deepEqual(store.state, {
    connected: false,
    active: null,
    conversations: [],
  });
});

test("ignores results from before a restart of the same store", async () => {
  const { store, source, b, log } = await setup();
  store.open(b);
  const attempt = accepted(store, "old session");

  store.stop();
  store.start();
  store.open(b);
  const emitted = log.length;
  const snapshot = store.state;
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  await attempt.delivery;

  assert.equal(log.length, emitted);
  assert.equal(store.state, snapshot);
  assert.deepEqual(conversation(store, b)?.messages, []);
});

test("returns a stable state object between changes", async () => {
  const { store, source, b } = await setup();
  await source.deliver({ id: "r1", from: b, body: "x" });
  const snapshot = store.state;

  assert.equal(store.state, snapshot);
  assert.equal(store.state.conversations, snapshot.conversations);
  store.close();
  assert.equal(store.state, snapshot);
});

test("bounds messages per conversation", async () => {
  const { store, source, b } = await setup();
  for (let i = 0; i < maxMessages + 10; i++) {
    await source.deliver({ id: `m${i}`, from: b, body: `${i}` });
  }

  const messages = conversation(store, b)?.messages ?? [];
  assert.equal(messages.length, maxMessages);
  assert.equal(messages[0].body, "10");
});

test("bounds conversations and never evicts the active one", async () => {
  const [self, ...others] = await identities(maxConversations + 3);
  const source = new Source();
  const store = new Conversations(source, self);
  store.start();
  store.open(others[0]);

  for (const identity of others.slice(1)) {
    await source.deliver({ id: "x", from: identity, body: "hi" });
  }

  assert.equal(store.state.conversations.length, maxConversations);
  assert.ok(conversation(store, others[0]));
  assert.equal(store.state.active, others[0]);
  assert.ok(conversation(store, others.at(-1) ?? ""));
});

test("lists conversations by most recent activity", async () => {
  const { store, source, b, c } = await setup();
  await source.deliver({ id: "1", from: b, body: "x" });
  await source.deliver({ id: "2", from: c, body: "y" });
  assert.deepEqual(
    store.state.conversations.map((conv) => conv.identity),
    [c, b],
  );
  await source.deliver({ id: "3", from: b, body: "z" });
  assert.deepEqual(
    store.state.conversations.map((conv) => conv.identity),
    [b, c],
  );
});

type Peer = {
  key: { identity: string };
  client: Client;
  messenger: Messenger;
  store: Conversations;
  device: SecureDevice;
};

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function peer(port: number): Promise<Peer> {
  const device = await secureDevice(port);
  const store = new Conversations(device.messenger, device.id);
  track({ close: () => store.stop() });
  store.start();
  await until(() => store.state.connected, "connected store");
  return {
    key: { identity: device.id },
    client: device.client,
    messenger: device.messenger,
    store,
    device,
  };
}

async function delivered(
  store: Conversations,
  peer: string,
  attempt: { id: string; delivery: Promise<unknown> },
): Promise<void> {
  assert.equal(await attempt.delivery, "queued");
  await until(
    () =>
      conversation(store, peer)?.messages.some(
        (m) =>
          m.id === attempt.id &&
          m.direction === "sent" &&
          m.delivery === "delivered",
      ) === true,
    "delivery receipt",
  );
}

async function barrier(p: Peer): Promise<void> {
  const reply = await p.client.request({
    type: "ping",
    payload: { sentAt: 1 },
  });
  assert.equal(reply?.type, "pong");
}

test("real conversation between identities with replies and isolation", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const c = await peer(port);

  a.store.open(b.key.identity);
  const first = accepted(a.store, "hello b");
  await delivered(a.store, b.key.identity, first);
  await until(
    () => conversation(b.store, a.key.identity)?.messages.length === 1,
    "b receives",
  );
  assert.equal(conversation(b.store, a.key.identity)?.unread, 1);

  b.store.open(a.key.identity);
  assert.equal(conversation(b.store, a.key.identity)?.unread, 0);
  await delivered(b.store, a.key.identity, accepted(b.store, "hello a"));
  await until(
    () => bodies(a.store, b.key.identity).length === 2,
    "a receives reply",
  );
  assert.deepEqual(bodies(a.store, b.key.identity), ["hello b", "hello a"]);
  assert.equal(conversation(a.store, b.key.identity)?.unread, 0);

  a.store.open(c.key.identity);
  await delivered(
    b.store,
    a.key.identity,
    accepted(b.store, "while a views c"),
  );
  await until(() => bodies(a.store, b.key.identity).length === 3, "a receives");
  assert.deepEqual(bodies(a.store, c.key.identity), []);
  assert.equal(conversation(a.store, b.key.identity)?.unread, 1);
  assert.equal(conversation(a.store, c.key.identity)?.unread, 0);
  assert.deepEqual(c.store.state.conversations, []);
});

test("real duplicate frames and reconnects do not duplicate messages", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const a = await peer(port);
  const b = await peer(port);

  a.store.open(b.key.identity);
  const sent = accepted(a.store, "once");
  await sent.delivery;
  await until(() => bodies(b.store, a.key.identity).length === 1, "delivery");
  const frame = b.device.received.find((data) => data.includes(sent.id));
  assert.ok(frame);
  b.device.deliver(frame);
  b.device.deliver(frame);
  await barrier(b);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(bodies(b.store, a.key.identity), ["once"]);

  await stopServer(server);
  await until(
    () => !a.store.state.connected && !b.store.state.connected,
    "disconnected",
  );
  assert.deepEqual(a.store.send("down"), {
    accepted: false,
    reason: "authentication_required",
  });
  await startServer(port);
  await until(
    () => a.store.state.connected && b.store.state.connected,
    "reconnected",
  );
  await barrier(b);

  assert.deepEqual(bodies(b.store, a.key.identity), ["once"]);
  assert.deepEqual(bodies(a.store, b.key.identity), ["once"]);
  await delivered(a.store, b.key.identity, accepted(a.store, "after"));
  await until(
    () => bodies(b.store, a.key.identity).length === 2,
    "post-reconnect delivery",
  );
  assert.deepEqual(bodies(b.store, a.key.identity), ["once", "after"]);
});

test("real recipient that never published is shown as unavailable", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const stranger = (await IdentityKey.generate()).identity;
  a.store.open(stranger);
  const attempt = accepted(a.store, "anyone there");
  assert.equal(await attempt.delivery, "unavailable");
  const [message] = conversation(a.store, stranger)?.messages ?? [];
  assert.ok(message.direction === "sent");
  assert.equal(message.delivery, "unavailable");
});

function deliveryOf(store: Conversations, identity: string, id: string) {
  const message = conversation(store, identity)?.messages.find(
    (m) => m.id === id,
  );
  assert.ok(message?.direction === "sent");
  return message.delivery;
}

test("a relay-accepted message expires exactly at the relay queue lifetime", async () => {
  const [self, peer] = await identities(2);
  const source = new Source();
  let now = 1_000_000;
  const store = new Conversations(source, self, {
    relay: true,
    now: () => now,
  });
  store.start();
  store.open(peer);
  const attempt = store.send("held by the relay");
  assert.ok(attempt.accepted);
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  assert.equal(await attempt.delivery, "queued");

  now += outboxLifetime - 1;
  source.setActive(true);
  assert.equal(deliveryOf(store, peer, attempt.id), "queued");
  now += 1;
  source.setActive(true);
  assert.equal(deliveryOf(store, peer, attempt.id), "expired");
});

test("a delivery receipt before the relay lifetime is never replaced by expiry", async () => {
  const [self, peer] = await identities(2);
  const source = new Source();
  let now = 1_000_000;
  const store = new Conversations(source, self, {
    relay: true,
    now: () => now,
  });
  store.start();
  store.open(peer);
  const attempt = store.send("delivered in time");
  assert.ok(attempt.accepted);
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  assert.equal(await attempt.delivery, "queued");
  await source.receipt({
    to: peer,
    device: DEVICE,
    id: attempt.id,
    status: "delivered",
  });
  assert.equal(deliveryOf(store, peer, attempt.id), "delivered");

  now += outboxLifetime * 2;
  source.setActive(true);
  assert.equal(deliveryOf(store, peer, attempt.id), "delivered");
  await source.receipt({
    to: peer,
    device: DEVICE,
    id: attempt.id,
    status: "expired",
  });
  source.setActive(true);
  assert.equal(deliveryOf(store, peer, attempt.id), "delivered");
});

test("a queued message without a relay acceptance time never expires", async () => {
  const [self, peer] = await identities(2);
  const source = new Source();
  let now = 1_000_000;
  const store = new Conversations(source, self, { now: () => now });
  store.start();
  store.open(peer);
  const attempt = store.send("acknowledged by a peer device");
  assert.ok(attempt.accepted);
  source.sent[0].resolve({ ok: true, devices: 1, pending: 0 });
  assert.equal(await attempt.delivery, "queued");

  now += outboxLifetime * 10;
  source.setActive(true);
  assert.equal(deliveryOf(store, peer, attempt.id), "queued");
});

test("a deferred message expires a relay lifetime after the relay accepts it", async () => {
  const [self, peer] = await identities(2);
  const source = new Source();
  const sent = 1_000_000;
  let now = sent;
  const store = new Conversations(source, self, {
    relay: true,
    now: () => now,
  });
  store.start();
  store.open(peer);
  const attempt = store.send("waiting for a session");
  assert.ok(attempt.accepted);
  source.sent[0].resolve({ ok: true, devices: 0, pending: 1 });
  assert.equal(await attempt.delivery, "pending");

  now = sent + 60_000;
  assert.ok(source.receiver?.relayed);
  assert.ok(await source.receiver.relayed({ to: peer, id: attempt.id }));
  assert.equal(deliveryOf(store, peer, attempt.id), "queued");

  now = sent + outboxLifetime;
  source.setActive(true);
  assert.equal(deliveryOf(store, peer, attempt.id), "queued");
  now = sent + 60_000 + outboxLifetime;
  source.setActive(true);
  assert.equal(deliveryOf(store, peer, attempt.id), "expired");
});

class RecordingHistory implements HistoryPort {
  readonly settled: { id: string; delivery: SettledDelivery; saved: boolean }[] =
    [];
  fail = false;

  has(): boolean {
    return false;
  }

  async received(): Promise<boolean> {
    return true;
  }

  async sent(): Promise<boolean> {
    return true;
  }

  async settle(
    _peer: string,
    id: string,
    delivery: SettledDelivery,
  ): Promise<boolean> {
    const saved = !(this.fail && delivery === "expired");
    this.settled.push({ id, delivery, saved });
    return saved;
  }

  read(): void {}

  expiries(id: string) {
    return this.settled.filter((s) => s.id === id && s.delivery === "expired");
  }
}

function settledTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

async function relaySession(
  t: TestContext,
  options: { history?: HistoryPort } = {},
) {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const [self, peer] = await identities(2);
  const source = new Source();
  const clock = { now: 1_000_000 };
  const store = new Conversations(source, self, {
    relay: true,
    now: () => clock.now,
    history: options.history,
  });
  store.start();
  store.open(peer);
  const advance = (ms: number) => {
    clock.now += ms;
    t.mock.timers.tick(ms);
  };
  const queue = async (body: string) => {
    const attempt = store.send(body);
    assert.ok(attempt.accepted);
    source.sent.at(-1)?.resolve({ ok: true, devices: 1, pending: 0 });
    assert.equal(await attempt.delivery, "queued");
    return attempt.id;
  };
  return { self, peer, source, clock, store, advance, queue };
}

test("an idle connected relay session expires a queued message at its deadline", async (t) => {
  const { peer, store, advance, queue } = await relaySession(t);
  const id = await queue("held by the relay");
  advance(outboxLifetime - 1);
  assert.equal(deliveryOf(store, peer, id), "queued");
  advance(1);
  assert.equal(deliveryOf(store, peer, id), "expired");
});

test("a receipt before the deadline is never overwritten by the expiry timer", async (t) => {
  const history = new RecordingHistory();
  const { peer, source, store, advance, queue } = await relaySession(t, {
    history,
  });
  const id = await queue("acknowledged in time");
  advance(outboxLifetime - 1);
  await source.receipt({ to: peer, device: DEVICE, id, status: "delivered" });
  advance(outboxLifetime * 2);
  assert.equal(deliveryOf(store, peer, id), "delivered");
  assert.deepEqual(history.expiries(id), []);
});

test("messages with different and shared deadlines each expire at their own deadline", async (t) => {
  const { peer, store, advance, queue } = await relaySession(t);
  const first = await queue("first");
  advance(1_000);
  const second = await queue("second");
  const shared = await queue("shared");
  advance(4_000);
  const last = await queue("last");
  const states = () =>
    [first, second, shared, last].map((id) => deliveryOf(store, peer, id));

  advance(outboxLifetime - 5_000);
  assert.deepEqual(states(), ["expired", "queued", "queued", "queued"]);
  advance(999);
  assert.deepEqual(states(), ["expired", "queued", "queued", "queued"]);
  advance(1);
  assert.deepEqual(states(), ["expired", "expired", "expired", "queued"]);
  advance(4_000);
  assert.deepEqual(states(), ["expired", "expired", "expired", "expired"]);
});

test("overdue restored messages expire at start and later deadlines still wait without repeated work", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const [self, peer] = await identities(2);
  const source = new Source();
  let now = 10_000_000;
  const sent = (id: string, sequence: number, accepted: number) => ({
    id,
    from: self,
    to: peer,
    sequence,
    direction: "sent" as const,
    body: id,
    delivery: "queued" as const,
    accepted,
  });
  const history = new RecordingHistory();
  const store = new Conversations(source, self, {
    relay: true,
    now: () => now,
    history,
    restored: [
      sent("overdue", 1, now - outboxLifetime - 5),
      sent("later", 2, now - outboxLifetime + 60_000),
    ],
  });
  let published = 0;
  store.onState(() => {
    published += 1;
  });
  store.start();
  assert.equal(deliveryOf(store, peer, "overdue"), "expired");
  assert.equal(deliveryOf(store, peer, "later"), "queued");
  await settledTurn();
  assert.equal(history.expiries("overdue").length, 1);

  const before = published;
  t.mock.timers.tick(0);
  t.mock.timers.tick(59_999);
  now += 59_999;
  assert.equal(published, before);
  assert.equal(deliveryOf(store, peer, "later"), "queued");
  now += 1;
  t.mock.timers.tick(1);
  assert.equal(deliveryOf(store, peer, "later"), "expired");
  await settledTurn();
  assert.equal(history.expiries("overdue").length, 1);
  assert.equal(history.expiries("later").length, 1);
});

test("a message evicted from the conversation is never expired by a stale timer", async (t) => {
  const history = new RecordingHistory();
  const { peer, source, store, advance, queue } = await relaySession(t, {
    history,
  });
  const id = await queue("pushed out of the window");
  for (let i = 0; i < maxMessages; i++) {
    assert.ok(
      await source.deliver({
        id: createMessageId(),
        from: peer,
        body: `incoming ${i}`,
      }),
    );
  }
  assert.ok(
    !conversation(store, peer)?.messages.some((m) => m.id === id),
    "the sent message left the window",
  );
  advance(outboxLifetime);
  await settledTurn();
  assert.deepEqual(history.expiries(id), []);
});

test("stopping the conversation store cancels its expiry timer", async (t) => {
  const history = new RecordingHistory();
  const { peer, store, advance, queue } = await relaySession(t, { history });
  const id = await queue("stopped before the deadline");
  store.stop();
  advance(outboxLifetime * 2);
  await settledTurn();
  assert.deepEqual(store.state.conversations, []);
  assert.deepEqual(history.expiries(id), []);
  assert.equal(conversation(store, peer), undefined);
});

test("an expiry that cannot be saved is retried on the next pass and not treated as saved", async (t) => {
  const history = new RecordingHistory();
  const { peer, source, store, advance, queue } = await relaySession(t, {
    history,
  });
  const id = await queue("expired while storage fails");
  history.fail = true;
  advance(outboxLifetime);
  await settledTurn();
  assert.equal(deliveryOf(store, peer, id), "expired");
  assert.deepEqual(history.expiries(id), [
    { id, delivery: "expired", saved: false },
  ]);

  advance(outboxLifetime * 10);
  await settledTurn();
  assert.equal(history.expiries(id).length, 1, "no timer retries a past deadline");

  history.fail = false;
  source.setActive(true);
  await settledTurn();
  assert.deepEqual(history.expiries(id).at(-1), {
    id,
    delivery: "expired",
    saved: true,
  });
  source.setActive(true);
  await settledTurn();
  assert.equal(history.expiries(id).length, 2, "a saved expiry is not rewritten");
});
