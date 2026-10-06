import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  type ConversationMessage,
  Conversations,
  type MessageSource,
  maxConversations,
  maxMessages,
} from "./conversations.ts";
import {
  History,
  historyVersion,
  maxRecordSize,
  maxStoredMessages,
  parseRecord,
} from "./history.ts";
import { Listeners } from "./listeners.ts";
import type {
  Incoming,
  MessengerState,
  SealedRecord,
  SendResult,
} from "./messenger.ts";
import { memoryStore } from "./testing.ts";
import { type Unlocked, loadVault } from "./vault.ts";

type Store = ReturnType<typeof memoryStore>;
type Party = Unlocked & { store: Store };

async function party(): Promise<Party> {
  const store = memoryStore();
  const state = await loadVault(store);
  assert.equal(state.status, "ready");
  return { ...(state as Unlocked), store };
}

async function reload(p: Party): Promise<Party> {
  const state = await loadVault(p.store);
  assert.equal(state.status, "ready");
  assert.equal((state as Unlocked).created, false);
  return { ...(state as Unlocked), store: p.store };
}

async function sealFor(
  from: Party,
  to: Party,
  id: string,
  body: string,
): Promise<{ toRecipient: SealedRecord; toSender: SealedRecord }> {
  const sealed = await from.keys.exchange.seal(
    {
      id,
      from: from.keys.identity.identity,
      to: to.keys.identity.identity,
      fromKey: from.keys.exchange.publicRaw,
      toKey: to.keys.exchange.publicRaw,
    },
    body,
  );
  const [fromBundle, toBundle] = await Promise.all([
    from.keys.exchange.bind(from.keys.identity),
    to.keys.exchange.bind(to.keys.identity),
  ]);
  assert.ok(sealed && fromBundle && toBundle);
  return {
    toRecipient: { sealed, peer: fromBundle },
    toSender: { sealed, peer: toBundle },
  };
}

async function open(p: Party): Promise<History> {
  return History.open(p.store, p.keys, p.integrity);
}

function records(store: Store): [string, Record<string, unknown>][] {
  return [...store.data.entries()]
    .filter(([key]) => key.startsWith("messages:"))
    .map(([key, value]) => [
      key.slice("messages:".length),
      value as Record<string, unknown>,
    ]);
}

function strings(value: unknown): string[] {
  if (typeof value === "string") {
    return [value];
  }
  if (typeof value === "object" && value !== null) {
    return Object.values(value).flatMap(strings);
  }
  return [];
}

function assertNoPlaintext(store: Store, secrets: string[]): void {
  const stored = [...store.data.entries()].flatMap(([key, value]) => [
    key,
    ...strings(value),
  ]);
  const serialized = JSON.stringify([...store.data.entries()]);
  for (const secret of secrets) {
    const bytes = new TextEncoder().encode(secret);
    for (const form of [
      secret,
      encodeBase64Url(bytes),
      Buffer.from(bytes).toString("base64"),
      Buffer.from(bytes).toString("hex"),
    ]) {
      assert.ok(!serialized.includes(form), `plaintext stored: ${form}`);
      assert.ok(!stored.some((s) => s.includes(form)));
    }
  }
}

function flip(text: string, index = 0): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 0x01;
  return encodeBase64Url(bytes);
}

async function history(a: Party, b: Party) {
  const h = await open(b);
  const secrets = ["first secret", "second secret", "reply secret"];
  const one = await sealFor(a, b, "m1", secrets[0]);
  const two = await sealFor(a, b, "m2", secrets[1]);
  const reply = await sealFor(b, a, "r1", secrets[2]);
  h.received({
    id: "m1",
    peer: a.keys.identity.identity,
    sequence: 2,
    read: true,
    record: one.toRecipient,
  });
  h.received({
    id: "m2",
    peer: a.keys.identity.identity,
    sequence: 4,
    read: false,
    record: two.toRecipient,
  });
  h.sent({
    id: "r1",
    peer: a.keys.identity.identity,
    sequence: 3,
    delivery: "delivered",
    record: reply.toSender,
  });
  await h.flush();
  return { h, secrets };
}

class Source implements MessageSource {
  state: MessengerState = { active: true };
  readonly states = new Listeners<MessengerState>();
  readonly messages = new Listeners<Incoming>();
  readonly pending: {
    id: string;
    resolve: (result: SendResult) => void;
  }[] = [];

  onState(listener: (state: MessengerState) => void) {
    return this.states.add(listener);
  }

  onMessage(listener: (message: Incoming) => void) {
    return this.messages.add(listener);
  }

  send(_to: string, _body: string, id: string): Promise<SendResult> {
    return new Promise((resolve) => this.pending.push({ id, resolve }));
  }
}

function summary(messages: readonly ConversationMessage[] | undefined) {
  return (messages ?? []).map((m) =>
    m.direction === "sent"
      ? `${m.id}:sent:${m.delivery}:${m.body}`
      : `${m.id}:received:${m.body}`,
  );
}

test("an empty database restores nothing", async () => {
  const b = await party();
  const h = await open(b);
  assert.deepEqual(await h.restore(), { restored: [], rejected: 0 });
  assert.equal(records(b.store).length, 0);
});

test("persists only ciphertext and restores it after a reload", async () => {
  const a = await party();
  const b = await party();
  const { secrets } = await history(a, b);

  assertNoPlaintext(b.store, secrets);
  for (const [key, record] of records(b.store)) {
    assert.equal(key, `${a.keys.identity.identity}/${record.id}`);
    assert.equal(record.v, historyVersion);
    assert.deepEqual(
      Object.keys(record).sort(),
      [
        "ciphertext",
        "direction",
        record.direction === "sent" ? "delivery" : "read",
        "id",
        "iv",
        "key",
        "mac",
        "peer",
        "salt",
        "sequence",
        "signature",
        "v",
      ].sort(),
    );
    assert.ok(!("body" in record));
  }

  const restoredB = await reload(b);
  const result = await (await open(restoredB)).restore();
  assert.equal(result.rejected, 0);
  assert.deepEqual(
    result.restored.map((m) => ({ ...m })),
    [
      {
        id: "m1",
        from: a.keys.identity.identity,
        to: b.keys.identity.identity,
        sequence: 2,
        direction: "received",
        body: secrets[0],
        read: true,
      },
      {
        id: "r1",
        from: b.keys.identity.identity,
        to: a.keys.identity.identity,
        sequence: 3,
        direction: "sent",
        body: secrets[2],
        delivery: "delivered",
      },
      {
        id: "m2",
        from: a.keys.identity.identity,
        to: b.keys.identity.identity,
        sequence: 4,
        direction: "received",
        body: secrets[1],
        read: false,
      },
    ],
  );
});

test("records are useless without the matching keys", async () => {
  const a = await party();
  const b = await party();
  const intruder = await party();
  await history(a, b);

  const foreignKeys = await History.open(b.store, intruder.keys, b.integrity);
  assert.deepEqual(await foreignKeys.restore(), { restored: [], rejected: 3 });
  const foreignIntegrity = await History.open(
    b.store,
    b.keys,
    intruder.integrity,
  );
  assert.deepEqual(await foreignIntegrity.restore(), {
    restored: [],
    rejected: 3,
  });
  assert.equal(records(b.store).length, 3);
});

test("rejects each corrupted record while preserving unrelated ones", async () => {
  const a = await party();
  const b = await party();
  const c = await party();
  await history(a, b);
  const h = await open(b);
  const fromC = await sealFor(c, b, "c1", "unrelated");
  h.received({
    id: "c1",
    peer: c.keys.identity.identity,
    sequence: 5,
    read: true,
    record: fromC.toRecipient,
  });
  await h.flush();

  const peerA = a.keys.identity.identity;
  const target = `${peerA}/m1`;
  const original = b.store.data.get(`messages:${target}`) as Record<
    string,
    unknown
  >;
  const bundleC = await c.keys.exchange.bind(c.keys.identity);
  assert.ok(bundleC);
  const { mac: _mac, ...withoutMac } = original;
  const { iv: _iv, ...withoutIv } = original;
  const mutations: Record<string, unknown> = {
    ciphertext: {
      ...original,
      ciphertext: flip(original.ciphertext as string),
    },
    "truncated ciphertext": {
      ...original,
      ciphertext: (original.ciphertext as string).slice(0, -4),
    },
    nonce: { ...original, iv: flip(original.iv as string) },
    salt: { ...original, salt: flip(original.salt as string) },
    "sender identity": { ...original, peer: c.keys.identity.identity },
    "sender public key": { ...original, key: bundleC.key },
    "key binding": { ...original, signature: bundleC.signature },
    "substituted bundle": {
      ...original,
      key: bundleC.key,
      signature: bundleC.signature,
    },
    "message id": { ...original, id: "m9" },
    direction: { ...original, direction: "sent", delivery: "delivered" },
    "read state": { ...original, read: false },
    sequence: { ...original, sequence: 99 },
    "negative sequence": { ...original, sequence: -1 },
    "future version": { ...original, v: historyVersion + 1 },
    "string version": { ...original, v: "1" },
    "missing mac": withoutMac,
    "missing nonce": withoutIv,
    "unexpected field": { ...original, body: "injected" },
    "mac flipped": { ...original, mac: flip(original.mac as string) },
    "non-object": "record",
    null: null,
    array: [original],
    oversized: {
      ...original,
      ciphertext: "A".repeat(maxRecordSize),
    },
  };
  for (const [name, mutated] of Object.entries(mutations)) {
    b.store.data.set(`messages:${target}`, mutated);
    const restoredB = await reload(b);
    const result = await (await open(restoredB)).restore();
    assert.equal(result.rejected, 1, name);
    assert.deepEqual(
      result.restored.map((m) => m.id).sort(),
      ["c1", "m2", "r1"],
      name,
    );
    assert.equal(b.store.data.get(`messages:${target}`), mutated, name);
  }

  b.store.data.set(`messages:${target}`, original);
  const forged = { ...original, id: "m9" };
  b.store.data.set(`messages:${peerA}/m9`, forged);
  const result = await (await open(await reload(b))).restore();
  assert.equal(result.rejected, 1);
  assert.deepEqual(result.restored.map((m) => m.id).sort(), [
    "c1",
    "m1",
    "m2",
    "r1",
  ]);

  const deliveryTarget = `${peerA}/r1`;
  const sent = b.store.data.get(`messages:${deliveryTarget}`) as Record<
    string,
    unknown
  >;
  for (const delivery of ["failed", "unavailable", "sending", "read", "seen"]) {
    b.store.data.set(`messages:${deliveryTarget}`, { ...sent, delivery });
    const check = await (await open(await reload(b))).restore();
    assert.ok(!check.restored.some((m) => m.id === "r1"), delivery);
  }
});

test("a corrupted record is reported but never displayed as valid", async () => {
  const a = await party();
  const b = await party();
  await history(a, b);
  const key = `messages:${a.keys.identity.identity}/m2`;
  const record = b.store.data.get(key) as Record<string, unknown>;
  b.store.data.set(key, { ...record, sequence: 1 });

  const result = await (await open(await reload(b))).restore();
  const store = new Conversations(new Source(), b.keys.identity.identity, {
    restored: result.restored,
  });
  store.start();
  assert.equal(result.rejected, 1);
  assert.deepEqual(summary(store.state.conversations[0]?.messages), [
    "m1:received:first secret",
    "r1:sent:delivered:reply secret",
  ]);
});

test("restores conversations, ordering, unread, and delivery state", async () => {
  const a = await party();
  const b = await party();
  const c = await party();
  const first = await open(b);
  const source = new Source();
  const store = new Conversations(source, b.keys.identity.identity, {
    history: first,
  });
  store.start();
  const peerA = a.keys.identity.identity;
  const peerC = c.keys.identity.identity;

  const deliver = async (from: Party, id: string, body: string) => {
    const { toRecipient } = await sealFor(from, b, id, body);
    source.messages.emit({
      id,
      from: from.keys.identity.identity,
      body,
      record: toRecipient,
    });
  };
  await deliver(a, "a1", "from a one");
  await deliver(c, "c1", "from c one");
  store.open(peerA);
  await deliver(a, "a2", "from a two while active");
  const outcomes: SendResult[] = [];
  for (const [body, reason] of [
    ["to a delivered", null],
    ["to a unavailable", "recipient_unavailable"],
    ["to a failed", "internal_error"],
  ] as const) {
    const attempt = store.send(body);
    assert.equal(attempt.accepted, true);
    const pending = source.pending.at(-1);
    assert.ok(pending);
    const { toSender } = await sealFor(b, a, pending.id, body);
    const result: SendResult = reason
      ? { ok: false, reason, record: toSender }
      : { ok: true, record: toSender };
    outcomes.push(result);
    pending.resolve(result);
    if (attempt.accepted) {
      await attempt.delivery;
    }
  }
  const pendingAttempt = store.send("still sending at reload");
  assert.equal(pendingAttempt.accepted, true);
  await deliver(c, "c2", "from c two");
  await first.flush();

  const before = store.state;
  assertNoPlaintext(b.store, [
    "from a one",
    "from c one",
    "from a two while active",
    "to a delivered",
    "to a unavailable",
    "to a failed",
    "still sending at reload",
    "from c two",
  ]);
  store.stop();
  await first.close();

  const restoredB = await reload(b);
  const second = await open(restoredB);
  const { restored, rejected } = await second.restore();
  assert.equal(rejected, 0);
  const after = new Conversations(new Source(), b.keys.identity.identity, {
    history: second,
    restored,
  });
  after.start();

  assert.equal(after.state.active, null);
  assert.deepEqual(
    after.state.conversations.map((x) => [x.identity, x.unread]),
    [
      [peerC, 2],
      [peerA, 0],
    ],
  );
  const conversationA = after.state.conversations.find(
    (x) => x.identity === peerA,
  );
  assert.deepEqual(
    summary(conversationA?.messages).map((s) =>
      s.split(":").slice(1).join(":"),
    ),
    [
      "received:from a one",
      "received:from a two while active",
      "sent:delivered:to a delivered",
      "sent:unavailable:to a unavailable",
      "sent:failed:to a failed",
    ],
  );
  assert.deepEqual(
    before.conversations
      .find((x) => x.identity === peerA)
      ?.messages.filter((m) => m.direction === "sent")
      .map((m) => m.direction === "sent" && m.delivery),
    ["delivered", "unavailable", "failed", "sending"],
  );
  assert.ok(
    !after.state.conversations.some((x) =>
      x.messages.some((m) => m.body === "still sending at reload"),
    ),
  );

  after.open(peerC);
  await second.flush();
  after.stop();
  const third = await (await open(await reload(b))).restore();
  const reopened = new Conversations(new Source(), b.keys.identity.identity, {
    restored: third.restored,
  });
  reopened.start();
  assert.deepEqual(
    reopened.state.conversations.map((x) => [x.identity, x.unread]),
    [
      [peerC, 0],
      [peerA, 0],
    ],
  );
  assert.equal(third.rejected, 0);
  assert.equal(outcomes.length, 3);
});

test("live duplicates of restored messages are ignored", async () => {
  const a = await party();
  const b = await party();
  await history(a, b);
  const { restored } = await (await open(await reload(b))).restore();
  const source = new Source();
  const h = await open(b);
  const store = new Conversations(source, b.keys.identity.identity, {
    history: h,
    restored: [...restored, ...restored],
  });
  store.start();
  const writes = b.store.writes;

  const replay = await sealFor(a, b, "m1", "first secret");
  source.messages.emit({
    id: "m1",
    from: a.keys.identity.identity,
    body: "first secret",
    record: replay.toRecipient,
  });
  await h.flush();
  assert.equal(b.store.writes, writes);
  assert.deepEqual(summary(store.state.conversations[0].messages), [
    "m1:received:first secret",
    "r1:sent:delivered:reply secret",
    "m2:received:second secret",
  ]);
  assert.equal(store.state.conversations[0].unread, 1);

  const fresh = await sealFor(a, b, "m3", "third secret");
  source.messages.emit({
    id: "m3",
    from: a.keys.identity.identity,
    body: "third secret",
    record: fresh.toRecipient,
  });
  await h.flush();
  const next = await (await open(await reload(b))).restore();
  assert.deepEqual(
    next.restored.map((m) => [m.id, m.sequence]),
    [
      ["m1", 2],
      ["r1", 3],
      ["m2", 4],
      ["m3", 5],
    ],
  );
});

test("undecryptable live messages are never persisted", async () => {
  const a = await party();
  const b = await party();
  const source = new Source();
  const h = await open(b);
  const store = new Conversations(source, b.keys.identity.identity, {
    history: h,
  });
  store.start();
  source.messages.emit({
    id: "x1",
    from: a.keys.identity.identity,
    body: null,
  });
  await h.flush();
  assert.equal(records(b.store).length, 0);
  assert.equal(store.state.conversations[0].messages[0].body, null);
});

test("bounds stored messages per conversation, conversations, and total", async () => {
  const a = await party();
  const b = await party();
  const h = await open(b);
  const { toRecipient } = await sealFor(a, b, "seed", "seed");
  const peers = await Promise.all(
    Array.from({ length: maxConversations + 5 }, () => party()),
  );
  let sequence = 0;

  for (let i = 0; i < maxMessages + 10; i++) {
    h.received({
      id: `a${i}`,
      peer: a.keys.identity.identity,
      sequence: ++sequence,
      read: true,
      record: toRecipient,
    });
  }
  await h.flush();
  const kept = records(b.store).map(([key]) => key.split("/")[1]);
  assert.equal(kept.length, maxMessages);
  assert.ok(!kept.includes("a9") && kept.includes("a10"));
  assert.ok(kept.includes(`a${maxMessages + 9}`));

  for (const [i, p] of peers.entries()) {
    h.received({
      id: `p${i}`,
      peer: p.keys.identity.identity,
      sequence: ++sequence,
      read: true,
      record: toRecipient,
    });
  }
  await h.flush();
  const owners = new Set(records(b.store).map(([, r]) => r.peer));
  assert.equal(owners.size, maxConversations);
  assert.ok(!owners.has(a.keys.identity.identity));
  for (const p of peers.slice(0, 5)) {
    assert.ok(!owners.has(p.keys.identity.identity));
  }
  for (const p of peers.slice(5)) {
    assert.ok(owners.has(p.keys.identity.identity));
  }

  const busy = peers.slice(-30);
  for (let round = 0; round < maxMessages; round++) {
    for (const p of busy) {
      h.received({
        id: `b${round}`,
        peer: p.keys.identity.identity,
        sequence: ++sequence,
        read: true,
        record: toRecipient,
      });
    }
  }
  await h.flush();
  const all = records(b.store);
  assert.equal(all.length, maxStoredMessages);
  const sequences = all.map(([, r]) => r.sequence as number);
  assert.equal(Math.min(...sequences), sequence - maxStoredMessages + 1);
  assert.equal(Math.max(...sequences), sequence);
  for (const [, record] of all) {
    assert.ok(JSON.stringify(record).length <= maxRecordSize);
  }
});

test("refuses to store a record larger than the limit", async () => {
  const a = await party();
  const b = await party();
  const h = await open(b);
  const { toRecipient } = await sealFor(a, b, "m1", "x");
  h.received({
    id: "m1",
    peer: a.keys.identity.identity,
    sequence: 1,
    read: true,
    record: {
      ...toRecipient,
      sealed: { ...toRecipient.sealed, ciphertext: "A".repeat(maxRecordSize) },
    },
  });
  h.received({
    id: "bad id with spaces",
    peer: a.keys.identity.identity,
    sequence: 2,
    read: true,
    record: toRecipient,
  });
  await h.flush();
  assert.equal(records(b.store).length, 0);
});

test("concurrent writes and reads stay consistent", async () => {
  const a = await party();
  const b = await party();
  const h = await open(b);
  const sealed = await Promise.all(
    Array.from({ length: 40 }, (_, i) => sealFor(a, b, `m${i}`, `body ${i}`)),
  );
  sealed.forEach(({ toRecipient }, i) => {
    h.received({
      id: `m${i}`,
      peer: a.keys.identity.identity,
      sequence: i + 1,
      read: false,
      record: toRecipient,
    });
    if (i % 7 === 0) {
      h.read(a.keys.identity.identity);
    }
  });
  const [restoredDuring] = await Promise.all([
    (async () => (await open(await reload(b))).restore())(),
    h.flush(),
  ]);
  assert.equal(restoredDuring.rejected, 0);
  h.read(a.keys.identity.identity);
  await h.flush();

  const result = await (await open(await reload(b))).restore();
  assert.equal(result.rejected, 0);
  assert.deepEqual(
    result.restored.map((m) => m.body),
    sealed.map((_, i) => `body ${i}`),
  );
  assert.ok(result.restored.every((m) => "read" in m && m.read === true));
});

test("marking read applies to writes still in flight", async () => {
  const a = await party();
  const b = await party();
  const h = await open(b);
  const sealed = await Promise.all(
    ["m1", "m2", "m3"].map((id) => sealFor(a, b, id, id)),
  );
  sealed.forEach(({ toRecipient }, i) =>
    h.received({
      id: `m${i + 1}`,
      peer: a.keys.identity.identity,
      sequence: i + 1,
      read: false,
      record: toRecipient,
    }),
  );
  h.read(a.keys.identity.identity);
  await h.flush();

  const { restored } = await (await open(await reload(b))).restore();
  assert.deepEqual(
    restored.map((m) => [m.id, "read" in m && m.read]),
    [
      ["m1", true],
      ["m2", true],
      ["m3", true],
    ],
  );
});

test("close finishes queued writes and discards later ones", async () => {
  const a = await party();
  const b = await party();
  const h = await open(b);
  const queued = await sealFor(a, b, "m1", "queued");
  const late = await sealFor(a, b, "m2", "late");
  h.received({
    id: "m1",
    peer: a.keys.identity.identity,
    sequence: 1,
    read: false,
    record: queued.toRecipient,
  });
  const closed = h.close();
  h.received({
    id: "m2",
    peer: a.keys.identity.identity,
    sequence: 2,
    read: false,
    record: late.toRecipient,
  });
  h.read(a.keys.identity.identity);
  await closed;
  await h.flush();
  assert.deepEqual(
    records(b.store).map(([, r]) => [r.id, r.read]),
    [["m1", false]],
  );
});

test("results that settle after the store stops are not persisted", async () => {
  const a = await party();
  const b = await party();
  const h = await open(b);
  const source = new Source();
  const store = new Conversations(source, b.keys.identity.identity, {
    history: h,
  });
  store.start();
  store.open(a.keys.identity.identity);
  const attempt = store.send("settles late");
  assert.equal(attempt.accepted, true);
  const pending = source.pending[0];
  const { toSender } = await sealFor(b, a, pending.id, "settles late");
  store.stop();
  pending.resolve({ ok: true, record: toSender });
  if (attempt.accepted) {
    await attempt.delivery;
  }
  await h.flush();
  assert.equal(records(b.store).length, 0);
});

test("restore re-verifies key bindings even for authentic records", async () => {
  const a = await party();
  const b = await party();
  const h = await open(b);
  const { toRecipient } = await sealFor(a, b, "m1", "unbound");
  h.received({
    id: "m1",
    peer: a.keys.identity.identity,
    sequence: 1,
    read: true,
    record: {
      ...toRecipient,
      peer: {
        ...toRecipient.peer,
        signature: flip(toRecipient.peer.signature),
      },
    },
  });
  await h.flush();
  assert.equal(records(b.store).length, 1);
  assert.deepEqual(await (await open(await reload(b))).restore(), {
    restored: [],
    rejected: 1,
  });
});

test("the record decoder enforces the schema independently of the MAC", async () => {
  const a = await party();
  const b = await party();
  await history(a, b);
  const peer = a.keys.identity.identity;
  const key = `${peer}/m1`;
  const received = b.store.data.get(`messages:${key}`) as Record<
    string,
    unknown
  >;
  const sentKey = `${peer}/r1`;
  const sent = b.store.data.get(`messages:${sentKey}`) as Record<
    string,
    unknown
  >;
  assert.deepEqual(parseRecord(key, received), received);
  assert.deepEqual(parseRecord(sentKey, sent), sent);

  const without = (record: Record<string, unknown>, name: string) => {
    const copy = { ...record };
    delete copy[name];
    return copy;
  };
  const cases: [string, string, unknown][] = [
    ["version 2", key, { ...received, v: historyVersion + 1 }],
    ["version 0", key, { ...received, v: 0 }],
    ["version string", key, { ...received, v: "1" }],
    ["moved record", `${peer}/m2`, received],
    ["other peer key", `${b.keys.identity.identity}/m1`, received],
    ["invalid id", `${peer}/bad id`, { ...received, id: "bad id" }],
    ["empty id", `${peer}/`, { ...received, id: "" }],
    ["invalid peer", "x/m1", { ...received, peer: "x" }],
    ["sequence zero", key, { ...received, sequence: 0 }],
    ["sequence negative", key, { ...received, sequence: -1 }],
    ["sequence fraction", key, { ...received, sequence: 1.5 }],
    ["sequence string", key, { ...received, sequence: "2" }],
    [
      "sequence unsafe",
      key,
      { ...received, sequence: Number.MAX_SAFE_INTEGER + 2 },
    ],
    ["direction", key, { ...received, direction: "outgoing" }],
    ["read string", key, { ...received, read: "true" }],
    ["read number", key, { ...received, read: 1 }],
    ["delivery sending", sentKey, { ...sent, delivery: "sending" }],
    ["delivery read", sentKey, { ...sent, delivery: "read" }],
    ["delivery seen", sentKey, { ...sent, delivery: "seen" }],
    ["delivery empty", sentKey, { ...sent, delivery: "" }],
    ["sent with read", sentKey, { ...without(sent, "delivery"), read: true }],
    [
      "received with delivery",
      key,
      {
        ...without(received, "read"),
        delivery: "delivered",
      },
    ],
    ["short key", key, { ...received, key: "AAAA" }],
    ["short signature", key, { ...received, signature: "AAAA" }],
    ["short salt", key, { ...received, salt: "AAAA" }],
    ["long iv", key, { ...received, iv: `${received.iv}AA` }],
    ["padded iv", key, { ...received, iv: `${received.iv}=` }],
    ["numeric ciphertext", key, { ...received, ciphertext: 7 }],
    ["short mac", key, { ...received, mac: "AAAA" }],
    ["unexpected body", key, { ...received, body: "plaintext" }],
    ["oversized", key, { ...received, ciphertext: "A".repeat(maxRecordSize) }],
    ["array", key, [received]],
    ["null", key, null],
    ["string", key, JSON.stringify(received)],
    ...Object.keys(received).map((name): [string, string, unknown] => [
      `missing ${name}`,
      key,
      without(received, name),
    ]),
  ];
  for (const [name, at, value] of cases) {
    assert.equal(parseRecord(at, value), null, name);
  }
});

test("reset removes identity, keys, and history", async () => {
  const a = await party();
  const b = await party();
  await history(a, b);
  const old = b.keys.identity.identity;

  await b.store.clear();
  assert.equal(b.store.data.size, 0);
  const state = await loadVault(b.store);
  assert.equal(state.status, "ready");
  const fresh = state as Unlocked;
  assert.equal(fresh.created, true);
  assert.notEqual(fresh.keys.identity.identity, old);
  const h = await History.open(b.store, fresh.keys, fresh.integrity);
  assert.deepEqual(await h.restore(), { restored: [], rejected: 0 });
});

test("fuzzed persisted records never restore as trusted state", async () => {
  const a = await party();
  const b = await party();
  await history(a, b);
  const key = `${a.keys.identity.identity}/m1`;
  const original = b.store.data.get(`messages:${key}`) as Record<
    string,
    unknown
  >;
  const names = Object.keys(original);
  const values: unknown[] = [
    null,
    undefined,
    0,
    -1,
    1.5,
    Number.MAX_SAFE_INTEGER + 2,
    "",
    "A",
    "=",
    "💥",
    "\u0000",
    true,
    false,
    [],
    {},
    { v: 1 },
    "A".repeat(43),
    "A".repeat(86),
  ];
  let seed = 0x9e3779b9;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 1500);
  let accepted = 0;
  for (let i = 0; i < iterations; i++) {
    const mutated: Record<string, unknown> = { ...original };
    const steps = 1 + random(3);
    for (let s = 0; s < steps; s++) {
      const name = names[random(names.length)];
      const choice = random(5);
      if (choice === 0) {
        delete mutated[name];
      } else if (choice === 1) {
        mutated[name] = values[random(values.length)];
      } else if (choice === 2 && typeof mutated[name] === "string") {
        const text = mutated[name] as string;
        const at = random(Math.max(1, text.length));
        const chars =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/=";
        mutated[name] =
          text.slice(0, at) + chars[random(chars.length)] + text.slice(at + 1);
      } else if (choice === 3) {
        mutated[`x${random(4)}`] = values[random(values.length)];
      } else {
        mutated[name] = original[names[random(names.length)]];
      }
    }
    b.store.data.set(`messages:${key}`, mutated);
    const h = await History.open(b.store, b.keys, b.integrity);
    const { restored } = await h.restore();
    const m1 = restored.find((m) => m.id === "m1");
    if (m1) {
      accepted += 1;
      assert.deepEqual(mutated, original);
      assert.equal(m1.body, "first secret");
    }
    assert.ok(restored.some((m) => m.id === "m2"));
  }
  assert.ok(accepted < iterations);
});
