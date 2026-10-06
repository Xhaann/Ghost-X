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
  legacyVersion,
  maxRecordSize,
  maxStoredMessages,
  parseLegacyRecord,
  parseRecord,
} from "./history.ts";
import { Listeners } from "./listeners.ts";
import type { Incoming, MessengerState, SendResult } from "./messenger.ts";
import { maxBodySize } from "./protocol.ts";
import {
  type LegacyParty,
  legacyParty,
  legacySeal,
  memoryStore,
} from "./testing.ts";
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

function open(p: Party, store: Store = p.store): Promise<History> {
  return History.open(store, p.keys, p.integrity, p.storage);
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
  for (const secret of secrets) {
    const bytes = new TextEncoder().encode(secret);
    for (const form of [
      secret,
      encodeBase64Url(bytes),
      Buffer.from(bytes).toString("base64"),
      Buffer.from(bytes).toString("hex"),
    ]) {
      assert.ok(
        !stored.some((s) => s.includes(form)),
        `plaintext stored: ${form}`,
      );
    }
  }
}

function flip(text: string, index = 0): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 0x01;
  return encodeBase64Url(bytes);
}

async function history(a: string, b: Party) {
  const h = await open(b);
  const secrets = ["first secret", "second secret", "reply secret"];
  h.received({ id: "m1", peer: a, sequence: 2, read: true, body: secrets[0] });
  h.received({ id: "m2", peer: a, sequence: 4, read: false, body: secrets[1] });
  h.sent({
    id: "r1",
    peer: a,
    sequence: 3,
    delivery: "delivered",
    body: secrets[2],
  });
  await h.flush();
  return { h, secrets };
}

async function identity(): Promise<string> {
  return (await party()).keys.identity.identity;
}

class Source implements MessageSource {
  state: MessengerState = { active: true };
  readonly states = new Listeners<MessengerState>();
  readonly messages = new Listeners<Incoming>();
  readonly pending: { id: string; resolve: (result: SendResult) => void }[] =
    [];

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

const legacyContext = "ghostx/history/v1\0";

async function legacyRecord(
  owner: Party,
  peer: LegacyParty,
  fields: {
    id: string;
    sequence: number;
    direction: "sent" | "received";
    state: string | boolean;
    body: string;
  },
): Promise<[string, Record<string, unknown>]> {
  const self = owner.keys.identity.identity;
  const sent = fields.direction === "sent";
  const parties = {
    id: fields.id,
    from: sent ? self : peer.identity.identity,
    to: sent ? peer.identity.identity : self,
    fromKey: sent ? owner.keys.exchange.publicRaw : peer.publicRaw,
    toKey: sent ? peer.publicRaw : owner.keys.exchange.publicRaw,
  };
  const sealed = await legacySeal(
    parties,
    peer.privateKey,
    owner.keys.exchange.publicRaw,
    fields.body,
  );
  const record: Record<string, unknown> = {
    v: legacyVersion,
    id: fields.id,
    peer: peer.identity.identity,
    direction: fields.direction,
    [sent ? "delivery" : "read"]: fields.state,
    sequence: fields.sequence,
    key: peer.bundle.key,
    signature: peer.bundle.signature,
    ...sealed,
  };
  const order = [
    "v",
    "id",
    "peer",
    "direction",
    sent ? "delivery" : "read",
    "sequence",
    "key",
    "signature",
    "salt",
    "iv",
    "ciphertext",
  ];
  const mac = await crypto.subtle.sign(
    "HMAC",
    owner.integrity,
    new TextEncoder().encode(
      legacyContext + JSON.stringify(order.map((name) => record[name])),
    ),
  );
  record.mac = encodeBase64Url(new Uint8Array(mac));
  return [`${peer.identity.identity}/${fields.id}`, record];
}

test("an empty database restores nothing", async () => {
  const b = await party();
  const h = await open(b);
  assert.deepEqual(await h.restore(), { restored: [], rejected: 0 });
  assert.equal(h.migrated, 0);
  assert.equal(records(b.store).length, 0);
});

test("persists only locally encrypted bodies and restores them after a reload", async () => {
  const a = await identity();
  const b = await party();
  const { secrets } = await history(a, b);

  assertNoPlaintext(b.store, secrets);
  for (const [key, record] of records(b.store)) {
    assert.equal(key, `${a}/${record.id}`);
    assert.equal(record.v, historyVersion);
    assert.deepEqual(
      Object.keys(record).sort(),
      [
        "ciphertext",
        "direction",
        record.direction === "sent" ? "delivery" : "read",
        "id",
        "iv",
        "peer",
        "sequence",
        "v",
      ].sort(),
    );
  }
  const ivs = records(b.store).map(([, r]) => r.iv);
  assert.equal(new Set(ivs).size, ivs.length);

  const restoredB = await reload(b);
  const result = await (await open(restoredB)).restore();
  assert.equal(result.rejected, 0);
  assert.deepEqual(
    result.restored.map((m) => ({ ...m })),
    [
      {
        id: "m1",
        from: a,
        to: b.keys.identity.identity,
        sequence: 2,
        direction: "received",
        body: secrets[0],
        read: true,
      },
      {
        id: "r1",
        from: b.keys.identity.identity,
        to: a,
        sequence: 3,
        direction: "sent",
        body: secrets[2],
        delivery: "delivered",
      },
      {
        id: "m2",
        from: a,
        to: b.keys.identity.identity,
        sequence: 4,
        direction: "received",
        body: secrets[1],
        read: false,
      },
    ],
  );
});

test("records are unreadable without the matching storage key", async () => {
  const a = await identity();
  const b = await party();
  const intruder = await party();
  await history(a, b);
  const foreign = await History.open(
    b.store,
    b.keys,
    b.integrity,
    intruder.storage,
  );
  assert.deepEqual(await foreign.restore(), { restored: [], rejected: 3 });
  assert.equal(records(b.store).length, 3);
});

test("rejects each corrupted record while preserving unrelated ones", async () => {
  const a = await identity();
  const c = await identity();
  const b = await party();
  await history(a, b);
  const h = await open(b);
  h.received({ id: "c1", peer: c, sequence: 5, read: true, body: "unrelated" });
  await h.flush();

  const target = `${a}/m1`;
  const original = b.store.data.get(`messages:${target}`) as Record<
    string,
    unknown
  >;
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
    "peer identity": { ...original, peer: c },
    "message id": { ...original, id: "m9" },
    direction: { ...original, direction: "sent", delivery: "delivered" },
    "read state": { ...original, read: false },
    sequence: { ...original, sequence: 99 },
    "negative sequence": { ...original, sequence: -1 },
    "future version": { ...original, v: historyVersion + 1 },
    "string version": { ...original, v: "2" },
    "missing nonce": withoutIv,
    "unexpected body": { ...original, body: "injected" },
    "legacy mac field": { ...original, mac: "x" },
    "non-object": "record",
    null: null,
    array: [original],
    oversized: { ...original, ciphertext: "A".repeat(maxRecordSize) },
  };
  for (const [name, mutated] of Object.entries(mutations)) {
    b.store.data.set(`messages:${target}`, mutated);
    const result = await (await open(await reload(b))).restore();
    assert.equal(result.rejected, 1, name);
    assert.deepEqual(
      result.restored.map((m) => m.id).sort(),
      ["c1", "m2", "r1"],
      name,
    );
    assert.equal(b.store.data.get(`messages:${target}`), mutated, name);
  }

  b.store.data.set(`messages:${target}`, original);
  b.store.data.set(`messages:${a}/m9`, { ...original, id: "m9" });
  const moved = await (await open(await reload(b))).restore();
  assert.equal(moved.rejected, 1);
  assert.deepEqual(moved.restored.map((m) => m.id).sort(), [
    "c1",
    "m1",
    "m2",
    "r1",
  ]);

  const sentKey = `messages:${a}/r1`;
  const sent = b.store.data.get(sentKey) as Record<string, unknown>;
  for (const delivery of ["failed", "unavailable", "sending", "read", "seen"]) {
    b.store.data.set(sentKey, { ...sent, delivery });
    const check = await (await open(await reload(b))).restore();
    assert.ok(!check.restored.some((m) => m.id === "r1"), delivery);
  }
});

test("a corrupted record is reported but never displayed as valid", async () => {
  const a = await identity();
  const b = await party();
  await history(a, b);
  const key = `messages:${a}/m2`;
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

test("restores conversations, ordering, unread, and settled delivery state", async () => {
  const peerA = await identity();
  const peerC = await identity();
  const b = await party();
  const first = await open(b);
  const source = new Source();
  const store = new Conversations(source, b.keys.identity.identity, {
    history: first,
  });
  store.start();

  const deliver = (from: string, id: string, body: string) =>
    source.messages.emit({ id, from, body });
  deliver(peerA, "a1", "from a one");
  deliver(peerC, "c1", "from c one");
  store.open(peerA);
  deliver(peerA, "a2", "from a two while active");
  for (const [body, result] of [
    ["to a delivered", { ok: true }],
    ["to a unavailable", { ok: false, reason: "recipient_unavailable" }],
    ["to a failed", { ok: false, reason: "internal_error" }],
  ] as [string, SendResult][]) {
    const attempt = store.send(body);
    assert.equal(attempt.accepted, true);
    source.pending.at(-1)?.resolve(result);
    if (attempt.accepted) {
      await attempt.delivery;
    }
  }
  assert.equal(store.send("still sending at reload").accepted, true);
  deliver(peerC, "c2", "from c two");
  await first.flush();
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

  const second = await open(await reload(b));
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
  assert.deepEqual(
    summary(
      after.state.conversations.find((x) => x.identity === peerA)?.messages,
    ).map((s) => s.split(":").slice(1).join(":")),
    [
      "received:from a one",
      "received:from a two while active",
      "sent:delivered:to a delivered",
      "sent:unavailable:to a unavailable",
      "sent:failed:to a failed",
    ],
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
});

test("live duplicates of restored messages are ignored", async () => {
  const a = await identity();
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
  source.messages.emit({ id: "m1", from: a, body: "first secret" });
  await h.flush();
  assert.equal(b.store.writes, writes);
  assert.deepEqual(summary(store.state.conversations[0].messages), [
    "m1:received:first secret",
    "r1:sent:delivered:reply secret",
    "m2:received:second secret",
  ]);
  source.messages.emit({ id: "m3", from: a, body: "third secret" });
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
  const a = await identity();
  const b = await party();
  const source = new Source();
  const h = await open(b);
  const store = new Conversations(source, b.keys.identity.identity, {
    history: h,
  });
  store.start();
  source.messages.emit({ id: "x1", from: a, body: null });
  await h.flush();
  assert.equal(records(b.store).length, 0);
  assert.equal(store.state.conversations[0].messages[0].body, null);
});

test("bounds stored messages per conversation, conversations, and total", async () => {
  const b = await party();
  const h = await open(b);
  const a = await identity();
  const peers = await Promise.all(
    Array.from({ length: maxConversations + 5 }, identity),
  );
  let sequence = 0;
  for (let i = 0; i < maxMessages + 10; i++) {
    h.received({
      id: `a${i}`,
      peer: a,
      sequence: ++sequence,
      read: true,
      body: "x",
    });
  }
  await h.flush();
  const kept = records(b.store).map(([key]) => key.split("/")[1]);
  assert.equal(kept.length, maxMessages);
  assert.ok(!kept.includes("a9") && kept.includes("a10"));

  for (const [i, p] of peers.entries()) {
    h.received({
      id: `p${i}`,
      peer: p,
      sequence: ++sequence,
      read: true,
      body: "x",
    });
  }
  await h.flush();
  const owners = new Set(records(b.store).map(([, r]) => r.peer));
  assert.equal(owners.size, maxConversations);
  assert.ok(!owners.has(a));
  for (const p of peers.slice(0, 5)) {
    assert.ok(!owners.has(p));
  }

  const busy = peers.slice(-30);
  for (let round = 0; round < maxMessages; round++) {
    for (const p of busy) {
      h.received({
        id: `b${round}`,
        peer: p,
        sequence: ++sequence,
        read: true,
        body: "x",
      });
    }
  }
  await h.flush();
  const all = records(b.store);
  assert.equal(all.length, maxStoredMessages);
  const sequences = all.map(([, r]) => r.sequence as number);
  assert.equal(Math.min(...sequences), sequence - maxStoredMessages + 1);
  assert.equal(Math.max(...sequences), sequence);
});

test("refuses invalid bodies and identifiers and fits the largest body", async () => {
  const a = await identity();
  const b = await party();
  const h = await open(b);
  h.received({
    id: "big",
    peer: a,
    sequence: 1,
    read: true,
    body: "a".repeat(maxBodySize),
  });
  h.received({
    id: "huge",
    peer: a,
    sequence: 2,
    read: true,
    body: "a".repeat(maxBodySize + 1),
  });
  h.received({ id: "empty", peer: a, sequence: 3, read: true, body: "" });
  h.received({ id: "ctrl", peer: a, sequence: 4, read: true, body: "a\u0000" });
  h.received({ id: "bad id", peer: a, sequence: 5, read: true, body: "x" });
  h.received({ id: "nopeer", peer: "x", sequence: 6, read: true, body: "x" });
  await h.flush();
  assert.deepEqual(
    records(b.store).map(([key]) => key),
    [`${a}/big`],
  );
  assert.ok(JSON.stringify(records(b.store)[0][1]).length <= maxRecordSize);
});

test("concurrent writes and reads stay consistent", async () => {
  const a = await identity();
  const b = await party();
  const h = await open(b);
  for (let i = 0; i < 40; i++) {
    h.received({
      id: `m${i}`,
      peer: a,
      sequence: i + 1,
      read: false,
      body: `body ${i}`,
    });
    if (i % 7 === 0) {
      h.read(a);
    }
  }
  const [during] = await Promise.all([
    (async () => (await open(await reload(b))).restore())(),
    h.flush(),
  ]);
  assert.equal(during.rejected, 0);
  h.read(a);
  await h.flush();
  const result = await (await open(await reload(b))).restore();
  assert.equal(result.rejected, 0);
  assert.deepEqual(
    result.restored.map((m) => m.body),
    Array.from({ length: 40 }, (_, i) => `body ${i}`),
  );
  assert.ok(result.restored.every((m) => "read" in m && m.read === true));
});

test("marking read applies to writes still in flight", async () => {
  const a = await identity();
  const b = await party();
  const h = await open(b);
  for (const id of ["m1", "m2", "m3"]) {
    h.received({ id, peer: a, sequence: Number(id[1]), read: false, body: id });
  }
  h.read(a);
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
  const a = await identity();
  const b = await party();
  const h = await open(b);
  h.received({ id: "m1", peer: a, sequence: 1, read: false, body: "queued" });
  const closed = h.close();
  h.received({ id: "m2", peer: a, sequence: 2, read: false, body: "late" });
  h.read(a);
  await closed;
  await h.flush();
  assert.deepEqual(
    records(b.store).map(([, r]) => [r.id, r.read]),
    [["m1", false]],
  );
});

test("results that settle after the store stops are not persisted", async () => {
  const a = await identity();
  const b = await party();
  const h = await open(b);
  const source = new Source();
  const store = new Conversations(source, b.keys.identity.identity, {
    history: h,
  });
  store.start();
  store.open(a);
  const attempt = store.send("settles late");
  assert.equal(attempt.accepted, true);
  store.stop();
  source.pending[0].resolve({ ok: true });
  if (attempt.accepted) {
    await attempt.delivery;
  }
  await h.flush();
  assert.equal(records(b.store).length, 0);
});

test("reset removes identity, keys, and history", async () => {
  const a = await identity();
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
  const h = await History.open(
    b.store,
    fresh.keys,
    fresh.integrity,
    fresh.storage,
  );
  assert.deepEqual(await h.restore(), { restored: [], rejected: 0 });
});

test("the record decoders enforce the schema", async () => {
  const a = await identity();
  const b = await party();
  await history(a, b);
  const key = `${a}/m1`;
  const received = b.store.data.get(`messages:${key}`) as Record<
    string,
    unknown
  >;
  const sentKey = `${a}/r1`;
  const sent = b.store.data.get(`messages:${sentKey}`) as Record<
    string,
    unknown
  >;
  assert.deepEqual(parseRecord(key, received), received);
  assert.deepEqual(parseRecord(sentKey, sent), sent);
  assert.equal(parseLegacyRecord(key, received), null);
  const without = (record: Record<string, unknown>, name: string) => {
    const copy = { ...record };
    delete copy[name];
    return copy;
  };
  const cases: [string, string, unknown][] = [
    ["version 1", key, { ...received, v: 1 }],
    ["version 3", key, { ...received, v: 3 }],
    ["moved record", `${a}/m2`, received],
    ["invalid id", `${a}/bad id`, { ...received, id: "bad id" }],
    ["invalid peer", "x/m1", { ...received, peer: "x" }],
    ["sequence zero", key, { ...received, sequence: 0 }],
    ["sequence fraction", key, { ...received, sequence: 1.5 }],
    ["sequence string", key, { ...received, sequence: "2" }],
    ["direction", key, { ...received, direction: "outgoing" }],
    ["read string", key, { ...received, read: "true" }],
    ["delivery sending", sentKey, { ...sent, delivery: "sending" }],
    ["delivery seen", sentKey, { ...sent, delivery: "seen" }],
    ["sent with read", sentKey, { ...without(sent, "delivery"), read: true }],
    ["short iv", key, { ...received, iv: "AAAA" }],
    ["padded iv", key, { ...received, iv: `${received.iv}=` }],
    [
      "tag-only ciphertext",
      key,
      { ...received, ciphertext: encodeBase64Url(new Uint8Array(16)) },
    ],
    ["numeric ciphertext", key, { ...received, ciphertext: 7 }],
    ["unexpected body", key, { ...received, body: "plaintext" }],
    ["unexpected key", key, { ...received, key: "x" }],
    ["array", key, [received]],
    ["null", key, null],
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

test("migrates authentic v1 records to v2 exactly once", async () => {
  const b = await party();
  const peer = await legacyParty();
  const legacy = await Promise.all([
    legacyRecord(b, peer, {
      id: "l1",
      sequence: 1,
      direction: "received",
      state: false,
      body: "legacy one",
    }),
    legacyRecord(b, peer, {
      id: "l2",
      sequence: 2,
      direction: "sent",
      state: "delivered",
      body: "legacy two",
    }),
    legacyRecord(b, peer, {
      id: "l3",
      sequence: 3,
      direction: "received",
      state: true,
      body: "legacy three",
    }),
  ]);
  for (const [key, value] of legacy) {
    b.store.data.set(`messages:${key}`, value);
  }
  const h = await open(b);
  assert.equal(h.migrated, 3);
  const { restored, rejected } = await h.restore();
  assert.equal(rejected, 0);
  assert.deepEqual(
    restored.map((m) => [m.id, m.direction, m.body]),
    [
      ["l1", "received", "legacy one"],
      ["l2", "sent", "legacy two"],
      ["l3", "received", "legacy three"],
    ],
  );
  for (const [, record] of records(b.store)) {
    assert.equal(record.v, historyVersion);
    assert.ok(!("mac" in record) && !("key" in record) && !("salt" in record));
  }
  assertNoPlaintext(b.store, ["legacy one", "legacy two", "legacy three"]);
  const writes = b.store.writes;
  const again = await open(await reload(b));
  assert.equal(again.migrated, 0);
  assert.equal((await again.restore()).restored.length, 3);
  assert.equal(b.store.writes, writes);
});

test("mixed, corrupted, and interrupted v1 migrations fail safely", async () => {
  const b = await party();
  const peer = await legacyParty();
  const other = await legacyParty();
  const a = peer.identity.identity;
  await history(a, b);
  const [goodKey, good] = await legacyRecord(b, peer, {
    id: "g1",
    sequence: 10,
    direction: "received",
    state: true,
    body: "migrates",
  });
  const bad = await Promise.all([
    legacyRecord(b, peer, {
      id: "x1",
      sequence: 11,
      direction: "received",
      state: true,
      body: "mac",
    }),
    legacyRecord(b, peer, {
      id: "x2",
      sequence: 12,
      direction: "received",
      state: true,
      body: "cipher",
    }),
    legacyRecord(b, peer, {
      id: "x3",
      sequence: 13,
      direction: "received",
      state: true,
      body: "binding",
    }),
    legacyRecord(b, other, {
      id: "x4",
      sequence: 14,
      direction: "received",
      state: true,
      body: "key",
    }),
  ]);
  bad[0][1].mac = flip(bad[0][1].mac as string);
  bad[1][1].ciphertext = flip(bad[1][1].ciphertext as string);
  bad[2][1].signature = other.bundle.signature;
  bad[3][1].peer = a;
  bad[3][1].key = peer.bundle.key;
  bad[3][0] = `${a}/x4`;
  b.store.data.set(`messages:${goodKey}`, good);
  for (const [key, value] of bad) {
    b.store.data.set(`messages:${key}`, value);
  }

  const failing = {
    ...b.store,
    swap: async () => {
      throw new Error("interrupted");
    },
  };
  const interrupted = await open(b, failing);
  assert.equal(interrupted.migrated, 0);
  const partial = await interrupted.restore();
  assert.equal(partial.rejected, 5);
  assert.equal(partial.restored.length, 3);
  assert.equal(
    (b.store.data.get(`messages:${goodKey}`) as Record<string, unknown>).v,
    legacyVersion,
  );

  const [first, second] = await Promise.all([open(b), open(b)]);
  assert.equal(first.migrated + second.migrated, 1);
  for (const h of [first, second]) {
    const result = await h.restore();
    assert.equal(result.rejected, 4);
    assert.deepEqual(result.restored.map((m) => m.id).sort(), [
      "g1",
      "m1",
      "m2",
      "r1",
    ]);
  }
  for (const [key, value] of bad) {
    assert.deepEqual(b.store.data.get(`messages:${key}`), value);
  }
});

test("fuzzed persisted records never restore as trusted state", async () => {
  const a = await identity();
  const b = await party();
  await history(a, b);
  const key = `${a}/m1`;
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
    1,
    2,
    "",
    "A",
    "=",
    "💥",
    true,
    false,
    [],
    {},
    "A".repeat(16),
    "A".repeat(43),
  ];
  let seed = 0x9e3779b9;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_+/=";
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 1500);
  for (let i = 0; i < iterations; i++) {
    const mutated: Record<string, unknown> = { ...original };
    for (let s = 0; s <= random(3); s++) {
      const name = names[random(names.length)];
      const choice = random(5);
      if (choice === 0) {
        delete mutated[name];
      } else if (choice === 1) {
        mutated[name] = values[random(values.length)];
      } else if (choice === 2 && typeof mutated[name] === "string") {
        const text = mutated[name] as string;
        const at = random(Math.max(1, text.length));
        mutated[name] =
          text.slice(0, at) + chars[random(chars.length)] + text.slice(at + 1);
      } else if (choice === 3) {
        mutated[["mac", "key", "body", "salt"][random(4)]] =
          values[random(values.length)];
      } else {
        mutated[name] = original[names[random(names.length)]];
      }
    }
    b.store.data.set(`messages:${key}`, mutated);
    const { restored } = await (await open(b)).restore();
    const m1 = restored.find((m) => m.id === "m1");
    if (m1) {
      assert.deepEqual(mutated, original);
      assert.equal(m1.body, "first secret");
    }
    assert.ok(restored.some((m) => m.id === "m2"));
  }
});
