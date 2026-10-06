import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64Url } from "./base64.ts";
import { Conversations, type DeliveryState } from "./conversations.ts";
import { maxSkip, maxSkipped } from "./ratchet.ts";
import { createMessageId } from "./protocol.ts";
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

useServer();

type Json = Record<string, unknown>;

type Device = SecureDevice & {
  conversations: Conversations;
  shutdown: () => Promise<void>;
};

async function until(
  predicate: () => boolean | Promise<boolean>,
  what: string,
  ms = 5000,
): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await predicate())) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function boot(
  port: number,
  store: MemoryStore,
  options: { drop?: string[] } = {},
): Promise<Device> {
  const device = await secureDevice(port, {
    store,
    drop: options.drop,
    inbox: false,
  });
  const { restored } = await device.history.restore();
  const conversations = new Conversations(device.messenger, device.id, {
    history: device.history,
    restored,
  });
  conversations.start();
  await until(() => conversations.state.connected, "connected");
  return {
    ...device,
    conversations,
    shutdown: async () => {
      conversations.stop();
      await device.shutdown();
    },
  };
}

function frames(list: string[], type: string): Json[] {
  return list
    .map((raw) => JSON.parse(raw) as Json)
    .filter((frame) => frame.type === type);
}

function thread(device: Device, peer: string): string[] {
  return (
    device.conversations.state.conversations
      .find((c) => c.identity === peer)
      ?.messages.map((m) =>
        m.direction === "sent"
          ? `sent:${m.delivery}:${m.body}`
          : `received:${m.body}`,
      ) ?? []
  );
}

function received(device: Device, peer: string): (string | null)[] {
  return (
    device.conversations.state.conversations
      .find((c) => c.identity === peer)
      ?.messages.filter((m) => m.direction === "received")
      .map((m) => m.body) ?? []
  );
}

function deliveryOf(device: Device, peer: string, id: string): DeliveryState {
  const message = device.conversations.state.conversations
    .find((c) => c.identity === peer)
    ?.messages.find((m) => m.id === id);
  assert.ok(message?.direction === "sent");
  return message.delivery;
}

async function send(device: Device, body: string) {
  const attempt = device.conversations.send(body);
  assert.equal(attempt.accepted, true);
  assert.ok(attempt.accepted);
  return { id: attempt.id, result: await attempt.delivery };
}

async function stored(
  device: Device,
  peer: string,
): Promise<(string | null)[]> {
  await device.history.flush();
  const { restored } = await device.history.restore();
  return restored
    .filter((m) => m.direction === "received" && m.from === peer)
    .map((m) => m.body);
}

async function pair(port: number) {
  const storeA = memoryStore();
  const storeB = memoryStore();
  const a = await boot(port, storeA);
  const b = await boot(port, storeB);
  assert.equal(await a.pairing.establish(b.id), "established");
  return { a, b, storeA, storeB };
}

function assertSealed(store: MemoryStore, secrets: string[]) {
  const dump = JSON.stringify([...store.data.entries()]);
  for (const secret of secrets) {
    assert.ok(!dump.includes(secret), "plaintext at rest");
    assert.ok(!dump.includes(Buffer.from(secret).toString("base64url")));
  }
}

test("messages sent to an offline recipient are queued as ciphertext and delivered on reconnect", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeA, storeB } = await pair(port);
  const idB = b.id;
  await b.shutdown();

  a.conversations.open(idB);
  const secrets = ["offline one", "offline two", "offline three 🔒"];
  const sent: string[] = [];
  for (const body of secrets) {
    const outcome = await send(a, body);
    assert.equal(outcome.result, "queued");
    sent.push(outcome.id);
  }
  assert.deepEqual(
    thread(a, idB),
    secrets.map((s) => `sent:queued:${s}`),
  );
  for (const frame of frames(a.sent, "send")) {
    const payload = frame.payload as Json;
    assert.deepEqual(Object.keys(payload).sort(), ["ciphertext", "id", "to"]);
    assert.ok(!secrets.some((s) => JSON.stringify(payload).includes(s)));
  }

  const again = await boot(port, storeB);
  await until(() => received(again, a.id).length === 3, "queued delivery");
  assert.deepEqual(received(again, a.id), secrets);
  assert.deepEqual(await stored(again, a.id), secrets);
  await until(() => frames(again.sent, "ack").length === 3, "acks");
  const acked = frames(again.sent, "ack").map((f) => (f.payload as Json).id);
  assert.deepEqual(acked, sent);
  await until(
    () => sent.every((id) => deliveryOf(a, idB, id) === "delivered"),
    "receipts",
  );
  await a.history.flush();
  await until(() => frames(a.sent, "clear").length === 3, "receipts cleared");

  const reloaded = await boot(port, storeA);
  assert.deepEqual(
    thread(reloaded, idB),
    secrets.map((s) => `sent:delivered:${s}`),
  );
  assertSealed(storeA, secrets);
  assertSealed(storeB, secrets);
  for (const frame of [
    ...a.sent,
    ...a.received,
    ...again.sent,
    ...again.received,
  ]) {
    assert.ok(!secrets.some((s) => frame.includes(s)), "plaintext on the wire");
    assert.ok(
      !/private|pkcs8|"root"|"chain"|"storage"|"integrity"/i.test(frame),
    );
  }
});

test("the sender ratchet advances while the recipient is offline and the recipient catches up", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeB } = await pair(port);
  const idB = b.id;
  await b.shutdown();
  a.conversations.open(idB);

  const count = maxSkip + 20;
  const chain = async () =>
    a.pairs.transact(idB, async (s) => ({
      state: s,
      value: s.sending?.n ?? 0,
    }));
  const start = await chain();
  const bodies: string[] = [];
  let full = 0;
  for (let i = 0; i < count; i++) {
    const body = `burst ${i}`;
    const outcome = await send(a, body);
    if (outcome.result === "queued") {
      bodies.push(body);
    } else {
      assert.equal(outcome.result, "failed");
      full += 1;
    }
  }
  assert.equal(bodies.length, 128 > count ? count : 128);
  assert.equal(((await chain()) ?? 0) - (start ?? 0), count);
  const texts = frames(a.sent, "send").map(
    (f) => (f.payload as Json).ciphertext,
  );
  assert.equal(new Set(texts).size, texts.length);

  const again = await boot(port, storeB);
  await until(
    () => received(again, a.id).length === bodies.length,
    "catch up",
    15000,
  );
  assert.deepEqual(received(again, a.id), bodies);
  const skipped = await again.pairs.transact(a.id, async (s) => ({
    state: s,
    value: s.skipped.length,
  }));
  assert.equal(skipped, 0);
  assert.equal(full, 0);

  const last = await send(a, "after catching up");
  assert.equal(last.result, "queued");
  await until(
    () => received(again, a.id).at(-1) === "after catching up",
    "live",
  );
});

test("a gap beyond the skip bound fails closed without moving the ratchet", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b } = await pair(port);
  for (let i = 0; i <= maxSkip; i++) {
    assert.ok(await a.pairing.seal(b.id, createMessageId(), `lost ${i}`));
  }
  const before = await b.pairs.transact(a.id, async (s) => ({
    state: s,
    value: JSON.stringify([s.receiving?.n ?? null, s.skipped.length]),
  }));
  a.conversations.open(b.id);
  assert.equal((await send(a, "too far ahead")).result, "queued");
  await until(() => received(b, a.id).length === 1, "processed");
  assert.deepEqual(received(b, a.id), [null]);
  const after = await b.pairs.transact(a.id, async (s) => ({
    state: s,
    value: JSON.stringify([s.receiving?.n ?? null, s.skipped.length]),
  }));
  assert.equal(after, before);
  assert.ok(maxSkipped >= maxSkip);
  await until(
    () => frames(b.sent, "ack").length === 1,
    "rejected message acknowledged",
  );
});

test("crash after transmission but before decryption redelivers the message", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeB } = await pair(port);
  b.hold(true);
  a.conversations.open(b.id);
  assert.equal((await send(a, "survives a crash")).result, "queued");
  await until(() => frames(b.received, "message").length === 1, "transmitted");
  await b.shutdown();
  const again = await boot(port, storeB);
  await until(() => received(again, a.id).length === 1, "redelivered");
  assert.deepEqual(received(again, a.id), ["survives a crash"]);
});

test("crash after decryption but before recording keeps the message and the ratchet consistent", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeB } = await pair(port);
  const realPut = storeB.put.bind(storeB);
  let failMessages = true;
  storeB.put = async (name, key, value) => {
    if (name === "messages" && failMessages) {
      throw new Error("storage unavailable");
    }
    return realPut(name, key, value);
  };
  const ratchet = async (d: Device) =>
    d.pairs.transact(a.id, async (s) => ({
      state: s,
      value: s.receiving?.n ?? -1,
    }));
  const before = await ratchet(b);
  a.conversations.open(b.id);
  assert.equal((await send(a, "decrypted but not stored")).result, "queued");
  await until(() => frames(b.received, "message").length === 1, "transmitted");
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.deepEqual(received(b, a.id), []);
  assert.equal(frames(b.sent, "ack").length, 0);
  assert.equal(await ratchet(b), before);
  await b.shutdown();
  failMessages = false;
  storeB.put = realPut;
  const again = await boot(port, storeB);
  await until(() => received(again, a.id).length === 1, "redelivered");
  assert.deepEqual(await stored(again, a.id), ["decrypted but not stored"]);
  assert.equal((await send(a, "next")).result, "queued");
  await until(() => received(again, a.id).length === 2, "ratchet continues");
});

test("crash after recording but before the ratchet commit heals on redelivery", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeB } = await pair(port);
  const realPut = storeB.put.bind(storeB);
  let failPairs = true;
  storeB.put = async (name, key, value) => {
    if (name === "pairs" && failPairs) {
      throw new Error("storage unavailable");
    }
    return realPut(name, key, value);
  };
  a.conversations.open(b.id);
  assert.equal((await send(a, "recorded first")).result, "queued");
  await until(() => received(b, a.id).length === 1, "recorded");
  await b.shutdown();
  failPairs = false;
  storeB.put = realPut;
  const again = await boot(port, storeB);
  await until(() => frames(again.sent, "ack").length >= 1, "acknowledged");
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(received(again, a.id), ["recorded first"]);
  const skipped = await again.pairs.transact(a.id, async (s) => ({
    state: s,
    value: s.skipped.length,
  }));
  assert.equal(skipped, 0);
  assert.equal((await send(a, "after healing")).result, "queued");
  await until(() => received(again, a.id).length === 2, "next");
  assert.deepEqual(await stored(again, a.id), [
    "recorded first",
    "after healing",
  ]);
});

test("a lost acknowledgment never duplicates the application message", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeB } = await pair(port);
  const realSend = b.client.send.bind(b.client);
  b.client.send = ((message, id) =>
    message.type === "ack"
      ? (id ?? "dropped")
      : realSend(message, id)) as typeof b.client.send;
  a.conversations.open(b.id);
  const first = await send(a, "ack lost");
  assert.equal(first.result, "queued");
  await until(() => received(b, a.id).length === 1, "recorded");
  await b.history.flush();
  assert.equal(deliveryOf(a, b.id, first.id), "queued");
  await b.shutdown();

  const again = await boot(port, storeB);
  await until(
    () => frames(again.received, "message").length === 1,
    "redelivered",
  );
  await until(() => frames(again.sent, "ack").length === 1, "acknowledged");
  await until(
    () => deliveryOf(a, again.id, first.id) === "delivered",
    "receipt",
  );
  assert.deepEqual(received(again, a.id), ["ack lost"]);
  assert.deepEqual(await stored(again, a.id), ["ack lost"]);
  await again.client.request({ type: "fetch", payload: {} });
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(frames(again.received, "message").length, 1);
});

test("the sender learns delivery after reconnecting and never resends", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeA } = await pair(port);
  await b.shutdown();
  a.conversations.open(b.id);
  const message = await send(a, "while both disappear");
  assert.equal(message.result, "queued");
  await a.history.flush();
  await a.shutdown();

  const bAgain = await boot(port, b.store);
  await until(() => received(bAgain, a.id).length === 1, "recipient got it");
  const aAgain = await boot(port, storeA);
  await until(
    () => deliveryOf(aAgain, b.id, message.id) === "delivered",
    "receipt after reconnect",
  );
  await until(() => frames(aAgain.sent, "clear").length === 1, "cleared");
  assert.equal(frames(aAgain.sent, "send").length, 0);
  await aAgain.history.flush();
  const reloaded = await boot(port, storeA);
  assert.deepEqual(thread(reloaded, b.id), [
    "sent:delivered:while both disappear",
  ]);
});

test("an unconfirmed send is shown as not delivered until a receipt proves otherwise", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b } = await pair(port);
  const realRequest = a.client.request.bind(a.client);
  a.client.request = (async (...args: Parameters<typeof realRequest>) => {
    if (args[0].type === "send") {
      a.client.send(args[0]);
      return null;
    }
    return realRequest(...args);
  }) as typeof realRequest;
  a.conversations.open(b.id);
  const message = await send(a, "reply lost");
  assert.equal(message.result, "failed");
  await until(() => received(b, a.id).length === 1, "it was queued");
  await until(
    () => deliveryOf(a, b.id, message.id) === "delivered",
    "receipt corrects state",
  );
  assert.equal(frames(a.sent, "send").length, 1);
});

test("the server restart drops the in-memory queue and the sender sees no delivery", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const { a, b, storeB } = await pair(port);
  await b.shutdown();
  a.conversations.open(b.id);
  const message = await send(a, "lost with the server");
  assert.equal(message.result, "queued");
  await stopServer(server);
  await until(() => !a.conversations.state.connected, "disconnected");
  await startServer(port);
  await until(() => a.conversations.state.connected, "reconnected");
  const again = await boot(port, storeB);
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.deepEqual(received(again, a.id), []);
  assert.equal(deliveryOf(a, b.id, message.id), "queued");
  assert.equal((await send(a, "after restart")).result, "queued");
  await until(
    () => received(again, a.id).length === 1,
    "ratchet tolerates the gap",
  );
  assert.deepEqual(received(again, a.id), ["after restart"]);
});

test("queued ciphertext from a replaced session is rejected, never decrypted with the new one", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeA, storeB } = await pair(port);
  const idA = a.id;
  const idB = b.id;
  const oldSession = b.pairs.id(idA);
  await b.shutdown();
  a.conversations.open(idB);
  assert.equal((await send(a, "old session message")).result, "queued");
  await a.shutdown();
  storeA.data.delete(`pairs:${idB}`);
  const fresh = await boot(port, storeA);
  assert.equal(await fresh.pairing.initiate(idB), "pending");

  const held = await boot(port, storeB, { drop: ["message"] });
  await until(
    () =>
      held.pairs.id(idA) !== oldSession &&
      held.pairs.state(idA) === "established",
    "new session",
  );
  await held.shutdown();
  const again = await boot(port, storeB);
  await until(
    () => received(again, idA).length === 1,
    "old ciphertext processed",
  );
  assert.deepEqual(received(again, idA), [null]);
  await until(
    () => fresh.pairs.state(idB) === "established",
    "initiator established",
  );
  fresh.conversations.open(idB);
  assert.equal((await send(fresh, "new session message")).result, "queued");
  await until(() => received(again, idA).length === 2, "new session delivery");
  assert.deepEqual(received(again, idA), [null, "new session message"]);
});

test("a message arriving before its session is confirmed waits instead of failing", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  let b = await boot(port, storeB);
  const idB = b.id;
  await b.shutdown();
  const a = await boot(port, memoryStore());
  a.delay(["acceptance"]);
  assert.equal(await a.pairing.initiate(idB), "pending");
  b = await boot(port, storeB);
  await until(() => b.pairs.state(a.id) === "established", "responder");
  b.conversations.open(a.id);
  assert.equal((await send(b, "early reply")).result, "queued");
  await until(
    () => frames(a.received, "message").length === 1,
    "arrived early",
  );
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(a.pairs.state(idB), "pending");
  assert.deepEqual(received(a, idB), []);
  assert.equal(frames(a.sent, "ack").length, 0);
  a.release();
  await until(() => a.pairs.state(idB) === "established", "confirmed");
  await until(() => received(a, idB).length === 1, "deferred delivery");
  assert.deepEqual(received(a, idB), ["early reply"]);
  await until(() => frames(a.sent, "ack").length === 1, "acknowledged");
});

test("forged and replayed acknowledgments never remove another recipient's message", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeB } = await pair(port);
  const mallory = await boot(port, memoryStore());
  await b.shutdown();
  a.conversations.open(b.id);
  const message = await send(a, "protected");
  for (const actor of [a, mallory]) {
    for (const from of [a.id, b.id, mallory.id]) {
      await actor.client.request({
        type: "ack",
        payload: { from, id: message.id },
      });
    }
  }
  const again = await boot(port, storeB);
  await until(() => received(again, a.id).length === 1, "still delivered");
  assert.deepEqual(received(again, a.id), ["protected"]);
  await until(
    () => deliveryOf(a, b.id, message.id) === "delivered",
    "real receipt",
  );
  for (let i = 0; i < 3; i++) {
    await again.client.request({
      type: "ack",
      payload: { from: a.id, id: message.id },
    });
  }
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(a.receipts.length, 0);
  assert.equal(
    a.conversations.state.conversations[0].messages.filter(
      (m) => m.direction === "sent",
    ).length,
    1,
  );
  assert.ok(
    !JSON.stringify(mallory.received).includes(
      encodeBase64Url(new TextEncoder().encode("protected")),
    ),
  );
});

test("a send that never reaches the server is marked failed and the gap is tolerated", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b } = await pair(port);
  const realRequest = a.client.request.bind(a.client);
  let drop = true;
  a.client.request = (async (...args: Parameters<typeof realRequest>) =>
    drop && args[0].type === "send"
      ? null
      : realRequest(...args)) as typeof realRequest;
  a.conversations.open(b.id);
  const lost = await send(a, "never left the device");
  assert.equal(lost.result, "failed");
  assert.equal(frames(a.sent, "send").length, 0);
  drop = false;
  const next = await send(a, "sent after the loss");
  assert.equal(next.result, "queued");
  await until(() => received(b, a.id).length === 1, "next delivered");
  assert.deepEqual(received(b, a.id), ["sent after the loss"]);
  await until(
    () => deliveryOf(a, b.id, next.id) === "delivered",
    "next acknowledged",
  );
  assert.equal(deliveryOf(a, b.id, lost.id), "failed");
  await a.history.flush();
  const { restored } = await a.history.restore();
  assert.deepEqual(
    restored.flatMap((m) =>
      m.direction === "sent" ? [[m.body, m.delivery]] : [],
    ),
    [
      ["never left the device", "failed"],
      ["sent after the loss", "delivered"],
    ],
  );
});

test("a receipt is cleared only after the sender durably stored the delivery state", async () => {
  const port = await freePort();
  await startServer(port);
  const { a, b, storeA } = await pair(port);
  a.conversations.open(b.id);
  const realPut = storeA.put.bind(storeA);
  const message = await send(a, "receipt must persist");
  assert.equal(message.result, "queued");
  await a.history.flush();
  let failing = true;
  storeA.put = async (name, key, value) => {
    if (name === "messages" && failing) {
      throw new Error("storage unavailable");
    }
    return realPut(name, key, value);
  };
  await until(() => received(b, a.id).length === 1, "recipient got it");
  await until(
    () => frames(a.received, "receipt").length === 1,
    "receipt pushed",
  );
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(frames(a.sent, "clear").length, 0);
  failing = false;
  await a.client.request({ type: "fetch", payload: {} });
  await until(
    () => frames(a.sent, "clear").length === 1,
    "cleared after storing",
  );
  await a.history.flush();
  const { restored } = await a.history.restore();
  assert.deepEqual(
    restored.flatMap((m) => (m.direction === "sent" ? [m.delivery] : [])),
    ["delivered"],
  );
});
