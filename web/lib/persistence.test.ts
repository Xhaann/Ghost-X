import assert from "node:assert/strict";
import { test } from "node:test";
import { Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import { Conversations } from "./conversations.ts";
import { History } from "./history.ts";
import { Messenger } from "./messenger.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  created,
  freePort,
  memoryStore,
  startServer,
  stopServer,
  track,
  useServer,
} from "./testing.ts";
import { type Unlocked, loadVault } from "./vault.ts";

useServer();

type Store = ReturnType<typeof memoryStore>;

type Device = Unlocked & {
  store: Store;
  history: History;
  rejected: number;
  client: Client;
  conversations: Conversations;
  socket: WebSocket;
  frames: string[];
  shutdown: () => Promise<void>;
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

async function boot(port: number, store: Store): Promise<Device> {
  const vault = await loadVault(store);
  assert.equal(vault.status, "ready");
  const unlocked = vault as Unlocked;
  const history = await History.open(store, unlocked.keys, unlocked.integrity);
  const { restored, rejected } = await history.restore();

  const before = created.length;
  const frames: string[] = [];
  const transport = track(
    new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
  );
  const transmit = transport.send.bind(transport);
  transport.send = (data: string) => {
    frames.push(data);
    return transmit(data);
  };
  transport.onData((data) => frames.push(data));
  const client = track(new Client(transport));
  const auth = new Authenticator(client, unlocked.keys.identity);
  const messenger = new Messenger(
    client,
    auth,
    unlocked.keys.identity,
    unlocked.keys.exchange,
  );
  const conversations = new Conversations(
    messenger,
    unlocked.keys.identity.identity,
    { history, restored },
  );
  let stopped = false;
  const shutdown = async () => {
    if (stopped) {
      return;
    }
    stopped = true;
    conversations.stop();
    messenger.stop();
    auth.stop();
    client.close();
    await history.close();
  };
  track({ close: () => void shutdown() });
  auth.start();
  messenger.start();
  conversations.start();
  client.open();
  await until(() => conversations.state.connected, "connected");
  return {
    ...unlocked,
    store,
    history,
    rejected,
    client,
    conversations,
    socket: created[before],
    frames,
    shutdown,
  };
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

function unread(device: Device, peer: string): number | undefined {
  return device.conversations.state.conversations.find(
    (c) => c.identity === peer,
  )?.unread;
}

function send(device: Device, body: string) {
  const attempt = device.conversations.send(body);
  assert.equal(attempt.accepted, true);
  return attempt as Extract<typeof attempt, { accepted: true }>;
}

function assertSealedAtRest(store: Store, secrets: string[]): void {
  const serialized = JSON.stringify([...store.data.entries()]);
  for (const secret of secrets) {
    assert.ok(!serialized.includes(secret), "plaintext at rest");
    assert.ok(
      !serialized.includes(Buffer.from(secret).toString("base64url")),
      "encoded plaintext at rest",
    );
  }
}

test("a reloaded device keeps its identity, keys, and encrypted history", async () => {
  const port = await freePort();
  await startServer(port);
  const storeA = memoryStore();
  const storeB = memoryStore();
  const a = await boot(port, storeA);
  let b = await boot(port, storeB);
  const idA = a.keys.identity.identity;
  const idB = b.keys.identity.identity;
  assert.equal(a.created, true);

  const captured: string[] = [];
  b.socket.addEventListener("message", (event) =>
    captured.push(String(event.data)),
  );
  a.conversations.open(idB);
  const first = send(a, "before reload");
  assert.equal(await first.delivery, "delivered");
  await until(() => thread(b, idA).length === 1, "b receives");
  b.conversations.open(idA);
  assert.equal(await send(b, "reply before reload").delivery, "delivered");
  await until(() => thread(a, idB).length === 2, "a receives reply");
  await b.history.flush();
  const frame = captured.find((data) => data.includes(first.id));
  assert.ok(frame);

  await b.shutdown();
  b = await boot(port, storeB);
  assert.equal(b.created, false);
  assert.equal(b.rejected, 0);
  assert.equal(b.keys.identity.identity, idB);
  assert.ok(
    b.frames.some((f) => f.includes('"type":"published"')),
    "server accepted the restored key binding",
  );
  assert.deepEqual(thread(b, idA), [
    "received:before reload",
    "sent:delivered:reply before reload",
  ]);
  assert.equal(unread(b, idA), 0);

  b.socket.dispatchEvent(new MessageEvent("message", { data: frame }));
  b.socket.dispatchEvent(new MessageEvent("message", { data: frame }));
  assert.equal(await send(a, "after reload").delivery, "delivered");
  await until(() => thread(b, idA).length === 3, "b receives after reload");
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(thread(b, idA), [
    "received:before reload",
    "sent:delivered:reply before reload",
    "received:after reload",
  ]);
  assert.equal(unread(b, idA), 1);
  await b.history.flush();
  await a.history.flush();

  const secrets = ["before reload", "reply before reload", "after reload"];
  assertSealedAtRest(storeA, secrets);
  assertSealedAtRest(storeB, secrets);
  for (const device of [a, b]) {
    for (const f of device.frames) {
      assert.ok(!secrets.some((s) => f.includes(s)), "plaintext on the wire");
      assert.ok(!/"(signing|exchange|integrity|mac)"/.test(f));
    }
  }

  await b.shutdown();
  b = await boot(port, storeB);
  assert.equal(unread(b, idA), 1);
  b.conversations.open(idA);
  await b.history.flush();
  await b.shutdown();
  b = await boot(port, storeB);
  assert.equal(unread(b, idA), 0);
  assert.equal(thread(b, idA).length, 3);
});

test("history and identity survive a server restart and multiple conversations", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const storeA = memoryStore();
  let a = await boot(port, storeA);
  const b = await boot(port, memoryStore());
  const c = await boot(port, memoryStore());
  const idA = a.keys.identity.identity;
  const idB = b.keys.identity.identity;
  const idC = c.keys.identity.identity;

  b.conversations.open(idA);
  assert.equal(await send(b, "from b").delivery, "delivered");
  c.conversations.open(idA);
  assert.equal(await send(c, "from c").delivery, "delivered");
  await until(
    () => thread(a, idB).length === 1 && thread(a, idC).length === 1,
    "a receives both",
  );

  await stopServer(server);
  await until(() => !a.conversations.state.connected, "disconnected");
  await a.history.flush();
  await a.shutdown();
  await startServer(port);
  a = await boot(port, storeA);
  await until(
    () => b.conversations.state.connected && c.conversations.state.connected,
    "peers reconnected",
  );

  assert.equal(a.keys.identity.identity, idA);
  assert.deepEqual(
    a.conversations.state.conversations.map((x) => [
      x.identity,
      x.unread,
      x.messages.length,
    ]),
    [
      [idC, 1, 1],
      [idB, 1, 1],
    ],
  );
  assert.equal(await send(b, "after restart").delivery, "delivered");
  await until(() => thread(a, idB).length === 2, "a receives after restart");
  assert.deepEqual(thread(a, idB), [
    "received:from b",
    "received:after restart",
  ]);
  assert.deepEqual(thread(a, idC), ["received:from c"]);
});

test("a message that was never encrypted is never persisted", async () => {
  const port = await freePort();
  await startServer(port);
  const storeA = memoryStore();
  let a = await boot(port, storeA);
  const b = await boot(port, memoryStore());
  const idB = b.keys.identity.identity;
  await b.shutdown();

  a.conversations.open(idB);
  const deadline = Date.now() + 5000;
  while ((await send(a, "probe").delivery) !== "unavailable") {
    assert.ok(Date.now() < deadline);
  }
  assert.equal(await send(a, "never encrypted").delivery, "unavailable");
  assert.equal(thread(a, idB).at(-1), "sent:unavailable:never encrypted");
  await a.history.flush();
  assertSealedAtRest(storeA, ["never encrypted", "probe"]);
  await a.shutdown();
  a = await boot(port, storeA);
  const restored = thread(a, idB);
  assert.ok(!restored.some((m) => m.endsWith(":never encrypted")));
  assert.ok(restored.every((m) => m === "sent:unavailable:probe"));
});

test("a corrupted record is rejected while the rest of the history restores", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  const a = await boot(port, memoryStore());
  let b = await boot(port, storeB);
  const idA = a.keys.identity.identity;
  a.conversations.open(b.keys.identity.identity);
  for (const body of ["one", "two", "three"]) {
    assert.equal(await send(a, body).delivery, "delivered");
  }
  await until(() => thread(b, idA).length === 3, "received");
  await b.history.flush();
  await b.shutdown();

  const [key, value] = [...storeB.data.entries()].find(
    ([, v]) => (v as { sequence?: number }).sequence === 3,
  ) as [string, Record<string, string>];
  const bytes = Buffer.from(value.ciphertext, "base64url");
  bytes[0] ^= 1;
  storeB.data.set(key, { ...value, ciphertext: bytes.toString("base64url") });

  b = await boot(port, storeB);
  assert.equal(b.rejected, 1);
  assert.deepEqual(thread(b, idA), ["received:one", "received:three"]);
  assert.equal(await send(a, "four").delivery, "delivered");
  await until(() => thread(b, idA).length === 3, "still receiving");
});

test("an explicit reset yields a new identity that cannot read the old history", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  const a = await boot(port, memoryStore());
  let b = await boot(port, storeB);
  const oldB = b.keys.identity.identity;
  a.conversations.open(oldB);
  assert.equal(await send(a, "to the old identity").delivery, "delivered");
  await until(() => thread(b, a.keys.identity.identity).length === 1, "rx");
  await b.history.flush();
  await b.shutdown();

  await storeB.clear();
  b = await boot(port, storeB);
  assert.equal(b.created, true);
  assert.notEqual(b.keys.identity.identity, oldB);
  assert.deepEqual(b.conversations.state.conversations, []);
  assert.equal(await send(a, "old identity is gone").delivery, "unavailable");
});
