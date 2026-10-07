import assert from "node:assert/strict";
import { test } from "node:test";
import { Conversations } from "./conversations.ts";
import { IdentityKey } from "./identity.ts";
import {
  type SecureDevice,
  freePort,
  memoryStore,
  secureDevice,
  startServer,
  stopServer,
  useServer,
} from "./testing.ts";

useServer();

type Store = ReturnType<typeof memoryStore>;

type Device = SecureDevice & {
  rejected: number;
  conversations: Conversations;
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
  const device = await secureDevice(port, { store, inbox: false });
  const { restored, rejected } = await device.history.restore();
  const conversations = new Conversations(device.messenger, device.id, {
    history: device.history,
    restored,
  });
  conversations.start();
  await until(() => conversations.state.connected, "connected");
  return {
    ...device,
    rejected,
    conversations,
    shutdown: async () => {
      conversations.stop();
      await device.shutdown();
    },
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
  const idA = a.keys.identity;
  const idB = b.keys.identity;
  assert.equal(a.created, true);

  a.conversations.open(idB);
  const first = send(a, "before reload");
  assert.equal(await first.delivery, "queued");
  await until(() => thread(b, idA).length === 1, "b receives");
  b.conversations.open(idA);
  assert.equal(await send(b, "reply before reload").delivery, "queued");
  await until(() => thread(a, idB).length === 2, "a receives reply");
  await until(
    () => thread(b, idA).includes("sent:delivered:reply before reload"),
    "receipt",
  );
  await b.history.flush();
  const frame = b.received.find((data) => data.includes(first.id));
  assert.ok(frame);

  await b.shutdown();
  b = await boot(port, storeB);
  assert.equal(b.created, false);
  assert.equal(b.rejected, 0);
  assert.equal(b.keys.identity, idB);
  assert.ok(
    b.frames.some(
      (f) => f.includes('"type":"authenticated"') && f.includes(b.deviceId),
    ),
    "server accepted the restored device",
  );
  assert.deepEqual(thread(b, idA), [
    "received:before reload",
    "sent:delivered:reply before reload",
  ]);
  assert.equal(unread(b, idA), 0);

  b.deliver(frame);
  b.deliver(frame);
  assert.equal(await send(a, "after reload").delivery, "queued");
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
      assert.ok(!/"(root|deviceKey|integrity|storage|mac|d|pkcs8)"/.test(f));
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
  const idA = a.keys.identity;
  const idB = b.keys.identity;
  const idC = c.keys.identity;

  b.conversations.open(idA);
  assert.equal(await send(b, "from b").delivery, "queued");
  c.conversations.open(idA);
  assert.equal(await send(c, "from c").delivery, "queued");
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

  assert.equal(a.keys.identity, idA);
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
  assert.equal(await send(b, "after restart").delivery, "queued");
  await until(() => thread(a, idB).length === 2, "a receives after restart");
  assert.deepEqual(thread(a, idB), [
    "received:from b",
    "received:after restart",
  ]);
  assert.deepEqual(thread(a, idC), ["received:from c"]);
});

test("queued and undeliverable messages are persisted encrypted with their state", async () => {
  const port = await freePort();
  await startServer(port);
  const storeA = memoryStore();
  let a = await boot(port, storeA);
  const b = await boot(port, memoryStore());
  const idB = b.keys.identity;
  assert.equal((await a.pairing.establish(idB)).result, "established");
  await b.shutdown();

  a.conversations.open(idB);
  assert.equal(await send(a, "queued secret").delivery, "queued");
  const nobody = (await IdentityKey.generate()).identity;
  a.conversations.open(nobody);
  assert.equal(await send(a, "undeliverable secret").delivery, "unavailable");
  await a.history.flush();
  assertSealedAtRest(storeA, ["queued secret", "undeliverable secret"]);
  await a.shutdown();
  a = await boot(port, storeA);
  assert.deepEqual(thread(a, idB), ["sent:queued:queued secret"]);
  assert.deepEqual(thread(a, nobody), [
    "sent:unavailable:undeliverable secret",
  ]);
});

test("a corrupted record is rejected while the rest of the history restores", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  const a = await boot(port, memoryStore());
  let b = await boot(port, storeB);
  const idA = a.keys.identity;
  a.conversations.open(b.keys.identity);
  for (const body of ["one", "two", "three"]) {
    assert.equal(await send(a, body).delivery, "queued");
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
  assert.equal(await send(a, "four").delivery, "queued");
  await until(() => thread(b, idA).length === 3, "still receiving");
});

test("an explicit reset yields a new identity that cannot read the old history", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  const a = await boot(port, memoryStore());
  let b = await boot(port, storeB);
  const oldB = b.keys.identity;
  a.conversations.open(oldB);
  assert.equal(await send(a, "to the old identity").delivery, "queued");
  await until(() => thread(b, a.keys.identity).length === 1, "rx");
  await b.history.flush();
  await b.shutdown();

  await storeB.clear();
  b = await boot(port, storeB);
  assert.equal(b.created, true);
  assert.notEqual(b.keys.identity, oldB);
  assert.deepEqual(b.conversations.state.conversations, []);
  assert.equal(await send(a, "old identity is gone").delivery, "queued");
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.deepEqual(b.conversations.state.conversations, []);
});
