import assert from "node:assert/strict";
import { test } from "node:test";
import { Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import { Conversations } from "./conversations.ts";
import { ExchangeKey } from "./encryption.ts";
import { fingerprint } from "./fingerprint.ts";
import { History } from "./history.ts";
import { IdentityKey } from "./identity.ts";
import { Messenger, type MessengerOptions } from "./messenger.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  freePort,
  memoryStore,
  startServer,
  stopServer,
  track,
  useServer,
} from "./testing.ts";
import { Trust } from "./trust.ts";
import { type Keys, type Unlocked, loadVault } from "./vault.ts";

useServer();

type Store = ReturnType<typeof memoryStore>;

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function connect(
  port: number,
  keys: Keys,
  trust?: Trust,
  history?: History,
  options: MessengerOptions = {},
) {
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
  const auth = new Authenticator(client, keys.identity);
  const messenger = new Messenger(
    client,
    auth,
    keys.identity,
    keys.exchange,
    options,
  );
  const restored = history ? (await history.restore()).restored : [];
  const conversations = new Conversations(messenger, keys.identity.identity, {
    history,
    restored,
  });
  const unkey = trust
    ? messenger.onKey((bundle) => void trust.observe(bundle))
    : () => {};
  let stopped = false;
  const shutdown = async () => {
    if (stopped) {
      return;
    }
    stopped = true;
    unkey();
    conversations.stop();
    messenger.stop();
    auth.stop();
    client.close();
    await Promise.all([history?.close(), trust?.close()]);
  };
  track({ close: () => void shutdown() });
  auth.start();
  messenger.start();
  conversations.start();
  client.open();
  await until(() => conversations.state.connected, "connected");
  return { keys, client, messenger, conversations, frames, shutdown };
}

async function device(port: number, store: Store) {
  const vault = await loadVault(store);
  assert.equal(vault.status, "ready");
  const { keys, integrity, storage } = vault as Unlocked;
  const [history, trust] = await Promise.all([
    History.open(store, keys, integrity, storage),
    Trust.open(store, integrity),
  ]);
  return { ...(await connect(port, keys, trust, history)), trust };
}

async function keysWith(identity?: IdentityKey): Promise<Keys> {
  return {
    identity: identity ?? (await IdentityKey.generate()),
    exchange: await ExchangeKey.generate(),
  };
}

async function own(keys: Keys) {
  const print = await fingerprint(
    keys.identity.identity,
    keys.exchange.publicKey,
  );
  assert.ok(print);
  return print;
}

function thread(conversations: Conversations, peer: string): (string | null)[] {
  return (
    conversations.state.conversations
      .find((c) => c.identity === peer)
      ?.messages.map((m) => m.body) ?? []
  );
}

test("verify, detect a key change, and re-verify with a real server", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const storeA = memoryStore();
  let a = await device(port, storeA);
  const bKeys = await keysWith();
  let b = await connect(port, bKeys);
  const idB = bKeys.identity.identity;
  const idA = a.keys.identity.identity;

  assert.equal(a.trust.view(idB).state, "unavailable");
  assert.equal(await a.messenger.lookup(idB), true);
  await until(() => a.trust.view(idB).state === "unverified", "unverified");
  const bPrint = await own(bKeys);
  assert.deepEqual(a.trust.view(idB).current, bPrint);
  assert.equal(b.conversations.state.connected, true);

  assert.equal(await a.trust.verify(idB, bPrint.value), true);
  assert.equal(a.trust.view(idB).state, "verified");

  a.conversations.open(idB);
  const first = a.conversations.send("verified hello");
  assert.ok(first.accepted);
  if (first.accepted) {
    assert.equal(await first.delivery, "delivered");
  }
  await until(() => thread(b.conversations, idA).length === 1, "b receives");
  assert.deepEqual(thread(b.conversations, idA), ["verified hello"]);
  b.conversations.open(idA);
  const reply = b.conversations.send("reply");
  assert.ok(reply.accepted);
  await until(() => thread(a.conversations, idB).length === 2, "a receives");
  assert.equal(a.trust.view(idB).state, "verified");

  await a.shutdown();
  a = await device(port, storeA);
  assert.equal(a.trust.view(idB).state, "unavailable");
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "verified", "reload");
  assert.deepEqual(thread(a.conversations, idB), ["verified hello", "reply"]);

  await stopServer(server);
  await until(() => !a.conversations.state.connected, "disconnected");
  assert.equal(a.trust.view(idB).state, "verified");
  await startServer(port);
  await until(
    () => a.conversations.state.connected && b.conversations.state.connected,
    "reconnected",
  );
  assert.equal(await a.messenger.lookup(idB), true);
  assert.equal(a.trust.view(idB).state, "verified");

  await b.shutdown();
  const rotatedKeys = await keysWith(bKeys.identity);
  b = await connect(port, rotatedKeys);
  const rotated = await own(rotatedKeys);
  assert.notEqual(rotated.value, bPrint.value);

  b.conversations.open(idA);
  const changedMessage = b.conversations.send("from the new key");
  assert.ok(changedMessage.accepted);
  await until(
    () => thread(a.conversations, idB).length === 3,
    "a receives from new key",
  );
  await until(() => a.trust.view(idB).state === "changed", "changed");
  assert.deepEqual(a.trust.view(idB).current, rotated);
  assert.deepEqual(a.trust.view(idB).verified, bPrint);
  assert.equal(
    a.conversations.state.conversations.find((c) => c.identity === idB)?.unread,
    1,
  );
  assert.equal(await a.trust.verify(idB, bPrint.value), false);

  await a.trust.flush();
  await a.shutdown();
  a = await device(port, storeA);
  assert.equal(a.trust.view(idB).state, "changed");
  await a.messenger.lookup(idB);
  await until(
    () => a.trust.view(idB).current?.value === rotated.value,
    "observed rotated key",
  );
  assert.equal(a.trust.view(idB).state, "changed");
  assert.deepEqual(thread(a.conversations, idB), [
    "verified hello",
    "reply",
    "from the new key",
  ]);

  assert.equal(await a.trust.verify(idB, rotated.value), true);
  assert.equal(a.trust.view(idB).state, "verified");
  a.conversations.open(idB);
  const after = a.conversations.send("after re-verification");
  assert.ok(after.accepted);
  if (after.accepted) {
    assert.equal(await after.delivery, "delivered");
  }
  await until(() => thread(b.conversations, idA).length === 1, "b2 receives");

  for (const frame of [...a.frames, ...b.frames]) {
    for (const secret of [
      "verified hello",
      "from the new key",
      "after re-verification",
    ]) {
      assert.ok(!frame.includes(secret), "plaintext crossed the wire");
    }
    assert.ok(!frame.includes(bPrint.value) && !frame.includes(rotated.value));
    assert.ok(
      !/verif|trust|fingerprint/i.test(
        frame.replace(/"[A-Za-z0-9_-]{20,}"/g, ""),
      ),
    );
  }
});

test("verification is independent of sessions, connections, and presence", async () => {
  const port = await freePort();
  await startServer(port);
  const storeA = memoryStore();
  const a = await device(port, storeA);
  const bKeys = await keysWith();
  const b1 = await connect(port, bKeys);
  const b2 = await connect(port, bKeys);
  const idB = bKeys.identity.identity;

  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "unverified", "observed");
  assert.equal(await a.trust.verify(idB, (await own(bKeys)).value), true);
  await b1.shutdown();
  await a.messenger.lookup(idB);
  assert.equal(a.trust.view(idB).state, "verified");
  await b2.shutdown();
  const deadline = Date.now() + 5000;
  while (await a.messenger.lookup(idB)) {
    assert.ok(Date.now() < deadline);
  }
  assert.equal(a.trust.view(idB).state, "verified");
  const b3 = await connect(port, bKeys);
  assert.equal(await a.messenger.lookup(idB), true);
  assert.equal(a.trust.view(idB).state, "verified");
  await b3.shutdown();
});

test("another client's verification never changes local trust", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port, memoryStore());
  const c = await device(port, memoryStore());
  const bKeys = await keysWith();
  await connect(port, bKeys);
  const idB = bKeys.identity.identity;
  const bPrint = await own(bKeys);

  await c.messenger.lookup(idB);
  await until(() => c.trust.view(idB).state === "unverified", "c observed");
  assert.equal(await c.trust.verify(idB, bPrint.value), true);
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "unverified", "a observed");
  assert.equal(a.trust.view(idB).state, "unverified");
  await a.messenger.lookup(c.keys.identity.identity);
  await until(
    () => a.trust.view(c.keys.identity.identity).state === "unverified",
    "a sees c unverified",
  );
});

test("verification survives ephemeral rotation and fresh sessions but not a key change", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port, memoryStore());
  const bKeys = await keysWith();
  const options = { rotationLimit: 2, previousLimit: 1 };
  let b = await connect(port, bKeys, undefined, undefined, options);
  const idA = a.keys.identity.identity;
  const idB = bKeys.identity.identity;
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "unverified", "observed");
  assert.equal(await a.trust.verify(idB, (await own(bKeys)).value), true);

  b.conversations.open(idA);
  for (let i = 0; i < 8; i++) {
    const attempt = b.conversations.send(`rotating ${i}`);
    assert.ok(attempt.accepted);
    if (attempt.accepted) {
      assert.equal(await attempt.delivery, "delivered");
    }
    await until(() => thread(a.conversations, idB).length === i + 1, `rx ${i}`);
    assert.equal(a.trust.view(idB).state, "verified");
  }
  const offers = b.frames
    .map((f) => JSON.parse(f))
    .filter((f) => f.type === "session")
    .map((f) => f.payload);
  assert.ok(offers.length >= 4);
  assert.equal(new Set(offers.map((o) => o.key)).size, offers.length);
  assert.ok(offers.every((o) => o.session === offers[0].session));

  const firstSession = offers[0].session;
  await b.shutdown();
  b = await connect(port, bKeys, undefined, undefined, options);
  const fresh = b.frames
    .map((f) => JSON.parse(f))
    .filter((f) => f.type === "session")
    .map((f) => f.payload);
  assert.notEqual(fresh[0].session, firstSession);
  assert.equal(fresh[0].epoch, 0);
  b.conversations.open(idA);
  const again = b.conversations.send("fresh session");
  assert.ok(again.accepted);
  await until(() => thread(a.conversations, idB).length === 9, "fresh rx");
  await a.messenger.lookup(idB);
  assert.equal(a.trust.view(idB).state, "verified");

  await b.shutdown();
  const changed = await keysWith(bKeys.identity);
  b = await connect(port, changed, undefined, undefined, options);
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "changed", "changed");
  assert.equal(await a.trust.verify(idB, (await own(changed)).value), true);
  assert.equal(a.trust.view(idB).state, "verified");
});
