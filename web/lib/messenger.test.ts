import assert from "node:assert/strict";
import { test } from "node:test";
import { Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import { IdentityKey } from "./identity.ts";
import { type Incoming, Messenger, type MessengerState } from "./messenger.ts";
import { maxBodySize } from "./protocol.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  created,
  freePort,
  startServer,
  stopServer,
  track,
  useServer,
  waitFor,
} from "./testing.ts";

useServer();

type Peer = {
  client: Client;
  key: IdentityKey;
  messenger: Messenger;
  inbox: Incoming[];
  states: MessengerState[];
  socket: WebSocket;
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

async function peer(port: number, key?: IdentityKey): Promise<Peer> {
  const before = created.length;
  const client = track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
      ),
    ),
  );
  const identity = key ?? (await IdentityKey.generate());
  const auth = new Authenticator(client, identity);
  const messenger = new Messenger(client, auth);
  track({ close: () => messenger.stop() });
  track({ close: () => auth.stop() });
  const inbox: Incoming[] = [];
  const states: MessengerState[] = [];
  messenger.onMessage((message) => inbox.push(message));
  messenger.onState((state) => states.push(state));
  auth.start();
  messenger.start();
  client.open();
  await until(() => messenger.state.active, "messenger active");
  return {
    client,
    key: identity,
    messenger,
    inbox,
    states,
    socket: created[before],
  };
}

async function barrier(p: Peer): Promise<void> {
  const reply = await p.client.request({
    type: "ping",
    payload: { sentAt: 1 },
  });
  assert.equal(reply?.type, "pong");
}

test("refuses to send before authentication", async () => {
  const port = await freePort();
  const client = track(
    new Client(track(new WebSocketTransport(`ws://127.0.0.1:${port}/ws`))),
  );
  const auth = new Authenticator(client, await IdentityKey.generate());
  const messenger = new Messenger(client, auth);
  track({ close: () => messenger.stop() });
  messenger.start();

  assert.deepEqual(await messenger.send("B".repeat(42) + "A", "x"), {
    ok: false,
    reason: "authentication_required",
  });
  assert.deepEqual(messenger.state, { active: false });
  assert.equal(created.length, 0);
});

test("delivers a message with the caller's id and the session sender", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);

  assert.deepEqual(await a.messenger.send(b.key.identity, "hello", "m1"), {
    ok: true,
  });
  await until(() => b.inbox.length === 1, "delivery");

  assert.deepEqual(b.inbox, [
    { id: "m1", from: a.key.identity, body: "hello" },
  ]);
  await barrier(a);
  assert.deepEqual(a.inbox, []);
});

test("delivers once to each session of the recipient", async () => {
  const port = await freePort();
  await startServer(port);
  const aKey = await IdentityKey.generate();
  const bKey = await IdentityKey.generate();
  const a = await peer(port, aKey);
  const aOther = await peer(port, aKey);
  const b1 = await peer(port, bKey);
  const b2 = await peer(port, bKey);

  await a.messenger.send(bKey.identity, "one", "m1");
  await a.messenger.send(bKey.identity, "two", "m2");
  for (const b of [b1, b2]) {
    await until(() => b.inbox.length >= 2, "deliveries");
    await barrier(b);
    assert.deepEqual(
      b.inbox.map((m) => m.id),
      ["m1", "m2"],
    );
  }
  await barrier(aOther);
  assert.deepEqual(aOther.inbox, []);
});

test("reports an unavailable recipient", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const absent = await IdentityKey.generate();

  assert.deepEqual(await a.messenger.send(absent.identity, "x"), {
    ok: false,
    reason: "recipient_unavailable",
  });
});

test("rejects invalid input without sending a frame", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const frames: string[] = [];
  const send = a.socket.send.bind(a.socket);
  a.socket.send = (data: string) => {
    frames.push(data);
    send(data);
  };

  for (const [to, body, id, reason] of [
    ["not-an-identity", "x", "m1", "invalid_payload"],
    [b.key.identity, "", "m1", "invalid_payload"],
    [b.key.identity, "a\u0000b", "m1", "invalid_payload"],
    [b.key.identity, "x", "bad id", "invalid_payload"],
    [b.key.identity, "a".repeat(maxBodySize + 1), "m1", "message_too_large"],
  ] as const) {
    assert.deepEqual(await a.messenger.send(to, body, id), {
      ok: false,
      reason,
    });
  }
  assert.deepEqual(frames, []);
});

test("emits nothing while inactive and nothing after stop", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const a = await peer(port);
  const b = await peer(port);

  await stopServer(server);
  await until(() => !b.messenger.state.active, "inactive");
  b.socket.dispatchEvent(
    new MessageEvent("message", {
      data: JSON.stringify({
        type: "message",
        payload: { id: "m9", from: a.key.identity, body: "stale" },
      }),
    }),
  );
  assert.deepEqual(b.inbox, []);

  await startServer(port);
  await until(
    () => a.messenger.state.active && b.messenger.state.active,
    "re-authenticated",
  );
  b.messenger.stop();
  b.messenger.stop();
  assert.deepEqual(await a.messenger.send(b.key.identity, "after stop"), {
    ok: true,
  });
  await barrier(b);
  assert.deepEqual(b.inbox, []);
  assert.deepEqual(b.states.at(-1), { active: false });
});

test("starts only once", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  b.messenger.start();
  b.messenger.start();

  await a.messenger.send(b.key.identity, "once", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  await barrier(b);

  assert.equal(b.inbox.length, 1);
});

test("server rejects unauthenticated and forged sends", async () => {
  const port = await freePort();
  await startServer(port);
  const b = await peer(port);
  const c = await IdentityKey.generate();
  const client = track(
    new Client(track(new WebSocketTransport(`ws://127.0.0.1:${port}/ws`))),
  );
  client.open();
  await waitFor(client, "connected");

  const unauthenticated = await client.request({
    type: "send",
    payload: { to: b.key.identity, body: "x" },
  });
  assert.deepEqual(
    unauthenticated?.type === "error" && unauthenticated.payload,
    { code: "authentication_required" },
  );

  const a = await peer(port);
  const forged = new Promise((resolve) => {
    const release = a.client.onMessage((message) => {
      if (message.id === "forged1") {
        release();
        resolve(message);
      }
    });
  });
  a.socket.send(
    JSON.stringify({
      type: "send",
      id: "forged1",
      payload: { to: b.key.identity, body: "x", from: c.identity },
    }),
  );
  assert.deepEqual(await forged, {
    type: "error",
    id: "forged1",
    payload: { code: "invalid_payload" },
  });
  await barrier(b);
  assert.deepEqual(b.inbox, []);
});
