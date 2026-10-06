import assert from "node:assert/strict";
import { test } from "node:test";
import { Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import { IdentityKey } from "./identity.ts";
import { Messenger, type MessengerState, maxReceived } from "./messenger.ts";
import { maxBodySize } from "./protocol.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  created,
  freePort,
  openSockets,
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
  auth: Authenticator;
  messenger: Messenger;
  log: MessengerState[];
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
  const log: MessengerState[] = [];
  messenger.onState((state) => log.push(state));
  auth.start();
  messenger.start();
  client.open();
  await until(() => messenger.state.active, "messenger active");
  return {
    client,
    key: identity,
    auth,
    messenger,
    log,
    socket: created[before],
  };
}

function bodies(p: Peer): string[] {
  return p.messenger.state.received.map((message) => message.body);
}

async function barrier(p: Peer): Promise<void> {
  const reply = await p.client.request({
    type: "ping",
    payload: { sentAt: 1 },
  });
  assert.equal(reply?.type, "pong");
}

function sentFrames(p: Peer): string[] {
  const frames: string[] = [];
  const send = p.socket.send.bind(p.socket);
  p.socket.send = (data: string) => {
    frames.push(data);
    send(data);
  };
  return frames;
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

  const result = await messenger.send("B".repeat(42) + "A", "x");

  assert.deepEqual(result, { ok: false, reason: "authentication_required" });
  assert.deepEqual(messenger.state, { active: false, received: [] });
  assert.equal(created.length, 0);
});

test("delivers a message from the authenticated sender", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);

  assert.deepEqual(await a.messenger.send(b.key.identity, "hello"), {
    ok: true,
  });
  await until(() => b.messenger.state.received.length === 1, "delivery");

  assert.equal(b.messenger.state.received[0].from, a.key.identity);
  assert.equal(b.messenger.state.received[0].body, "hello");
  await barrier(a);
  assert.equal(a.messenger.state.received.length, 0);
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

  assert.deepEqual(await a.messenger.send(bKey.identity, "one"), { ok: true });
  assert.deepEqual(await a.messenger.send(bKey.identity, "two"), { ok: true });
  for (const b of [b1, b2]) {
    await until(() => b.messenger.state.received.length >= 2, "deliveries");
    await barrier(b);
    assert.deepEqual(
      b.messenger.state.received.map((m) => m.body),
      ["one", "two"],
    );
  }
  await barrier(aOther);
  await barrier(a);
  assert.equal(a.messenger.state.received.length, 0);
  assert.equal(aOther.messenger.state.received.length, 0);
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
  const frames = sentFrames(a);

  assert.deepEqual(await a.messenger.send("not-an-identity", "x"), {
    ok: false,
    reason: "invalid_payload",
  });
  assert.deepEqual(await a.messenger.send(b.key.identity, ""), {
    ok: false,
    reason: "invalid_payload",
  });
  assert.deepEqual(await a.messenger.send(b.key.identity, "a\u0000b"), {
    ok: false,
    reason: "invalid_payload",
  });
  assert.deepEqual(
    await a.messenger.send(b.key.identity, "a".repeat(maxBodySize + 1)),
    { ok: false, reason: "message_too_large" },
  );
  assert.deepEqual(frames, []);
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
    {
      code: "authentication_required",
    },
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
  assert.equal(b.messenger.state.received.length, 0);
});

test("ignores malformed and unexpected delivery frames", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const count = a.log.length;
  const inject = (data: unknown) =>
    a.socket.dispatchEvent(
      new MessageEvent("message", { data: JSON.stringify(data) }),
    );

  inject({ type: "message", payload: { from: "short", body: "x" } });
  inject({
    type: "message",
    id: "m1",
    payload: { from: a.key.identity, body: "x" },
  });
  inject({ type: "message", payload: { from: a.key.identity, body: "" } });
  inject({ type: "message", payload: { from: a.key.identity } });
  a.socket.dispatchEvent(new MessageEvent("message", { data: "not json" }));

  assert.equal(a.log.length, count);
  assert.deepEqual(a.messenger.state.received, []);
});

test("clears state on disconnect and ignores stale deliveries", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  await a.messenger.send(b.key.identity, "before");
  await until(() => b.messenger.state.received.length === 1, "delivery");

  await stopServer(server);
  await until(() => !b.messenger.state.active, "inactive");
  assert.deepEqual(b.messenger.state.received, []);
  b.socket.dispatchEvent(
    new MessageEvent("message", {
      data: JSON.stringify({
        type: "message",
        payload: { from: a.key.identity, body: "stale" },
      }),
    }),
  );
  assert.deepEqual(b.messenger.state, { active: false, received: [] });
  assert.deepEqual(await b.messenger.send(a.key.identity, "x"), {
    ok: false,
    reason: "authentication_required",
  });

  await startServer(port);
  await until(() => a.messenger.state.active, "a re-authenticated");
  await until(() => b.messenger.state.active, "b re-authenticated");
  assert.deepEqual(await a.messenger.send(b.key.identity, "after"), {
    ok: true,
  });
  await until(() => b.messenger.state.received.length === 1, "redelivery");
  assert.deepEqual(bodies(b), ["after"]);
  assert.equal(openSockets().length, 2);
});

test("stop releases listeners and starts only once", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  b.messenger.start();
  b.messenger.start();

  await a.messenger.send(b.key.identity, "once");
  await until(() => b.messenger.state.received.length === 1, "delivery");
  await barrier(b);
  assert.equal(b.messenger.state.received.length, 1);

  b.messenger.stop();
  assert.deepEqual(b.messenger.state, { active: false, received: [] });
  const count = b.log.length;
  assert.deepEqual(await a.messenger.send(b.key.identity, "after stop"), {
    ok: true,
  });
  await barrier(b);
  assert.equal(b.log.length, count);
  assert.deepEqual(b.messenger.state, { active: false, received: [] });
});

test("bounds the received list", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);

  for (let i = 0; i < maxReceived + 5; i++) {
    assert.deepEqual(await a.messenger.send(b.key.identity, `m${i}`), {
      ok: true,
    });
  }
  await until(
    () => b.messenger.state.received.at(-1)?.body === `m${maxReceived + 4}`,
    "last delivery",
  );

  assert.equal(b.messenger.state.received.length, maxReceived);
  assert.equal(b.messenger.state.received[0].body, "m5");
});
