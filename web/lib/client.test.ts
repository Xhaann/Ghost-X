import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "./client.ts";
import type { ServerMessage } from "./protocol.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  created,
  freePort,
  openSockets,
  record,
  sleep,
  startServer,
  stopServer,
  track,
  useServer,
  waitFor,
  waitForCount,
} from "./testing.ts";
import type { TransportError } from "./transport.ts";

useServer();

function websocket(port: number): WebSocketTransport {
  return track(
    new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
  );
}

function collect(client: Client): ServerMessage[] {
  const messages: ServerMessage[] = [];
  client.onMessage((message) => messages.push(message));
  return messages;
}

async function connected(port: number): Promise<Client> {
  const client = track(new Client(websocket(port)));
  client.open();
  await waitFor(client, "connected");
  return client;
}

test("does not send while disconnected", async () => {
  const port = await freePort();
  const client = track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, {
          minDelay: 5000,
        }),
      ),
    ),
  );

  assert.equal(client.send({ type: "ping", payload: { sentAt: 1 } }), null);
  client.open();
  assert.equal(client.send({ type: "ping", payload: { sentAt: 1 } }), null);
});

test("receives a pong for a ping", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const messages = collect(client);

  const sentAt = Date.now();
  const id = client.send({ type: "ping", payload: { sentAt } });
  assert.ok(id);
  await waitForCount(messages, 1);

  const [message] = messages;
  assert.equal(message.type, "pong");
  assert.equal(message.id, id);
  assert.ok(message.type === "pong");
  assert.equal(message.payload.sentAt, sentAt);
  assert.ok(message.payload.receivedAt >= sentAt - 1000);
});

test("correlates concurrent requests", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const messages = collect(client);

  const ids = Array.from({ length: 20 }, (_, i) =>
    client.send({ type: "ping", payload: { sentAt: i } }),
  );
  await waitForCount(messages, ids.length);

  assert.deepEqual(
    messages.map((message) => message.id),
    ids,
  );
  assert.equal(new Set(ids).size, ids.length);
});

test("receives protocol errors from the server", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const messages = collect(client);

  const id = client.send({ type: "ping", payload: { sentAt: -1 } });
  await waitForCount(messages, 1);

  assert.deepEqual(messages, [
    { type: "error", id, payload: { code: "invalid_payload" } },
  ]);
  assert.equal(client.state, "connected");
});

test("stops delivering messages after unsubscribe", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const kept = collect(client);
  const removed: ServerMessage[] = [];
  const unsubscribe = client.onMessage((message) => removed.push(message));

  unsubscribe();
  unsubscribe();
  client.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForCount(kept, 1);
  await sleep(50);

  assert.equal(kept.length, 1);
  assert.equal(removed.length, 0);
});

test("drops replies that arrive after close", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const messages = collect(client);

  client.send({ type: "ping", payload: { sentAt: 1 } });
  client.close();
  await sleep(200);

  assert.equal(messages.length, 0);
  assert.equal(client.state, "disconnected");
});

test("delivers each message once across reconnects", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const client = await connected(port);
  const messages = collect(client);
  const states = record(client);

  client.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForCount(messages, 1);

  await stopServer(server);
  await waitFor(client, "reconnecting");
  await startServer(port);
  await waitFor(client, "connected");

  const id = client.send({ type: "ping", payload: { sentAt: 2 } });
  await waitForCount(messages, 2);
  await sleep(100);

  assert.equal(messages.length, 2);
  assert.equal(messages[1].id, id);
  assert.deepEqual(states, ["reconnecting", "connected"]);
  assert.equal(openSockets().length, 1);
});

test("delivers messages after an intentional reopen", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const messages = collect(client);

  client.close();
  client.open();
  await waitFor(client, "connected");
  client.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForCount(messages, 1);
  await sleep(100);

  assert.equal(messages.length, 1);
  assert.equal(openSockets().length, 1);
});

test("forwards transport errors", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const client = await connected(port);
  const errors: TransportError[] = [];
  client.onError((error) => errors.push(error));

  await stopServer(server);
  await waitForCount(errors, 1);

  assert.equal(errors[0], "lost");
});

test("forwards retry to the active transport", async () => {
  const port = await freePort();
  const client = track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, {
          minDelay: 60000,
        }),
      ),
    ),
  );

  client.open();
  await waitFor(client, "reconnecting");
  await startServer(port);
  client.retry();
  await waitFor(client, "connected");

  assert.equal(created.length, 2);
});

test("keeps exactly one active transport when selecting", async () => {
  const port = await freePort();
  await startServer(port);
  const first = websocket(port);
  const second = websocket(port);
  const client = track(new Client(first));
  const messages = collect(client);
  const states = record(client);

  client.open();
  await waitFor(client, "connected");
  client.select(second);
  await waitFor(client, "connected");

  assert.equal(first.state, "disconnected");
  assert.equal(second.state, "connected");
  await sleep(100);
  assert.equal(openSockets().length, 1);

  const id = client.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForCount(messages, 1);
  assert.equal(messages[0].id, id);

  first.open();
  await waitFor(first, "connected");
  await sleep(50);
  assert.deepEqual(states, [
    "connecting",
    "connected",
    "disconnected",
    "connecting",
    "connected",
  ]);
});

test("does not open a selected transport while closed", async () => {
  const port = await freePort();
  await startServer(port);
  const first = websocket(port);
  const second = websocket(port);
  const client = track(new Client(first));

  client.select(second);
  await sleep(100);

  assert.equal(client.state, "disconnected");
  assert.equal(created.length, 0);
});

test("ignores selecting the active transport", async () => {
  const port = await freePort();
  await startServer(port);
  const transport = websocket(port);
  const client = track(new Client(transport));

  client.open();
  await waitFor(client, "connected");
  client.select(transport);
  await sleep(100);

  assert.equal(client.state, "connected");
  assert.equal(created.length, 1);
});

test("drops malformed data from the transport", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const messages = collect(client);
  const [socket] = openSockets();

  for (const data of [
    "not json",
    "{}",
    '{"type":"pong","id":"x"}',
    '{"type":"unknown","id":"x","payload":{}}',
    '{"type":"error","payload":{"code":"secret"}}',
  ]) {
    socket.dispatchEvent(new MessageEvent("message", { data }));
  }
  const id = client.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForCount(messages, 1);
  await sleep(50);

  assert.equal(messages.length, 1);
  assert.equal(messages[0].id, id);
  assert.equal(client.state, "connected");
});

test("correlates a request with its reply", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);

  const [first, second] = await Promise.all([
    client.request({ type: "ping", payload: { sentAt: 1 } }),
    client.request({ type: "ping", payload: { sentAt: 2 } }),
  ]);

  assert.equal(first?.type, "pong");
  assert.equal(second?.type, "pong");
  assert.ok(first?.type === "pong" && second?.type === "pong");
  assert.equal(first.payload.sentAt, 1);
  assert.equal(second.payload.sentAt, 2);
});

test("resolves a request with null when it cannot be sent", async () => {
  const port = await freePort();
  const client = track(new Client(websocket(port)));

  assert.equal(
    await client.request({ type: "ping", payload: { sentAt: 1 } }),
    null,
  );
});

test("resolves a pending request with null when the connection closes", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);

  const reply = client.request({ type: "ping", payload: { sentAt: 1 } });
  client.close();

  assert.equal(await reply, null);
});

test("resolves a request with null on timeout", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const [socket] = openSockets();
  socket.onmessage = null;

  const started = Date.now();
  const reply = await client.request(
    { type: "ping", payload: { sentAt: 1 } },
    100,
  );

  assert.equal(reply, null);
  assert.ok(Date.now() - started >= 90);
});
