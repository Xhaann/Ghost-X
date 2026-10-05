import assert from "node:assert/strict";
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import type { ServerMessage } from "./protocol.ts";
import { Socket, type SocketState } from "./socket.ts";

const NativeWebSocket = globalThis.WebSocket;
const created: WebSocket[] = [];

class TrackedWebSocket extends NativeWebSocket {
  constructor(url: string | URL, protocols?: string | string[]) {
    super(url, protocols);
    created.push(this);
  }
}

let workdir = "";
let binary = "";
const servers = new Set<ChildProcess>();
const sockets = new Set<Socket>();

before(() => {
  globalThis.WebSocket = TrackedWebSocket;
  workdir = mkdtempSync(join(tmpdir(), "ghostx-"));
  binary = join(workdir, "server");
  const serverDir = fileURLToPath(new URL("../../server", import.meta.url));
  execFileSync("go", ["build", "-o", binary, "."], { cwd: serverDir });
});

afterEach(async () => {
  for (const socket of sockets) {
    socket.close();
  }
  sockets.clear();
  created.length = 0;
  await Promise.all([...servers].map(stopServer));
});

after(() => {
  globalThis.WebSocket = NativeWebSocket;
  rmSync(workdir, { recursive: true, force: true });
});

async function freePort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  server.close();
  await once(server, "close");
  assert.ok(address && typeof address === "object");
  return address.port;
}

async function startServer(port: number): Promise<ChildProcess> {
  const server = spawn(binary, [], {
    env: { ...process.env, SERVER_ADDR: `127.0.0.1:${port}` },
    stdio: "ignore",
  });
  servers.add(server);
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (response.status === 204) {
        return server;
      }
    } catch {}
    await sleep(20);
  }
  throw new Error("server did not start");
}

async function stopServer(server: ChildProcess): Promise<void> {
  servers.delete(server);
  if (server.exitCode !== null || server.signalCode !== null) {
    return;
  }
  const exited = once(server, "exit");
  server.kill("SIGTERM");
  await exited;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function track(socket: Socket): SocketState[] {
  sockets.add(socket);
  const states: SocketState[] = [];
  socket.subscribe((state) => states.push(state));
  return states;
}

async function waitFor(socket: Socket, state: SocketState): Promise<void> {
  const deadline = Date.now() + 5000;
  while (socket.state !== state) {
    if (Date.now() > deadline) {
      throw new Error(
        `timed out waiting for ${state}, state is ${socket.state}`,
      );
    }
    await sleep(10);
  }
}

function openSockets(): WebSocket[] {
  return created.filter(
    (ws) =>
      ws.readyState === NativeWebSocket.CONNECTING ||
      ws.readyState === NativeWebSocket.OPEN,
  );
}

test("starts disconnected without creating a connection", () => {
  const socket = new Socket("ws://127.0.0.1:1/ws");
  track(socket);
  assert.equal(socket.state, "disconnected");
  assert.equal(created.length, 0);
});

test("connects to the server", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  const states = track(socket);

  socket.open();
  await waitFor(socket, "connected");

  assert.deepEqual(states, ["connecting", "connected"]);
  assert.equal(created.length, 1);
});

test("ignores repeated open calls", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  track(socket);

  socket.open();
  socket.open();
  await waitFor(socket, "connected");
  socket.open();

  assert.equal(created.length, 1);
  assert.equal(openSockets().length, 1);
});

test("closes intentionally", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  const states = track(socket);

  socket.open();
  await waitFor(socket, "connected");
  socket.close();

  assert.equal(socket.state, "disconnected");
  assert.deepEqual(states, ["connecting", "connected", "disconnected"]);
  await sleep(100);
  assert.equal(openSockets().length, 0);
  assert.equal(socket.state, "disconnected");
});

test("closes while connecting", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  const states = track(socket);

  socket.open();
  socket.close();
  await sleep(200);

  assert.deepEqual(states, ["connecting", "disconnected"]);
  assert.equal(openSockets().length, 0);
});

test("stops notifying after unsubscribe", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  sockets.add(socket);
  const states: SocketState[] = [];
  const unsubscribe = socket.subscribe((state) => states.push(state));

  socket.open();
  unsubscribe();
  await waitFor(socket, "connected");

  assert.deepEqual(states, ["connecting"]);
});

test("rejects an invalid url without throwing", () => {
  const socket = new Socket("not a url");
  const states = track(socket);

  socket.open();

  assert.equal(socket.state, "disconnected");
  assert.deepEqual(states, []);
  assert.equal(created.length, 0);
});

test("retries when the server is unavailable", async () => {
  const port = await freePort();
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 5000 });
  const states = track(socket);

  socket.open();
  await waitFor(socket, "reconnecting");
  await sleep(100);

  assert.deepEqual(states, ["connecting", "reconnecting"]);
  assert.equal(created.length, 1);
});

test("detects server shutdown", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  const states = track(socket);

  socket.open();
  await waitFor(socket, "connected");
  await stopServer(server);
  await waitFor(socket, "reconnecting");

  assert.deepEqual(states, ["connecting", "connected", "reconnecting"]);
});

test("reconnects after the server restarts", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 });
  const states = track(socket);

  socket.open();
  await waitFor(socket, "connected");
  await stopServer(server);
  await waitFor(socket, "reconnecting");
  await sleep(300);
  await startServer(port);
  await waitFor(socket, "connected");

  assert.deepEqual(states, [
    "connecting",
    "connected",
    "reconnecting",
    "connected",
  ]);
  assert.equal(openSockets().length, 1);
});

test("connects once the server becomes available", async () => {
  const port = await freePort();
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 });
  const states = track(socket);

  socket.open();
  await waitFor(socket, "reconnecting");
  await startServer(port);
  await waitFor(socket, "connected");

  assert.deepEqual(states, ["connecting", "reconnecting", "connected"]);
});

test("backs off between attempts without overlapping", async () => {
  const port = await freePort();
  const minDelay = 40;
  const maxDelay = 160;
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, {
    minDelay,
    maxDelay,
  });
  track(socket);
  const times: number[] = [];
  let seen = 0;
  let maxOpen = 0;

  socket.open();
  const deadline = Date.now() + 1500;
  while (Date.now() < deadline) {
    while (seen < created.length) {
      times.push(performance.now());
      seen += 1;
    }
    maxOpen = Math.max(maxOpen, openSockets().length);
    await sleep(2);
  }

  assert.ok(times.length >= 4, `attempts = ${times.length}`);
  assert.ok(times.length <= 20, `attempts = ${times.length}`);
  assert.equal(maxOpen, 1);
  for (let i = 1; i < times.length; i++) {
    const ceiling = Math.min(maxDelay, minDelay * 2 ** (i - 1));
    const gap = times[i] - times[i - 1];
    assert.ok(gap >= ceiling / 2 - 5, `gap ${i} = ${gap}ms`);
    assert.ok(gap <= maxDelay + 100, `gap ${i} = ${gap}ms`);
  }
});

test("resets backoff after a successful connection", async () => {
  const port = await freePort();
  const minDelay = 50;
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, {
    minDelay,
    maxDelay: 5000,
  });
  track(socket);

  socket.open();
  await waitFor(socket, "reconnecting");
  await sleep(800);
  const server = await startServer(port);
  await waitFor(socket, "connected");

  const before = created.length;
  const stoppedAt = performance.now();
  await stopServer(server);
  while (created.length === before) {
    assert.ok(performance.now() - stoppedAt < 300, "retry was not reset");
    await sleep(2);
  }
});

test("cancels a pending retry on close", async () => {
  const port = await freePort();
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 100 });
  const states = track(socket);

  socket.open();
  await waitFor(socket, "reconnecting");
  socket.close();
  await startServer(port);
  await sleep(400);

  assert.deepEqual(states, ["connecting", "reconnecting", "disconnected"]);
  assert.equal(created.length, 1);
});

test("stops reconnecting after an intentional close", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 });
  track(socket);

  socket.open();
  await waitFor(socket, "connected");
  socket.close();
  await stopServer(server);
  await startServer(port);
  await sleep(300);

  assert.equal(socket.state, "disconnected");
  assert.equal(created.length, 1);
});

test("retries immediately on request", async () => {
  const port = await freePort();
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 60000 });
  track(socket);

  socket.open();
  await waitFor(socket, "reconnecting");
  await sleep(50);
  await startServer(port);
  socket.retry();
  await waitFor(socket, "connected");
  socket.retry();

  assert.equal(created.length, 2);
  assert.equal(openSockets().length, 1);
});

test("ignores retry when not reconnecting", () => {
  const socket = new Socket("ws://127.0.0.1:1/ws");
  track(socket);

  socket.retry();

  assert.equal(socket.state, "disconnected");
  assert.equal(created.length, 0);
});

test("reopens after an intentional close", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  const states = track(socket);

  socket.open();
  await waitFor(socket, "connected");
  socket.close();
  socket.open();
  await waitFor(socket, "connected");

  assert.deepEqual(states, [
    "connecting",
    "connected",
    "disconnected",
    "connecting",
    "connected",
  ]);
  await sleep(100);
  assert.equal(openSockets().length, 1);
});

function collect(socket: Socket): ServerMessage[] {
  const messages: ServerMessage[] = [];
  socket.onMessage((message) => messages.push(message));
  return messages;
}

async function waitForMessages(
  messages: ServerMessage[],
  count: number,
): Promise<void> {
  const deadline = Date.now() + 5000;
  while (messages.length < count) {
    if (Date.now() > deadline) {
      throw new Error(`received ${messages.length} of ${count} messages`);
    }
    await sleep(5);
  }
}

async function connected(port: number): Promise<Socket> {
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 });
  track(socket);
  socket.open();
  await waitFor(socket, "connected");
  return socket;
}

test("does not send while disconnected", async () => {
  const port = await freePort();
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`, { minDelay: 5000 });
  track(socket);

  assert.equal(socket.send({ type: "ping", payload: { sentAt: 1 } }), null);
  socket.open();
  assert.equal(socket.send({ type: "ping", payload: { sentAt: 1 } }), null);
});

test("receives a pong for a ping", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = await connected(port);
  const messages = collect(socket);

  const sentAt = Date.now();
  const id = socket.send({ type: "ping", payload: { sentAt } });
  assert.ok(id);
  await waitForMessages(messages, 1);

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
  const socket = await connected(port);
  const messages = collect(socket);

  const ids = Array.from({ length: 20 }, (_, i) =>
    socket.send({ type: "ping", payload: { sentAt: i } }),
  );
  await waitForMessages(messages, ids.length);

  assert.deepEqual(
    messages.map((message) => message.id),
    ids,
  );
  assert.equal(new Set(ids).size, ids.length);
});

test("receives protocol errors from the server", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = await connected(port);
  const messages = collect(socket);

  const id = socket.send({ type: "ping", payload: { sentAt: -1 } });
  await waitForMessages(messages, 1);

  assert.deepEqual(messages, [
    { type: "error", id, payload: { code: "invalid_payload" } },
  ]);
  assert.equal(socket.state, "connected");
});

test("stops delivering messages after unsubscribe", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = await connected(port);
  const kept = collect(socket);
  const removed: ServerMessage[] = [];
  const unsubscribe = socket.onMessage((message) => removed.push(message));

  unsubscribe();
  unsubscribe();
  socket.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForMessages(kept, 1);
  await sleep(50);

  assert.equal(kept.length, 1);
  assert.equal(removed.length, 0);
});

test("drops replies that arrive after close", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = await connected(port);
  const messages = collect(socket);

  socket.send({ type: "ping", payload: { sentAt: 1 } });
  socket.close();
  await sleep(200);

  assert.equal(messages.length, 0);
});

test("delivers each message once across reconnects", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const socket = await connected(port);
  const messages = collect(socket);

  socket.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForMessages(messages, 1);

  await stopServer(server);
  await waitFor(socket, "reconnecting");
  await startServer(port);
  await waitFor(socket, "connected");

  const id = socket.send({ type: "ping", payload: { sentAt: 2 } });
  await waitForMessages(messages, 2);
  await sleep(100);

  assert.equal(messages.length, 2);
  assert.equal(messages[1].id, id);
  assert.equal(openSockets().length, 1);
});

test("delivers messages after an intentional reopen", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = await connected(port);
  const messages = collect(socket);

  socket.close();
  socket.open();
  await waitFor(socket, "connected");
  socket.send({ type: "ping", payload: { sentAt: 1 } });
  await waitForMessages(messages, 1);
  await sleep(100);

  assert.equal(messages.length, 1);
  assert.equal(openSockets().length, 1);
});
