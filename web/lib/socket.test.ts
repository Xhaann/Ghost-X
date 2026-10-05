import assert from "node:assert/strict";
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, before, test } from "node:test";
import { fileURLToPath } from "node:url";
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

test("reports failure when the server is unavailable", async () => {
  const port = await freePort();
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  const states = track(socket);

  socket.open();
  await waitFor(socket, "disconnected");

  assert.deepEqual(states, ["connecting", "disconnected"]);
});

test("detects server shutdown", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const socket = new Socket(`ws://127.0.0.1:${port}/ws`);
  const states = track(socket);

  socket.open();
  await waitFor(socket, "connected");
  await stopServer(server);
  await waitFor(socket, "disconnected");

  assert.deepEqual(states, ["connecting", "connected", "disconnected"]);
});
