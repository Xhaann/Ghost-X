import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer } from "node:net";
import { test } from "node:test";
import { WebSocketTransport, type WebSocketOptions } from "./socket.ts";
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
import {
  type TransportError,
  maxBufferedBytes,
  maxFrameSize,
} from "./transport.ts";

useServer();

function transport(port: number, options?: WebSocketOptions) {
  return track(new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, options));
}

test("starts disconnected without creating a connection", () => {
  const socket = track(new WebSocketTransport("ws://127.0.0.1:1/ws"));
  record(socket);
  assert.equal(socket.state, "disconnected");
  assert.equal(created.length, 0);
});

test("connects to the server", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = transport(port);
  const states = record(socket);

  socket.open();
  await waitFor(socket, "connected");

  assert.deepEqual(states, ["connecting", "connected"]);
  assert.equal(created.length, 1);
});

test("ignores repeated open calls", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = transport(port);

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
  const socket = transport(port);
  const states = record(socket);

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
  const socket = transport(port);
  const states = record(socket);

  socket.open();
  socket.close();
  await sleep(200);

  assert.deepEqual(states, ["connecting", "disconnected"]);
  assert.equal(openSockets().length, 0);
});

test("stops notifying after unsubscribe", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = transport(port);
  const states: string[] = [];
  const unsubscribe = socket.onState((state) => states.push(state));

  socket.open();
  unsubscribe();
  await waitFor(socket, "connected");

  assert.deepEqual(states, ["connecting"]);
});

test("rejects an invalid url without throwing", () => {
  const socket = track(new WebSocketTransport("not a url"));
  const states = record(socket);
  const errors: TransportError[] = [];
  socket.onError((error) => errors.push(error));

  socket.open();

  assert.equal(socket.state, "error");
  assert.deepEqual(states, ["error"]);
  assert.deepEqual(errors, ["unavailable"]);
  assert.equal(created.length, 0);
});

test("retries when the server is unavailable", async () => {
  const port = await freePort();
  const socket = transport(port, { minDelay: 5000 });
  const states = record(socket);

  socket.open();
  await waitFor(socket, "reconnecting");
  await sleep(100);

  assert.deepEqual(states, ["connecting", "reconnecting"]);
  assert.equal(created.length, 1);
});

test("detects server shutdown", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const socket = transport(port);
  const states = record(socket);

  socket.open();
  await waitFor(socket, "connected");
  await stopServer(server);
  await waitFor(socket, "reconnecting");

  assert.deepEqual(states, ["connecting", "connected", "reconnecting"]);
});

test("reconnects after the server restarts", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const socket = transport(port, { minDelay: 50 });
  const states = record(socket);

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
  const socket = transport(port, { minDelay: 50 });
  const states = record(socket);

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
  const socket = transport(port, { minDelay, maxDelay });
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
  const socket = transport(port, { minDelay: 50, maxDelay: 5000 });

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
  const socket = transport(port, { minDelay: 100 });
  const states = record(socket);

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
  const socket = transport(port, { minDelay: 50 });

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
  const socket = transport(port, { minDelay: 60000 });

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
  const socket = track(new WebSocketTransport("ws://127.0.0.1:1/ws"));

  socket.retry();

  assert.equal(socket.state, "disconnected");
  assert.equal(created.length, 0);
});

test("reopens after an intentional close", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = transport(port);
  const states = record(socket);

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

test("reports each failed attempt as a failed connection", async () => {
  const port = await freePort();
  const socket = transport(port, { minDelay: 40, maxDelay: 40 });
  const errors: TransportError[] = [];
  socket.onError((error) => errors.push(error));

  socket.open();
  await waitForCount(errors, 2);

  assert.ok(errors.length >= 2, `errors = ${errors.length}`);
  assert.ok(errors.every((error) => error === "failed"));
});

test("reports no error on intentional close", async () => {
  const port = await freePort();
  await startServer(port);
  const socket = transport(port);
  const errors: TransportError[] = [];
  socket.onError((error) => errors.push(error));

  socket.open();
  await waitFor(socket, "connected");
  socket.close();
  await sleep(100);

  assert.deepEqual(errors, []);
});

async function rawPeer(options: { send?: string; read: boolean }) {
  const server = createServer((socket) => {
    let handshake = "";
    const onData = (chunk: Buffer) => {
      handshake += chunk.toString("latin1");
      if (!handshake.includes("\r\n\r\n")) {
        return;
      }
      socket.off("data", onData);
      if (!options.read) {
        socket.pause();
      }
      const key = /Sec-WebSocket-Key: (.+)\r\n/i.exec(handshake)?.[1] ?? "";
      const accept = createHash("sha1")
        .update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
        .digest("base64");
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
      );
      if (options.send !== undefined) {
        const body = Buffer.from(options.send, "utf8");
        const header =
          body.length < 126
            ? Buffer.from([0x81, body.length])
            : body.length < 65536
              ? Buffer.from([0x81, 126, body.length >> 8, body.length & 0xff])
              : Buffer.concat([
                  Buffer.from([0x81, 127, 0, 0, 0, 0]),
                  Buffer.from([
                    (body.length >>> 24) & 0xff,
                    (body.length >>> 16) & 0xff,
                    (body.length >>> 8) & 0xff,
                    body.length & 0xff,
                  ]),
                ]);
        socket.write(Buffer.concat([header, body]));
      }
    };
    socket.on("data", onData);
    socket.on("error", () => {});
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  track({ close: () => server.close() });
  return (server.address() as { port: number }).port;
}

test("drops and reports inbound frames above the frame limit", async () => {
  const port = await rawPeer({
    send: "x".repeat(maxFrameSize + 1),
    read: true,
  });
  const socket = transport(port);
  const errors: TransportError[] = [];
  const received: string[] = [];
  socket.onError((e) => errors.push(e));
  socket.onData((d) => received.push(d));
  socket.open();
  await waitFor(socket, "connected");
  const deadline = Date.now() + 3000;
  while (errors.length === 0 && Date.now() < deadline) {
    await sleep(10);
  }
  assert.deepEqual(errors, ["oversized"]);
  assert.deepEqual(received, []);
});

test("delivers inbound frames up to the frame limit", async () => {
  const frame = "y".repeat(maxFrameSize);
  const port = await rawPeer({ send: frame, read: true });
  const socket = transport(port);
  const received: string[] = [];
  socket.onData((d) => received.push(d));
  socket.open();
  await waitFor(socket, "connected");
  const deadline = Date.now() + 3000;
  while (received.length === 0 && Date.now() < deadline) {
    await sleep(10);
  }
  assert.deepEqual(received, [frame]);
});

test("reports backpressure instead of buffering without bound", async () => {
  const port = await rawPeer({ read: false });
  const socket = transport(port);
  socket.open();
  await waitFor(socket, "connected");
  const frame = "z".repeat(maxFrameSize);
  let result = "sent";
  let sent = 0;
  while (result === "sent" && sent < 20000) {
    result = socket.send(frame);
    sent += 1;
  }
  assert.equal(result, "busy");
  assert.ok(sent * maxFrameSize < 64 * maxBufferedBytes, `sent ${sent} frames`);
});
