import assert from "node:assert/strict";
import { test } from "node:test";
import { createId } from "./protocol.ts";
import { LocalTransport } from "./local.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  freePort,
  localSocket,
  pingFrame,
  record,
  sleep,
  startServer,
  stopServer,
  track,
  unixLink,
  useServer,
  waitFor,
  waitForCount,
} from "./testing.ts";
import {
  type Transport,
  type TransportError,
  maxFrameSize,
} from "./transport.ts";

useServer();

const serverFrameLimit = 32 * 1024;

type Factory = (port: number) => Transport;

function transportContract(name: string, create: Factory): void {
  const build = (port: number) => track(create(port));

  test(`${name}: starts disconnected`, async () => {
    const transport = build(await freePort());
    assert.equal(transport.state, "disconnected");
    assert.equal(transport.send(pingFrame(createId(), 1)), "not_connected");
  });

  test(`${name}: connects and closes`, async () => {
    const port = await freePort();
    await startServer(port);
    const transport = build(port);
    const states = record(transport);

    transport.open();
    await waitFor(transport, "connected");
    transport.close();

    assert.equal(transport.state, "disconnected");
    assert.deepEqual(states, ["connecting", "connected", "disconnected"]);
  });

  test(`${name}: ignores repeated open`, async () => {
    const port = await freePort();
    await startServer(port);
    const transport = build(port);
    const states = record(transport);

    transport.open();
    transport.open();
    await waitFor(transport, "connected");
    transport.open();

    assert.deepEqual(states, ["connecting", "connected"]);
  });

  test(`${name}: sends and receives data`, async () => {
    const port = await freePort();
    await startServer(port);
    const transport = build(port);
    const received: string[] = [];
    transport.onData((data) => received.push(data));

    transport.open();
    await waitFor(transport, "connected");
    const id = createId();
    assert.equal(transport.send(pingFrame(id, 1)), "sent");
    await waitForCount(received, 1);

    const reply = JSON.parse(received[0]);
    assert.equal(reply.type, "pong");
    assert.equal(reply.id, id);
  });

  test(`${name}: stops delivering after unsubscribe`, async () => {
    const port = await freePort();
    await startServer(port);
    const transport = build(port);
    const kept: string[] = [];
    const removed: string[] = [];
    const states: string[] = [];
    transport.onData((data) => kept.push(data));
    const unsubscribe = [
      transport.onData((data) => removed.push(data)),
      transport.onState((state) => states.push(state)),
    ];

    unsubscribe.forEach((release) => release());
    transport.open();
    await waitFor(transport, "connected");
    transport.send(pingFrame(createId(), 1));
    await waitForCount(kept, 1);
    await sleep(50);

    assert.equal(removed.length, 0);
    assert.equal(states.length, 0);
  });

  test(`${name}: delivers nothing after close`, async () => {
    const port = await freePort();
    await startServer(port);
    const transport = build(port);
    const received: string[] = [];
    transport.onData((data) => received.push(data));

    transport.open();
    await waitFor(transport, "connected");
    transport.send(pingFrame(createId(), 1));
    transport.close();
    await sleep(200);

    assert.equal(received.length, 0);
    assert.equal(transport.send(pingFrame(createId(), 1)), "not_connected");
  });

  test(`${name}: reports a failed connection`, async () => {
    const transport = build(await freePort());
    const errors: TransportError[] = [];
    transport.onError((error) => errors.push(error));

    transport.open();
    await waitForCount(errors, 1);

    assert.equal(errors[0], "failed");
    assert.notEqual(transport.state, "connected");
  });

  test(`${name}: reports a lost connection`, async () => {
    const port = await freePort();
    const server = await startServer(port);
    const transport = build(port);
    const errors: TransportError[] = [];
    transport.onError((error) => errors.push(error));

    transport.open();
    await waitFor(transport, "connected");
    await stopServer(server);
    await waitForCount(errors, 1);

    assert.equal(errors[0], "lost");
    assert.notEqual(transport.state, "connected");
  });

  test(`${name}: refuses oversized frames and stays connected`, async () => {
    const port = await freePort();
    await startServer(port);
    const transport = build(port);
    const received: string[] = [];
    transport.onData((data) => received.push(data));

    transport.open();
    await waitFor(transport, "connected");
    assert.equal(transport.send("x".repeat(serverFrameLimit + 1)), "oversized");
    assert.equal(transport.send("x".repeat(maxFrameSize + 1)), "oversized");
    assert.equal(transport.send(""), "oversized");
    const id = createId();
    assert.equal(transport.send(pingFrame(id, 1)), "sent");
    await waitForCount(received, 1);
    assert.equal(transport.state, "connected");
    assert.equal(JSON.parse(received[0]).id, id);
  });

  test(`${name}: reopens after close`, async () => {
    const port = await freePort();
    await startServer(port);
    const transport = build(port);
    const received: string[] = [];
    transport.onData((data) => received.push(data));

    transport.open();
    await waitFor(transport, "connected");
    transport.close();
    transport.open();
    await waitFor(transport, "connected");
    transport.send(pingFrame(createId(), 1));
    await waitForCount(received, 1);
    await sleep(50);

    assert.equal(received.length, 1);
  });
}

transportContract(
  "websocket",
  (port) => new WebSocketTransport(`ws://127.0.0.1:${port}/ws`),
);

transportContract(
  "local",
  (port) => new LocalTransport(unixLink(localSocket(port))),
);
