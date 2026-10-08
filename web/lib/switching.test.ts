import assert from "node:assert/strict";
import { test } from "node:test";
import { Client } from "./client.ts";
import { type Link, type LinkHandlers, LocalTransport } from "./local.ts";
import { pairAddress } from "./pairs.ts";
import { createId } from "./protocol.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  type SecureDevice,
  created,
  freePort,
  linkedDevice,
  localSocket,
  openSockets,
  secureDevice,
  sleep,
  startServer,
  track,
  unixLink,
  useServer,
  waitFor,
} from "./testing.ts";
import type { TransportError } from "./transport.ts";

useServer();

type Json = Record<string, unknown>;

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 8000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await sleep(10);
  }
}

function frames(list: string[], type: string): Json[] {
  return list
    .map((raw) => JSON.parse(raw) as Json)
    .filter((frame) => frame.type === type);
}

function bodies(d: SecureDevice): (string | null)[] {
  return d.inbox.map((m) => m.body);
}

function recorded<T extends { send(frame: string): unknown }>(
  transport: T,
  into: string[],
): T {
  const send = transport.send.bind(transport);
  transport.send = ((frame: string) => {
    into.push(frame);
    return send(frame);
  }) as T["send"];
  return transport;
}

function counting(): Link & { calls: number } {
  const link = {
    calls: 0,
    connect: () => {
      link.calls += 1;
      return Promise.reject(new Error("no peer"));
    },
  };
  return link;
}

test("selecting the local transport never activates the websocket transport", async () => {
  const port = await freePort();
  await startServer(port);
  const client = track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 20 }),
      ),
    ),
  );
  const errors: TransportError[] = [];
  client.onError((e) => errors.push(e));
  client.open();
  await waitFor(client, "connected");
  const before = created.length;
  client.select(track(new LocalTransport(null)));
  assert.equal(client.kind, "local");
  assert.equal(client.state, "error");
  assert.deepEqual(errors, ["unavailable"]);
  await sleep(300);
  assert.equal(created.length, before, "no websocket was opened");
  assert.equal(openSockets().length, 0, "the previous websocket was closed");
  assert.equal(client.send({ type: "ping", payload: { sentAt: 1 } }), null);
  assert.equal(
    await client.request({ type: "ping", payload: { sentAt: 1 } }, 200),
    null,
  );
  client.select(
    track(
      new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 20 }),
    ),
  );
  await waitFor(client, "connected");
  assert.equal(client.kind, "websocket");
});

test("a failed websocket transport never activates a local link, and a failed link never opens a websocket", async () => {
  const port = await freePort();
  const link = counting();
  const client = track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 20 }),
      ),
    ),
  );
  const errors: TransportError[] = [];
  client.onError((e) => errors.push(e));
  client.open();
  await until(() => errors.length >= 3, "websocket failures");
  assert.equal(link.calls, 0);
  assert.ok(errors.every((e) => e === "failed"));

  client.select(track(new LocalTransport(link)));
  const sockets = created.length;
  await until(() => client.state === "error", "local failure");
  await sleep(200);
  assert.equal(link.calls, 1, "the failed link is not retried");
  assert.equal(created.length, sockets, "no websocket fallback");
  assert.equal(errors.at(-1), "failed");
});

test("frames from a replaced transport never reach the client", async () => {
  let handlers: LinkHandlers | null = null;
  const link: Link = {
    connect: (h) => {
      handlers = h;
      return Promise.resolve({ send: () => true, close: () => {} });
    },
  };
  const old = new LocalTransport(link);
  const client = track(new Client(old));
  const seen: unknown[] = [];
  client.onMessage((m) => seen.push(m));
  client.open();
  await waitFor(client, "connected");
  const pong = JSON.stringify({
    type: "pong",
    id: createId(),
    payload: { sentAt: 1, receivedAt: 2 },
  });
  handlers!.frame(pong);
  assert.equal(seen.length, 1);
  client.select(new LocalTransport(null));
  handlers!.frame(pong);
  handlers!.closed();
  assert.equal(seen.length, 1);
  assert.equal(old.state, "disconnected");
});

test("a device on the local carrier is a full end-to-end encrypted participant", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port, { transport: "local" });
  const b = await secureDevice(port);
  assert.equal(a.client.kind, "local");
  const sent = await a.messenger.send(b.id, "over the local carrier");
  assert.deepEqual(sent, { ok: true, devices: 1, pending: 0 });
  await until(() => bodies(b).includes("over the local carrier"), "b receives");
  await b.messenger.send(a.id, "back over websocket");
  await until(() => bodies(a).includes("back over websocket"), "a receives");
  await until(() => a.receipts.length === 1, "receipt over the local carrier");
  assert.equal(a.receipts[0].status, "delivered");
  for (const frame of [...a.frames, ...b.frames]) {
    assert.ok(!frame.includes("over the local carrier"));
    assert.ok(!frame.includes("back over websocket"));
  }
  assert.equal(frames(a.sent, "authenticate").length, 1);
});

test("switching carriers requires a fresh authenticated session and keeps encrypted sessions", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  const b = await secureDevice(port);
  await a.messenger.send(b.id, "before switching");
  await until(() => bodies(b).includes("before switching"), "first message");
  const session = a.pairs.id(pairAddress(b.id, b.deviceId));
  const overLocal: string[] = [];
  a.client.select(
    track(recorded(new LocalTransport(unixLink(localSocket(port))), overLocal)),
  );
  assert.equal(a.client.kind, "local");
  assert.notEqual(a.auth.state, "authenticated");
  await until(() => a.auth.state === "authenticated", "re-authenticated");
  await until(() => a.messenger.state.active, "messenger active");
  assert.equal(frames(overLocal, "challenge").length, 1);
  assert.equal(frames(overLocal, "authenticate").length, 1);
  assert.equal(
    openSockets().filter((s) => s.url.includes(String(port))).length,
    1,
  );

  await a.messenger.send(b.id, "after switching to local");
  await until(() => bodies(b).includes("after switching to local"), "local");
  await b.messenger.send(a.id, "reply to the local device");
  await until(() => bodies(a).includes("reply to the local device"), "reply");
  assert.equal(a.pairs.id(pairAddress(b.id, b.deviceId)), session);

  const overWebSocket: string[] = [];
  a.client.select(
    track(
      recorded(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
        overWebSocket,
      ),
    ),
  );
  await until(() => a.auth.state === "authenticated", "back on websocket");
  assert.equal(frames(overWebSocket, "challenge").length, 1);
  await a.messenger.send(b.id, "back on websocket");
  await until(() => bodies(b).includes("back on websocket"), "websocket again");
  assert.ok(b.inbox.every((m) => m.body !== null));
});

test("an authenticated session never carries over to a new carrier", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await secureDevice(port);
  a.auth.stop();
  a.client.select(track(new LocalTransport(unixLink(localSocket(port)))));
  await waitFor(a.client, "connected");
  const reply = await a.client.request({ type: "whoami", payload: {} });
  assert.ok(reply?.type === "error");
  assert.equal(reply.payload.code, "authentication_required");
  const send = await a.client.request({ type: "fetch", payload: {} });
  assert.ok(send?.type === "error");
  assert.equal(send.payload.code, "authentication_required");
});

test("revocation reaches a device connected over the local carrier", async () => {
  const port = await freePort();
  await startServer(port);
  const b1 = await secureDevice(port);
  const b2 = await linkedDevice(port, b1, { transport: "local" });
  assert.equal(b2.client.kind, "local");
  const a = await secureDevice(port);
  await a.messenger.send(b1.id, "to both");
  await until(() => bodies(b2).includes("to both"), "local device receives");
  const errors: TransportError[] = [];
  b2.client.onError((e) => errors.push(e));
  assert.ok((await b1.devices.revoke(b1.client, b2.deviceId)).ok);
  await until(() => b2.client.state === "error", "local connection closed");
  assert.deepEqual(errors, ["lost"]);
  assert.notEqual(b2.auth.state, "authenticated");
  await sleep(200);
  assert.equal(b2.client.state, "error", "no automatic reconnection");
  b2.client.open();
  await until(() => b2.auth.state === "revoked", "revoked after reopening");
  await a.messenger.send(b1.id, "after revocation");
  await until(() => bodies(b1).includes("after revocation"), "b1");
  await sleep(200);
  assert.ok(!bodies(b2).includes("after revocation"));
});

test("frames a transport refuses are never reported as sent", async () => {
  const link: Link = {
    connect: () => Promise.resolve({ send: () => false, close: () => {} }),
  };
  const client = track(new Client(new LocalTransport(link)));
  client.open();
  await waitFor(client, "connected");
  assert.equal(client.send({ type: "ping", payload: { sentAt: 1 } }), null);
  const started = Date.now();
  assert.equal(
    await client.request({ type: "ping", payload: { sentAt: 1 } }, 5000),
    null,
  );
  assert.ok(Date.now() - started < 1000, "a refused request resolves at once");
  const oversized = {
    type: "register",
    payload: { padding: "x".repeat(40 * 1024) },
  } as unknown as Parameters<typeof client.send>[0];
  assert.equal(client.send(oversized), null);
});
