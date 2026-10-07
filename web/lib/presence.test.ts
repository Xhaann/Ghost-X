import assert from "node:assert/strict";
import { test } from "node:test";
import { type AuthState, Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import { Devices } from "./devices.ts";
import { memoryStore } from "./testing.ts";
import { type Keys, type Unlocked, createVault } from "./vault.ts";

type Local = { identity: string; keys: Keys; devices: Devices };

async function local(): Promise<Local> {
  const store = memoryStore();
  const vault = (await createVault(store)) as Unlocked;
  const devices = await Devices.open(store, vault.keys);
  assert.ok(devices);
  return { identity: vault.keys.identity, keys: vault.keys, devices };
}
import { Presence, type PresenceState } from "./presence.ts";
import { WebSocketTransport } from "./socket.ts";
import {
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
  key: Local;
  auth: Authenticator;
  presence: Presence;
  log: PresenceState[];
};

async function until(
  predicate: () => boolean,
  description: string,
): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${description}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function authenticated(
  auth: Authenticator,
  state: AuthState = "authenticated",
) {
  await until(() => auth.state === state, `auth ${state}`);
}

async function peer(
  port: number,
  key?: Local,
  withPresence = true,
): Promise<Peer> {
  const client = track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
      ),
    ),
  );
  const identity = key ?? (await local());
  const auth = new Authenticator(client, identity.keys, identity.devices);
  const presence = new Presence(client, auth);
  track({ close: () => presence.stop() });
  track({ close: () => auth.stop() });
  const log: PresenceState[] = [];
  presence.onState((state) => log.push(state));
  auth.start();
  if (withPresence) {
    presence.start();
  }
  client.open();
  await authenticated(auth);
  return { client, key: identity, auth, presence, log };
}

async function barrier(client: Client): Promise<void> {
  const reply = await client.request({ type: "ping", payload: { sentAt: 1 } });
  assert.equal(reply?.type, "pong");
}

function activeWith(p: Peer, ...ids: string[]): () => boolean {
  const want = [...ids].sort().join();
  return () =>
    p.presence.state.status === "active" &&
    p.presence.state.identities.join() === want;
}

test("stays inactive until authenticated", async () => {
  const port = await freePort();
  await startServer(port);
  const client = track(
    new Client(track(new WebSocketTransport(`ws://127.0.0.1:${port}/ws`))),
  );
  const owner = await local();
  const auth = new Authenticator(client, owner.keys, owner.devices);
  const presence = new Presence(client, auth);
  track({ close: () => presence.stop() });
  const log: PresenceState[] = [];
  presence.onState((state) => log.push(state));

  presence.start();
  client.open();
  await waitFor(client, "connected");
  await barrier(client);

  assert.deepEqual(presence.state, { status: "inactive", identities: [] });
  assert.deepEqual(log, []);
});

test("establishes presence after authentication", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);

  await until(activeWith(a, a.key.identity), "own presence");

  assert.deepEqual(a.log, [
    { status: "pending", identities: [] },
    { status: "pending", identities: [a.key.identity] },
    { status: "active", identities: [a.key.identity] },
  ]);
});

test("tracks other identities joining and leaving", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  await until(activeWith(a, a.key.identity), "own presence");

  const b = await peer(port, undefined, false);
  await until(activeWith(a, a.key.identity, b.key.identity), "b present");
  b.client.close();
  await until(activeWith(a, a.key.identity), "b absent");

  const states = a.log.slice(3).map((s) => s.identities.join());
  assert.deepEqual(states, [
    [a.key.identity, b.key.identity].sort().join(),
    a.key.identity,
  ]);
});

test("keeps an identity present while any session remains", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  await until(activeWith(a, a.key.identity), "own presence");
  const shared = await local();

  const first = await peer(port, shared, false);
  await until(activeWith(a, a.key.identity, shared.identity), "shared present");
  const second = await peer(port, shared, false);
  await barrier(second.client);
  first.client.close();
  const c = await peer(port, undefined, false);
  await until(
    activeWith(a, a.key.identity, shared.identity, c.key.identity),
    "c present",
  );
  second.client.close();
  await until(activeWith(a, a.key.identity, c.key.identity), "shared absent");

  const absences = a.log.filter(
    (s, i) =>
      i > 0 &&
      a.log[i - 1].identities.includes(shared.identity) &&
      !s.identities.includes(shared.identity),
  );
  assert.equal(absences.length, 1);
});

test("resets on disconnect and re-establishes after restart", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const a = await peer(port);
  await until(activeWith(a, a.key.identity), "own presence");

  await stopServer(server);
  await until(() => a.presence.state.status === "inactive", "reset");
  assert.deepEqual(a.presence.state.identities, []);
  await startServer(port);
  await until(activeWith(a, a.key.identity), "presence after restart");

  assert.equal(openSockets().length, 1);
  const statuses = a.log.map((s) => s.status);
  assert.deepEqual(statuses.slice(-4), [
    "inactive",
    "pending",
    "pending",
    "active",
  ]);
});

test("clears other identities after reconnect", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const a = await peer(port);
  const b = await peer(port, undefined, false);
  await until(activeWith(a, a.key.identity, b.key.identity), "b present");
  b.auth.stop();
  b.client.close();

  await stopServer(server);
  await startServer(port);
  await until(activeWith(a, a.key.identity), "fresh presence");
});

test("stop releases listeners and state", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  await until(activeWith(a, a.key.identity), "own presence");
  const count = a.log.length;

  a.presence.stop();
  assert.deepEqual(a.presence.state, { status: "inactive", identities: [] });
  const b = await peer(port, undefined, false);
  await barrier(b.client);
  await barrier(a.client);

  assert.equal(a.log.length, count + 1);
  assert.deepEqual(a.presence.state, { status: "inactive", identities: [] });
});

test("ignores malformed, stale, and duplicate presence frames", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  await until(activeWith(a, a.key.identity), "own presence");
  const [socket] = openSockets();
  const other = await local();
  const inject = (data: unknown) =>
    socket.dispatchEvent(
      new MessageEvent("message", {
        data: typeof data === "string" ? data : JSON.stringify(data),
      }),
    );
  const count = a.log.length;

  inject("not json");
  inject({ type: "present", id: "x1", payload: { identity: other.identity } });
  inject({ type: "present", payload: { identity: "short" } });
  inject({ type: "present", payload: { identity: other.identity, extra: 1 } });
  inject({ type: "absent", payload: {} });
  inject({ type: "present", payload: { identity: a.key.identity } });
  inject({ type: "absent", payload: { identity: other.identity } });

  assert.equal(a.log.length, count);
  assert.deepEqual(a.presence.state.identities, [a.key.identity]);
});

test("ignores presence frames while inactive", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  await until(activeWith(a, a.key.identity), "own presence");
  const [socket] = openSockets();
  const other = await local();

  a.auth.stop();
  await until(() => a.presence.state.status === "inactive", "reset");
  socket.dispatchEvent(
    new MessageEvent("message", {
      data: JSON.stringify({
        type: "present",
        payload: { identity: other.identity },
      }),
    }),
  );

  assert.deepEqual(a.presence.state, { status: "inactive", identities: [] });
});

test("discards a subscription reply from a superseded attempt", async () => {
  const port = await freePort();
  await startServer(port);
  const client = track(
    new Client(track(new WebSocketTransport(`ws://127.0.0.1:${port}/ws`))),
  );
  const key = await local();
  const auth = new Authenticator(client, key.keys, key.devices);
  track({ close: () => auth.stop() });
  let state: AuthState = "unauthenticated";
  const listeners = new Set<(s: AuthState) => void>();
  const source = {
    get state() {
      return state;
    },
    onState(listener: (s: AuthState) => void) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
  const presence = new Presence(client, source);
  track({ close: () => presence.stop() });
  presence.start();
  auth.start();
  client.open();
  await authenticated(auth);

  state = "authenticated";
  listeners.forEach((listener) => listener(state));
  state = "unauthenticated";
  listeners.forEach((listener) => listener(state));
  await barrier(client);

  assert.deepEqual(presence.state, { status: "inactive", identities: [] });
});
