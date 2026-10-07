import assert from "node:assert/strict";
import { test } from "node:test";
import { type AuthState, Authenticator, authMessage } from "./auth.ts";
import { Client } from "./client.ts";
import { Devices } from "./devices.ts";
import type { ServerMessage } from "./protocol.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  freePort,
  openSockets,
  sleep,
  startServer,
  stopServer,
  track,
  useServer,
  waitFor,
  memoryStore,
} from "./testing.ts";
import { type Keys, type Unlocked, createVault, linkVault } from "./vault.ts";

type Local = { keys: Keys; devices: Devices };

async function local(link?: string): Promise<Local> {
  const store = memoryStore();
  const vault = (
    link ? await linkVault(store, link) : await createVault(store)
  ) as Unlocked;
  const devices = await Devices.open(store, vault.keys);
  assert.ok(devices);
  return { keys: vault.keys, devices };
}

useServer();

function client(port: number): Client {
  return track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
      ),
    ),
  );
}

async function connected(port: number): Promise<Client> {
  const c = client(port);
  c.open();
  await waitFor(c, "connected");
  return c;
}

function authenticator(c: Client, key: Local) {
  const auth = new Authenticator(c, key.keys, key.devices);
  track({ close: () => auth.stop() });
  const states: AuthState[] = [];
  auth.onState((state) => states.push(state));
  return { auth, states };
}

async function settle(
  auth: Authenticator,
  state: AuthState,
  timeout = 5000,
): Promise<void> {
  const deadline = Date.now() + timeout;
  while (auth.state !== state) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${state}, state is ${auth.state}`);
    }
    await sleep(5);
  }
}

function replies(c: Client, type: ServerMessage["type"]): ServerMessage[] {
  const seen: ServerMessage[] = [];
  c.onMessage((message) => {
    if (message.type === type) {
      seen.push(message);
    }
  });
  return seen;
}

test("builds a domain-separated authentication message bound to identity and device", async () => {
  const nonce = Uint8Array.from({ length: 32 }, (_, i) => i);
  const { keys } = await local();
  const message = authMessage(nonce, keys.identity, keys.deviceId);
  assert.ok(message);
  const context = "ghostx/session/authenticate/v2\0";
  assert.equal(
    new TextDecoder().decode(message.slice(0, context.length)),
    context,
  );
  assert.deepEqual(message.slice(context.length, context.length + 32), nonce);
  assert.equal(message.length, context.length + 32 + 32 + 16);
  const other = await local();
  assert.notDeepEqual(
    authMessage(nonce, other.keys.identity, keys.deviceId),
    message,
  );
  assert.notDeepEqual(
    authMessage(nonce, keys.identity, other.keys.deviceId),
    message,
  );
  assert.equal(authMessage(nonce, "bad", keys.deviceId), null);
  assert.equal(authMessage(nonce, keys.identity, "bad"), null);
});

test("starts unauthenticated", async () => {
  const c = client(await freePort());
  const { auth, states } = authenticator(c, await local());

  auth.start();

  assert.equal(auth.state, "unauthenticated");
  assert.deepEqual(states, []);
});

test("authenticates a connected client", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const { auth, states } = authenticator(c, await local());

  auth.start();
  await settle(auth, "authenticated");

  assert.deepEqual(states, ["authenticating", "authenticated"]);
});

test("authenticates once the client connects", async () => {
  const port = await freePort();
  await startServer(port);
  const c = client(port);
  const { auth, states } = authenticator(c, await local());

  auth.start();
  c.open();
  await settle(auth, "authenticated");

  assert.deepEqual(states, ["authenticating", "authenticated"]);
});

test("fails with a released key and retries on request", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const key = await local();
  key.keys.device.release();
  const { auth, states } = authenticator(c, key);

  auth.start();
  await settle(auth, "failed");
  auth.retry();
  await settle(auth, "failed");

  assert.deepEqual(states, [
    "authenticating",
    "failed",
    "authenticating",
    "failed",
  ]);
  assert.equal(c.state, "connected");
});

test("ignores retry unless authentication failed", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const challenges = replies(c, "challenge");
  const { auth } = authenticator(c, await local());

  auth.retry();
  auth.start();
  await settle(auth, "authenticated");
  auth.retry();
  await sleep(100);

  assert.equal(challenges.length, 1);
  assert.equal(auth.state, "authenticated");
});

test("re-authenticates with a fresh challenge after reconnect", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const c = await connected(port);
  const challenges = replies(c, "challenge");
  const authenticated = replies(c, "authenticated");
  const { auth, states } = authenticator(c, await local());

  auth.start();
  await settle(auth, "authenticated");
  await stopServer(server);
  await settle(auth, "unauthenticated");
  await startServer(port);
  await settle(auth, "authenticated");
  await sleep(100);

  assert.deepEqual(states, [
    "authenticating",
    "authenticated",
    "unauthenticated",
    "authenticating",
    "authenticated",
  ]);
  assert.equal(challenges.length, 2);
  assert.equal(authenticated.length, 2);
  assert.ok(
    challenges[0].type === "challenge" && challenges[1].type === "challenge",
  );
  assert.notEqual(challenges[0].payload.nonce, challenges[1].payload.nonce);
  assert.equal(openSockets().length, 1);
});

test("starts once even when called repeatedly", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const challenges = replies(c, "challenge");
  const { auth } = authenticator(c, await local());

  auth.start();
  auth.start();
  await settle(auth, "authenticated");
  await sleep(100);

  assert.equal(challenges.length, 1);
});

test("abandons a superseded attempt without a second proof", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const authenticated = replies(c, "authenticated");
  const errors = replies(c, "error");
  const key = await local();
  const first = authenticator(c, key);
  const second = authenticator(c, key);

  first.auth.start();
  first.auth.stop();
  second.auth.start();
  await settle(second.auth, "authenticated");
  await sleep(200);

  assert.equal(first.auth.state, "unauthenticated");
  assert.equal(authenticated.length, 1);
  assert.equal(errors.length, 0);
});

test("stop resets state and ignores later connections", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const c = await connected(port);
  const challenges = replies(c, "challenge");
  const { auth } = authenticator(c, await local());

  auth.start();
  await settle(auth, "authenticated");
  auth.stop();
  assert.equal(auth.state, "unauthenticated");

  await stopServer(server);
  await waitFor(c, "reconnecting");
  await startServer(port);
  await waitFor(c, "connected");
  await sleep(200);

  assert.equal(auth.state, "unauthenticated");
  assert.equal(challenges.length, 1);
});

test("resets when the client closes", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const { auth } = authenticator(c, await local());

  auth.start();
  await settle(auth, "authenticated");
  c.close();

  assert.equal(auth.state, "unauthenticated");
});

test("authenticates independent connections with one identity", async () => {
  const port = await freePort();
  await startServer(port);
  const key = await local();
  const [a, b] = await Promise.all([connected(port), connected(port)]);
  const first = authenticator(a, key);
  const second = authenticator(b, key);

  first.auth.start();
  second.auth.start();
  await settle(first.auth, "authenticated");
  await settle(second.auth, "authenticated");
  a.close();
  await sleep(100);

  assert.equal(first.auth.state, "unauthenticated");
  assert.equal(second.auth.state, "authenticated");
});

test("rejects an authenticated reply for another identity", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const [socket] = openSockets();
  const [key, other] = await Promise.all([local(), local()]);
  const send = socket.send.bind(socket);
  socket.send = (data: string) => {
    const message = JSON.parse(data);
    if (message.type === "authenticate") {
      queueMicrotask(() => {
        socket.dispatchEvent(new MessageEvent("message", { data: "not json" }));
        socket.dispatchEvent(
          new MessageEvent("message", {
            data: JSON.stringify({
              type: "authenticated",
              id: message.id,
              payload: {
                identity: other.keys.identity,
                device: key.keys.deviceId,
              },
            }),
          }),
        );
      });
    }
    send(data);
  };
  const { auth } = authenticator(c, key);

  auth.start();
  await settle(auth, "failed");
});

test("never places private key material in sent frames", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const [socket] = openSockets();
  const sent: string[] = [];
  const send = socket.send.bind(socket);
  socket.send = (data: string) => {
    sent.push(data);
    send(data);
  };
  const key = await local();
  const { auth } = authenticator(c, key);

  auth.start();
  await settle(auth, "authenticated");

  assert.equal(sent.length, 3);
  const [register, challenge, authenticate] = sent.map((frame) =>
    JSON.parse(frame),
  );
  assert.equal(register.type, "register");
  assert.deepEqual(register.payload, key.devices.roster);
  assert.deepEqual(Object.keys(challenge).sort(), ["id", "payload", "type"]);
  assert.deepEqual(challenge.payload, {});
  assert.deepEqual(Object.keys(authenticate).sort(), ["id", "payload", "type"]);
  assert.deepEqual(Object.keys(authenticate.payload).sort(), [
    "device",
    "identity",
    "signature",
  ]);
  assert.equal(authenticate.payload.identity, key.keys.identity);
  assert.equal(authenticate.payload.device, key.keys.deviceId);
  assert.match(authenticate.payload.signature, /^[A-Za-z0-9_-]{86}$/);
  for (const frame of sent) {
    assert.ok(!/private|pkcs8|"root"|"d":/i.test(frame));
  }
});

test("protected requests require authentication", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const key = await local();

  const before = await c.request({ type: "whoami", payload: {} });
  assert.deepEqual(before?.type === "error" && before.payload, {
    code: "authentication_required",
  });

  const { auth } = authenticator(c, key);
  auth.start();
  await settle(auth, "authenticated");

  const after = await c.request({ type: "whoami", payload: {} });
  assert.ok(after?.type === "whoami");
  assert.equal(after.payload.identity, key.keys.identity);
  assert.equal(after.payload.device, key.keys.deviceId);
});

test("protected requests need fresh authentication after reconnect", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const c = await connected(port);
  const key = await local();
  const { auth } = authenticator(c, key);

  auth.start();
  await settle(auth, "authenticated");
  auth.stop();
  await stopServer(server);
  await waitFor(c, "reconnecting");
  await startServer(port);
  await waitFor(c, "connected");

  const unauthenticated = await c.request({ type: "whoami", payload: {} });
  assert.deepEqual(
    unauthenticated?.type === "error" && unauthenticated.payload,
    { code: "authentication_required" },
  );

  auth.start();
  await settle(auth, "authenticated");
  const reply = await c.request({ type: "whoami", payload: {} });
  assert.ok(reply?.type === "whoami");
  assert.equal(reply.payload.identity, key.keys.identity);
});

test("a linked device waits for authorization, then authenticates with its own key", async () => {
  const port = await freePort();
  await startServer(port);
  const owner = await local();
  const rootClient = await connected(port);
  const rootAuth = authenticator(rootClient, owner);
  rootAuth.auth.start();
  await settle(rootAuth.auth, "authenticated");

  const second = await local(owner.keys.identity);
  const c = await connected(port);
  const sent: string[] = [];
  const [, socket] = openSockets();
  const send = socket.send.bind(socket);
  socket.send = (data: string) => {
    sent.push(data);
    send(data);
  };
  const { auth, states } = authenticator(c, second);
  auth.start();
  await settle(auth, "pending");
  assert.equal(
    sent.filter((f) => JSON.parse(f).type === "authenticate").length,
    0,
  );

  const request = await second.devices.linkRequest();
  assert.ok(request);
  assert.ok((await owner.devices.authorize(rootClient, request)).ok);
  await settle(auth, "authenticated", 8000);
  assert.ok(states.includes("pending"));
  const authenticate = JSON.parse(
    sent.find((f) => JSON.parse(f).type === "authenticate") as string,
  );
  assert.equal(authenticate.payload.device, second.keys.deviceId);
});

test("a revoked device is disconnected and cannot authenticate again", async () => {
  const port = await freePort();
  await startServer(port);
  const owner = await local();
  const rootClient = await connected(port);
  const rootAuth = authenticator(rootClient, owner);
  rootAuth.auth.start();
  await settle(rootAuth.auth, "authenticated");
  const second = await local(owner.keys.identity);
  const request = await second.devices.linkRequest();
  assert.ok(request);
  assert.ok((await owner.devices.authorize(rootClient, request)).ok);
  const c = await connected(port);
  const { auth } = authenticator(c, second);
  auth.start();
  await settle(auth, "authenticated");

  assert.ok((await owner.devices.revoke(rootClient, second.keys.deviceId)).ok);
  await settle(auth, "revoked", 8000);
  assert.equal(second.devices.status, "revoked");
  const whoami = await c.request({ type: "whoami", payload: {} });
  assert.ok(whoami?.type === "error");
  assert.equal(rootAuth.auth.state, "authenticated");
});
