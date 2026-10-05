import assert from "node:assert/strict";
import { test } from "node:test";
import { type AuthState, Authenticator, authMessage } from "./auth.ts";
import { Client } from "./client.ts";
import { IdentityKey } from "./identity.ts";
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
} from "./testing.ts";

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

function authenticator(c: Client, key: IdentityKey) {
  const auth = new Authenticator(c, key);
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

test("builds a domain-separated authentication message", () => {
  const nonce = Uint8Array.from({ length: 32 }, (_, i) => i);
  const message = authMessage(nonce);
  const context = "ghostx/session/authenticate/v1\0";

  assert.equal(
    new TextDecoder().decode(message.slice(0, context.length)),
    context,
  );
  assert.deepEqual(message.slice(context.length), nonce);
  assert.deepEqual(authMessage(nonce), message);
});

test("starts unauthenticated", async () => {
  const c = client(await freePort());
  const { auth, states } = authenticator(c, await IdentityKey.generate());

  auth.start();

  assert.equal(auth.state, "unauthenticated");
  assert.deepEqual(states, []);
});

test("authenticates a connected client", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const { auth, states } = authenticator(c, await IdentityKey.generate());

  auth.start();
  await settle(auth, "authenticated");

  assert.deepEqual(states, ["authenticating", "authenticated"]);
});

test("authenticates once the client connects", async () => {
  const port = await freePort();
  await startServer(port);
  const c = client(port);
  const { auth, states } = authenticator(c, await IdentityKey.generate());

  auth.start();
  c.open();
  await settle(auth, "authenticated");

  assert.deepEqual(states, ["authenticating", "authenticated"]);
});

test("fails with a released key and retries on request", async () => {
  const port = await freePort();
  await startServer(port);
  const c = await connected(port);
  const key = await IdentityKey.generate();
  key.release();
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
  const { auth } = authenticator(c, await IdentityKey.generate());

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
  const { auth, states } = authenticator(c, await IdentityKey.generate());

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
  const { auth } = authenticator(c, await IdentityKey.generate());

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
  const key = await IdentityKey.generate();
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
  const { auth } = authenticator(c, await IdentityKey.generate());

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
  const { auth } = authenticator(c, await IdentityKey.generate());

  auth.start();
  await settle(auth, "authenticated");
  c.close();

  assert.equal(auth.state, "unauthenticated");
});

test("authenticates independent connections with one identity", async () => {
  const port = await freePort();
  await startServer(port);
  const key = await IdentityKey.generate();
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
  const [key, other] = await Promise.all([
    IdentityKey.generate(),
    IdentityKey.generate(),
  ]);
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
              payload: { identity: other.identity },
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
  const key = await IdentityKey.generate();
  const { auth } = authenticator(c, key);

  auth.start();
  await settle(auth, "authenticated");

  assert.equal(sent.length, 2);
  const authenticate = JSON.parse(sent[1]);
  assert.deepEqual(Object.keys(authenticate.payload).sort(), [
    "identity",
    "signature",
  ]);
  assert.equal(authenticate.payload.identity, key.identity);
  for (const frame of sent) {
    assert.doesNotMatch(frame, /private|pkcs8|jwk|"d":/i);
  }
});
