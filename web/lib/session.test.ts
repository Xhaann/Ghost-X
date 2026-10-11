import assert from "node:assert/strict";
import { test } from "node:test";
import { availability, connectionOf, phaseOf } from "./application.ts";
import { encodeBase64Url } from "./base64.ts";
import { Session, type SessionOptions, type SessionState } from "./session.ts";
import {
  created,
  freePort,
  localSession,
  openSockets,
  peerCarrier,
  secureDevice,
  sleep,
  startServer,
  track,
  useServer,
} from "./testing.ts";

useServer();

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 8000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await sleep(5);
  }
}

function started(options: SessionOptions): Session {
  const session = new Session(options);
  track({ close: () => session.dispose() });
  session.start();
  return session;
}

function ready(session: Session): () => boolean {
  return () =>
    session.state.connection.status === "authenticated" &&
    session.state.messaging === "ready" &&
    session.state.conversations.connected;
}

function bodies(state: SessionState, peer: string): (string | null)[] {
  return (
    state.conversations.conversations
      .find((c) => c.identity === peer)
      ?.messages.map((m) => m.body) ?? []
  );
}

function liveSockets(port: number): number {
  return openSockets().filter((s) => s.url.includes(`:${port}/`)).length;
}

test("connection state is derived from the transport and authentication without contradictions", () => {
  assert.deepEqual(connectionOf("connected", null, "authenticated"), {
    status: "authenticated",
  });
  assert.deepEqual(connectionOf("connected", null, "authenticating"), {
    status: "authenticating",
  });
  assert.deepEqual(connectionOf("connected", null, "unauthenticated"), {
    status: "authenticating",
  });
  assert.deepEqual(connectionOf("connecting", null, "unauthenticated"), {
    status: "connecting",
  });
  assert.deepEqual(connectionOf("reconnecting", "lost", "unauthenticated"), {
    status: "reconnecting",
  });
  assert.deepEqual(connectionOf("error", "unavailable", "unauthenticated"), {
    status: "unavailable",
  });
  assert.deepEqual(connectionOf("error", "lost", "unauthenticated"), {
    status: "disconnected",
    reason: "lost",
  });
  assert.deepEqual(connectionOf("disconnected", null, "unauthenticated"), {
    status: "disconnected",
    reason: null,
  });
  for (const transport of ["connected", "error", "disconnected"] as const) {
    assert.equal(connectionOf(transport, null, "revoked").status, "revoked");
    assert.equal(connectionOf(transport, null, "pending").status, "pending");
    assert.equal(connectionOf(transport, null, "failed").status, "rejected");
  }
  assert.equal(
    availability("websocket", {
      url: "ws://x/ws",
      websocket: true,
      link: false,
    }),
    "available",
  );
  assert.equal(
    availability("websocket", { url: undefined, websocket: true, link: false }),
    "unavailable",
  );
  assert.equal(
    availability("websocket", {
      url: "ws://x/ws",
      websocket: false,
      link: true,
    }),
    "unavailable",
  );
  assert.equal(
    availability("local", { url: "ws://x/ws", websocket: true, link: false }),
    "unavailable",
  );
  assert.equal(
    availability("local", { url: undefined, websocket: false, link: true }),
    "available",
  );
  assert.deepEqual(phaseOf("loading"), { phase: "initializing" });
  assert.deepEqual(phaseOf("unavailable"), {
    phase: "fatal",
    reason: "storage_unavailable",
  });
  assert.deepEqual(phaseOf("corrupted"), {
    phase: "fatal",
    reason: "corrupted",
  });
  assert.deepEqual(phaseOf("empty"), { phase: "no_identity" });
  assert.deepEqual(phaseOf("ready"), { phase: "ready" });
});

test("an internet session composes authentication, messaging and verification end to end", async () => {
  const port = await freePort();
  await startServer(port);
  const url = `ws://127.0.0.1:${port}/ws`;
  const a = started({ kind: "websocket", local: await localSession(), url });
  const bLocal = await localSession();
  const b = started({ kind: "websocket", local: bLocal, url });
  await until(ready(a), "a ready");
  await until(ready(b), "b ready");
  assert.equal(a.state.presence.status, "active");
  assert.equal(a.state.peer, null);
  assert.equal(a.state.authorization, null);

  const bId = bLocal.keys.identity;
  assert.ok(a.open(bId));
  await until(() => a.state.pairing !== null, "pairing state");
  const attempt = a.send("hello through the session");
  assert.ok(attempt.accepted);
  assert.equal(await attempt.delivery, "queued");
  const aId = a.state.conversations.conversations[0]?.messages[0]?.from;
  assert.ok(aId);
  await until(
    () => bodies(b.state, aId).includes("hello through the session"),
    "b receives",
  );
  await until(
    () =>
      a.state.conversations.conversations
        .find((c) => c.identity === bId)
        ?.messages.some(
          (m) => m.direction === "sent" && m.delivery === "delivered",
        ) === true,
    "delivery confirmed by the recipient device",
  );

  const view = a.state.verification;
  assert.equal(view?.state, "unverified");
  assert.ok(view?.current);
  assert.ok(await a.verify(view.current.value));
  await until(() => a.state.verification?.state === "verified", "verified");
  assert.equal(a.trustOf(bId), "verified");

  assert.equal((await a.whoami()).ok, true);
  assert.equal((await a.ping()).ok, true);
  assert.ok(a.admin);
});

test("disposing a session releases its socket, listeners and state updates", async () => {
  const port = await freePort();
  await startServer(port);
  const url = `ws://127.0.0.1:${port}/ws`;
  const local = await localSession();
  for (let i = 0; i < 10; i++) {
    const session = started({ kind: "websocket", local, url });
    if (i % 2 === 0) {
      await until(ready(session), `ready ${i}`);
    }
    session.dispose();
    session.dispose();
  }
  await until(() => liveSockets(port) === 0, "all sockets closed");
  const session = started({ kind: "websocket", local, url });
  await until(ready(session), "final session ready");
  const emitted: SessionState[] = [];
  session.onState((state) => emitted.push(state));
  session.dispose();
  await sleep(200);
  assert.deepEqual(emitted, [], "a disposed session never publishes");
  assert.equal(liveSockets(port), 0);
  assert.equal(session.open(local.keys.identity), false);
  assert.deepEqual(session.send("after dispose"), {
    accepted: false,
    reason: "no_conversation",
  });
});

test("selecting the local link never falls back to the internet and switching back authenticates afresh", async () => {
  const port = await freePort();
  await startServer(port);
  const url = `ws://127.0.0.1:${port}/ws`;
  const local = await localSession();
  const internet = started({ kind: "websocket", local, url });
  await until(ready(internet), "internet ready");
  internet.dispose();
  const before = created.length;
  const direct = started({ kind: "local", local, url, link: null });
  await until(
    () => direct.state.connection.status === "unavailable",
    "local link unavailable",
  );
  await sleep(300);
  assert.equal(created.length, before, "no websocket was opened");
  assert.equal(liveSockets(port), 0);
  assert.equal(direct.state.kind, "local");
  assert.equal(direct.state.conversations.connected, false);
  assert.equal(direct.admin, null, "device management needs the internet");
  assert.deepEqual(await direct.whoami(), { ok: false, required: false });
  direct.dispose();

  const again = started({ kind: "websocket", local, url });
  await until(ready(again), "internet again");
  assert.equal(created.length, before + 1);
  assert.equal(liveSockets(port), 1);
});

test("local sessions on a real carrier authenticate each other directly and exchange messages", async () => {
  const carrier = await peerCarrier();
  const aLocal = await localSession();
  const bLocal = await localSession();
  const before = created.length;
  const b = started({ kind: "local", local: bLocal, link: carrier.listen });
  const a = started({ kind: "local", local: aLocal, link: carrier.dial });
  await until(ready(a), "a ready");
  await until(ready(b), "b ready");
  assert.deepEqual(a.state.peer, {
    identity: bLocal.keys.identity,
    device: bLocal.keys.deviceId,
  });
  assert.equal(a.state.authorization?.basis, "unconfirmed");
  assert.equal(a.state.presence.status, "inactive");
  assert.ok(a.open(bLocal.keys.identity));
  const attempt = a.send("direct through the session");
  assert.ok(attempt.accepted);
  assert.equal(
    await attempt.delivery,
    "delivered",
    "on a direct link the peer acknowledgement is the delivery confirmation",
  );
  await until(
    () =>
      bodies(b.state, aLocal.keys.identity).includes(
        "direct through the session",
      ),
    "b receives directly",
  );
  assert.equal(created.length, before, "no websocket was involved");
  carrier.drop();
  await until(
    () => a.state.connection.status === "disconnected",
    "carrier loss is reported",
  );
  await sleep(200);
  assert.equal(
    a.state.connection.status,
    "disconnected",
    "no automatic reconnect",
  );
  assert.equal(a.state.peer, null);
});

test("messaging reports starting until history is restored and a disposed session never starts it", async () => {
  const local = await localSession();
  const restore = local.history.restore.bind(local.history);
  let finish: (() => void) | null = null;
  local.history.restore = () =>
    new Promise((resolve) => {
      finish = () => void restore().then(resolve);
    });
  const session = new Session({ kind: "local", local, link: null });
  const states: SessionState[] = [];
  session.onState((state) => states.push(state));
  session.start();
  assert.equal(session.state.messaging, "starting");
  assert.equal(session.open(local.keys.identity), false);
  session.dispose();
  const count = states.length;
  finish!();
  await sleep(100);
  assert.equal(states.length, count, "no state after dispose");
  assert.equal(session.state.messaging, "starting");
  assert.equal(session.open(local.keys.identity), false);

  const failing = await localSession();
  failing.history.restore = () => Promise.reject(new Error("unreadable"));
  const broken = started({ kind: "local", local: failing, link: null });
  await until(() => broken.state.messaging === "unavailable", "failure");
  assert.deepEqual(broken.state.conversations.conversations, []);
});

test("a revoked device and a replaced identity are reflected without stale state", async () => {
  const port = await freePort();
  await startServer(port);
  const url = `ws://127.0.0.1:${port}/ws`;
  const rootLocal = await localSession();
  const root = started({ kind: "websocket", local: rootLocal, url });
  await until(ready(root), "root ready");
  const linkedLocal = await localSession({ root: rootLocal.keys.identity });
  const linked = started({ kind: "websocket", local: linkedLocal, url });
  await until(() => linked.state.connection.status === "pending", "pending");
  assert.equal(linked.admin, null);
  const request = await linkedLocal.devices.linkRequest();
  assert.ok(request && root.admin);
  assert.ok((await root.admin.authorize(request)).ok);
  await until(ready(linked), "linked ready");
  assert.ok((await root.admin.revoke(linkedLocal.keys.deviceId)).ok);
  await until(() => linked.state.connection.status === "revoked", "revoked");
  assert.equal(linked.state.conversations.connected, false);
  assert.equal(linked.send("after revocation").accepted, false);
  linked.dispose();

  const sender = started({
    kind: "websocket",
    local: await localSession(),
    url,
  });
  await until(ready(sender), "sender ready");
  const firstLocal = await localSession();
  const first = started({ kind: "websocket", local: firstLocal, url });
  await until(ready(first), "first identity ready");
  first.dispose();
  const replacement = started({
    kind: "websocket",
    local: await localSession(),
    url,
  });
  await until(ready(replacement), "replacement ready");
  sender.open(firstLocal.keys.identity);
  const sent = sender.send("for the previous identity");
  assert.ok(sent.accepted);
  await sent.delivery;
  await sleep(300);
  assert.deepEqual(
    replacement.state.conversations.conversations,
    [],
    "nothing addressed to the replaced identity reaches the new one",
  );
});

test("a pairing result for a previous conversation never overwrites the current one", async () => {
  const port = await freePort();
  await startServer(port);
  const url = `ws://127.0.0.1:${port}/ws`;
  const a = started({ kind: "websocket", local: await localSession(), url });
  const b = await secureDevice(port);
  await until(ready(a), "a ready");
  const stranger = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  assert.ok(a.open(stranger));
  assert.ok(a.open(b.id));
  await until(
    () => a.state.pairing === "established" || a.state.pairing === "pending",
    "pairing for the current conversation",
  );
  await sleep(300);
  assert.notEqual(a.state.pairing, "unavailable");
  assert.equal(a.state.conversations.active, b.id);
});

test("a message held locally is pending, then queued once relayed, then delivered", async () => {
  const port = await freePort();
  await startServer(port);
  const url = `ws://127.0.0.1:${port}/ws`;
  const bLocal = await localSession();
  const first = started({ kind: "websocket", local: bLocal, url });
  await until(ready(first), "recipient published its keys");
  first.dispose();
  const a = started({ kind: "websocket", local: await localSession(), url });
  await until(ready(a), "sender ready");
  const seen: string[] = [];
  a.onState((state) => {
    const message = state.conversations.conversations
      .find((c) => c.identity === bLocal.keys.identity)
      ?.messages.find((m) => m.direction === "sent");
    if (message?.direction === "sent" && seen.at(-1) !== message.delivery) {
      seen.push(message.delivery);
    }
  });
  assert.ok(a.open(bLocal.keys.identity));
  const attempt = a.send("while the recipient is away");
  assert.ok(attempt.accepted);
  assert.equal(await attempt.delivery, "pending");
  const back = started({ kind: "websocket", local: bLocal, url });
  await until(ready(back), "recipient back");
  await until(() => seen.at(-1) === "delivered", "delivered");
  assert.deepEqual(seen, ["sending", "pending", "queued", "delivered"]);
  assert.ok(
    bodies(
      back.state,
      a.state.conversations.conversations[0].messages[0].from,
    ).includes("while the recipient is away"),
  );
});
