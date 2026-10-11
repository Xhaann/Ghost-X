import assert from "node:assert/strict";
import { test } from "node:test";
import { phaseOf } from "./application.ts";
import { deviceLockName, requestDeviceLock } from "./lock.ts";
import { type LoadedDevice, type LocalSession, loadDevice } from "./owner.ts";
import { pairAddress } from "./pairs.ts";
import { Session, type SessionState } from "./session.ts";
import {
  freePort,
  memoryStore,
  sleep,
  startServer,
  track,
  useServer,
} from "./testing.ts";

useServer();

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 10000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await sleep(5);
  }
}

function ready(local: LoadedDevice["local"]): LocalSession {
  assert.equal(local.status, "ready");
  return local as LocalSession;
}

function online(local: LocalSession, url: string): Session {
  const session = new Session({ kind: "websocket", local, url });
  track({ close: () => session.dispose() });
  session.start();
  return session;
}

function connected(session: Session): () => boolean {
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

function delivery(state: SessionState, peer: string, body: string) {
  const message = state.conversations.conversations
    .find((c) => c.identity === peer)
    ?.messages.find((m) => m.body === body);
  return message?.direction === "sent" ? message.delivery : null;
}

async function locks(): Promise<{ held: number; pending: number }> {
  const state = await navigator.locks.query();
  return {
    held: (state.held ?? []).filter((l) => l.name === deviceLockName).length,
    pending: (state.pending ?? []).filter((l) => l.name === deviceLockName)
      .length,
  };
}

async function settles(expected: { held: number; pending: number }) {
  const deadline = Date.now() + 5000;
  let actual = await locks();
  while (
    (actual.held !== expected.held || actual.pending !== expected.pending) &&
    Date.now() < deadline
  ) {
    await sleep(5);
    actual = await locks();
  }
  assert.deepEqual(actual, expected);
}

test("the device lock is exclusive, reports waiting, hands over on release and cancels cleanly", async () => {
  let waitedA = 0;
  let waitedB = 0;
  let waitedC = 0;
  const releaseA = await requestDeviceLock(new AbortController().signal, () => {
    waitedA += 1;
  });
  assert.equal(waitedA, 0, "a free lock is granted without waiting");

  let grantedB = false;
  const b = requestDeviceLock(new AbortController().signal, () => {
    waitedB += 1;
  }).then((release) => {
    grantedB = true;
    return release;
  });
  const cancel = new AbortController();
  const c = requestDeviceLock(cancel.signal, () => {
    waitedC += 1;
  });
  await sleep(100);
  assert.equal(
    waitedB + waitedC,
    0,
    "waiting is not reported for a brief wait",
  );
  await until(() => waitedB === 1 && waitedC === 1, "waiting reported");
  await settles({ held: 1, pending: 2 });
  assert.equal(grantedB, false);

  cancel.abort();
  await assert.rejects(c, { name: "AbortError" });
  await sleep(50);
  assert.equal(grantedB, false, "cancelling a waiter never grants another");

  releaseA();
  const releaseB = await b;
  assert.equal(grantedB, true);
  releaseB();
  await settles({ held: 0, pending: 0 });

  const aborted = new AbortController();
  aborted.abort();
  const late = await requestDeviceLock(aborted.signal);
  late();
  await settles({ held: 0, pending: 0 });

  const original = Object.getOwnPropertyDescriptor(navigator, "locks");
  Object.defineProperty(navigator, "locks", {
    value: undefined,
    configurable: true,
  });
  try {
    await assert.rejects(requestDeviceLock(new AbortController().signal));
  } finally {
    if (original) {
      Object.defineProperty(navigator, "locks", original);
    } else {
      delete (navigator as { locks?: unknown }).locks;
    }
  }
  assert.ok(navigator.locks);
});

test("a tab that takes over after waiting loads current sessions and decrypts the next message", async () => {
  const port = await freePort();
  await startServer(port);
  const url = `ws://127.0.0.1:${port}/ws`;
  const shared = memoryStore();

  const releaseA = await requestDeviceLock(new AbortController().signal);
  const loadedA = await loadDevice(shared, { setup: { kind: "create" } });
  const localA = ready(loadedA.local);
  const self = localA.keys.identity;
  const a = online(localA, url);
  await until(connected(a), "owner ready");

  let waited = false;
  let grantedB = false;
  const lockB = requestDeviceLock(
    new AbortController().signal,
    () => {
      waited = true;
    },
    0,
  ).then((release) => {
    grantedB = true;
    return release;
  });
  await until(() => waited, "second tab waits");
  const stale = await loadDevice(shared);
  const staleLocal = ready(stale.local);

  const senderLoaded = await loadDevice(memoryStore(), {
    setup: { kind: "create" },
  });
  const senderLocal = ready(senderLoaded.local);
  const peer = senderLocal.keys.identity;
  const sender = online(senderLocal, url);
  await until(connected(sender), "sender ready");
  assert.equal(sender.open(self), true);
  assert.equal(sender.send("before handover").accepted, true);
  await until(
    () => bodies(a.state, peer).includes("before handover"),
    "owner receives",
  );
  await until(
    () => delivery(sender.state, self, "before handover") === "delivered",
    "first delivered",
  );
  const address = pairAddress(peer, senderLocal.keys.deviceId);
  const sessionId = localA.pairs.id(address);
  assert.ok(sessionId);
  assert.equal(localA.pairs.state(address), "established");
  assert.equal(
    staleLocal.pairs.state(address),
    "none",
    "state loaded before ownership misses the owner's new session",
  );
  await stale.close();
  assert.equal(grantedB, false, "the waiting tab never owned the device");

  a.dispose();
  await loadedA.close();
  releaseA();
  const releaseB = await lockB;
  const loadedB = await loadDevice(shared);
  const localB = ready(loadedB.local);
  assert.equal(localB.keys.identity, self);
  assert.equal(localB.pairs.id(address), sessionId);
  assert.equal(localB.pairs.state(address), "established");
  const b = online(localB, url);
  await until(connected(b), "new owner ready");
  assert.deepEqual(bodies(b.state, peer), ["before handover"]);

  assert.equal(sender.send("after handover").accepted, true);
  await until(
    () => bodies(b.state, peer).includes("after handover"),
    "new owner decrypts",
  );
  assert.deepEqual(bodies(b.state, peer), [
    "before handover",
    "after handover",
  ]);
  await until(
    () => delivery(sender.state, self, "after handover") === "delivered",
    "second delivered",
  );
  assert.equal(localB.pairs.id(address), sessionId, "the session is reused");
  assert.equal(
    senderLocal.pairs.id(pairAddress(self, localA.keys.deviceId)),
    sessionId,
  );

  b.dispose();
  sender.dispose();
  await loadedB.close();
  await senderLoaded.close();
  releaseB();
});

test("loading fails closed without exposing keys and maps to the right phases", async () => {
  const broken = memoryStore();
  let closed = 0;
  broken.close = () => {
    closed += 1;
  };
  broken.getAll = () => Promise.reject(new Error("unreadable"));
  broken.get = () => Promise.reject(new Error("unreadable"));
  const loaded = await loadDevice(broken, { setup: { kind: "create" } });
  assert.deepEqual(loaded.local, { status: "unavailable" });
  assert.equal(closed, 1);

  const empty = await loadDevice(memoryStore());
  assert.deepEqual(empty.local, { status: "empty" });

  assert.deepEqual(phaseOf("waiting"), { phase: "waiting" });
  assert.deepEqual(phaseOf("unsupported"), {
    phase: "fatal",
    reason: "unsupported",
  });
  assert.deepEqual(phaseOf("unavailable"), {
    phase: "fatal",
    reason: "storage_unavailable",
  });
});
