import assert from "node:assert/strict";
import { test } from "node:test";
import { phaseOf } from "./application.ts";
import { ExchangeKey } from "./encryption.ts";
import { History } from "./history.ts";
import { IdentityKey } from "./identity.ts";
import { deviceLockName, requestDeviceLock } from "./lock.ts";
import { type LoadedDevice, type LocalSession, loadDevice } from "./owner.ts";
import { Pairs, pairAddress } from "./pairs.ts";
import { createMessageId } from "./protocol.ts";
import { Session, type SessionState } from "./session.ts";
import { Trust } from "./trust.ts";
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

type Subtle = "sign" | "verify" | "deriveBits" | "importKey" | "generateKey";

async function failing<T>(
  method: Subtle,
  run: () => Promise<T>,
  when: (args: unknown[]) => boolean = () => true,
  times = 1,
): Promise<{ result: T; failed: number }> {
  const subtle = crypto.subtle as unknown as Record<
    Subtle,
    (...args: unknown[]) => Promise<unknown>
  >;
  const original = subtle[method];
  let failed = 0;
  subtle[method] = (...args: unknown[]) => {
    if (failed < times && when(args)) {
      failed += 1;
      return Promise.reject(new DOMException("temporary", "OperationError"));
    }
    return original.apply(crypto.subtle, args);
  };
  try {
    return { result: await run(), failed };
  } finally {
    subtle[method] = original;
  }
}

const rosterPrefix = new TextEncoder().encode("ghostx/roster/v1\0");

const rosterCheck = (args: unknown[]) => {
  const data = new Uint8Array(args.at(-1) as Uint8Array);
  return rosterPrefix.every((byte, i) => data[i] === byte);
};

async function withHistory() {
  const store = memoryStore();
  const loaded = await loadDevice(store, { setup: { kind: "create" } });
  const local = ready(loaded.local);
  const peer = (await IdentityKey.generate()).identity;
  assert.ok(
    await local.history.received({
      id: createMessageId(),
      peer,
      sequence: 1,
      read: true,
      body: "kept across failures",
    }),
  );
  await local.history.flush();
  const identity = local.keys.identity;
  const deviceId = local.keys.deviceId;
  await loaded.close();
  return { store, identity, deviceId };
}

function contents(store: ReturnType<typeof memoryStore>) {
  return { writes: store.writes, keys: [...store.data.keys()].sort() };
}

async function recovered(
  store: ReturnType<typeof memoryStore>,
  identity: string,
  deviceId: string,
): Promise<void> {
  const loaded = await loadDevice(store);
  const local = ready(loaded.local);
  assert.equal(local.keys.identity, identity, "the same identity is restored");
  assert.equal(local.keys.deviceId, deviceId, "the same device is restored");
  const { restored } = await local.history.restore();
  assert.deepEqual(
    restored.map((m) => m.body),
    ["kept across failures"],
  );
  await loaded.close();
}

test("a temporary browser error while restoring keys is unavailable, never corrupted, and changes nothing", async () => {
  for (const method of [
    "sign",
    "verify",
    "deriveBits",
    "importKey",
    "generateKey",
  ] as const) {
    const { store, identity, deviceId } = await withHistory();
    const before = contents(store);
    const { result, failed } = await failing(method, () => loadDevice(store));
    assert.equal(failed, 1, `${method} was exercised`);
    assert.deepEqual(result.local, { status: "unavailable" }, method);
    assert.deepEqual(phaseOf(result.local.status), {
      phase: "fatal",
      reason: "storage_unavailable",
    });
    await result.close();
    assert.deepEqual(contents(store), before, `${method} changed storage`);
    await recovered(store, identity, deviceId);
  }
});

test("a temporary browser error while checking the stored device roster is unavailable", async () => {
  const { store, identity, deviceId } = await withHistory();
  const before = contents(store);
  const { result, failed } = await failing(
    "verify",
    () => loadDevice(store),
    rosterCheck,
  );
  assert.equal(failed, 1);
  assert.deepEqual(result.local, { status: "unavailable" });
  await result.close();
  assert.deepEqual(contents(store), before);
  await recovered(store, identity, deviceId);
});

test("a temporary browser error while rebuilding a missing roster is unavailable and the roster is rebuilt later", async () => {
  const { store, identity, deviceId } = await withHistory();
  store.data.delete("vault:roster");
  const before = contents(store);
  const { result, failed } = await failing(
    "verify",
    () => loadDevice(store),
    rosterCheck,
  );
  assert.equal(failed, 1);
  assert.deepEqual(result.local, { status: "unavailable" });
  await result.close();
  assert.deepEqual(contents(store), before, "no partial roster is stored");
  await recovered(store, identity, deviceId);
  assert.ok(store.data.has("vault:roster"));
});

function rebuildingWith(
  store: ReturnType<typeof memoryStore>,
  attempt: () => Promise<boolean>,
): () => void {
  const add = store.add;
  store.add = (name, key, value) =>
    name === "vault" && key === "roster" ? attempt() : add(name, key, value);
  return () => {
    store.add = add;
  };
}

test("a failed write while rebuilding a missing roster is unavailable, never corrupted", async () => {
  const { store, identity, deviceId } = await withHistory();
  store.data.delete("vault:roster");
  const before = contents(store);
  const restore = rebuildingWith(store, async () => false);
  const failed = await loadDevice(store);
  restore();
  assert.deepEqual(failed.local, { status: "unavailable" });
  assert.deepEqual(phaseOf(failed.local.status), {
    phase: "fatal",
    reason: "storage_unavailable",
  });
  await failed.close();
  assert.deepEqual(contents(store), before, "nothing was written");

  const undo = rebuildingWith(store, async () => false);
  const get = store.get;
  let reads = 0;
  store.get = async (name, key) => {
    if (name === "vault" && key === "roster" && ++reads === 2) {
      throw new DOMException("temporary", "UnknownError");
    }
    return get(name, key);
  };
  const throwing = await loadDevice(store);
  undo();
  store.get = get;
  assert.deepEqual(throwing.local, { status: "unavailable" });
  await throwing.close();

  await recovered(store, identity, deviceId);
  assert.ok(store.data.has("vault:roster"), "the roster is rebuilt later");
});

test("a missing roster is rebuilt on a healthy store and recovered from another tab only when valid", async () => {
  const healthy = await withHistory();
  healthy.store.data.delete("vault:roster");
  await recovered(healthy.store, healthy.identity, healthy.deviceId);
  assert.ok(healthy.store.data.has("vault:roster"));

  const raced = await withHistory();
  const theirs = raced.store.data.get("vault:roster");
  raced.store.data.delete("vault:roster");
  const restore = rebuildingWith(raced.store, async () => {
    raced.store.data.set("vault:roster", structuredClone(theirs));
    return false;
  });
  const won = await loadDevice(raced.store);
  restore();
  const local = ready(won.local);
  assert.deepEqual(local.devices.roster, theirs);
  await won.close();

  const foreign = await withHistory();
  const stranger = await withHistory();
  foreign.store.data.delete("vault:roster");
  const strangerRoster = stranger.store.data.get("vault:roster");
  const undo = rebuildingWith(foreign.store, async () => {
    foreign.store.data.set("vault:roster", structuredClone(strangerRoster));
    return false;
  });
  const rejected = await loadDevice(foreign.store);
  undo();
  assert.deepEqual(rejected.local, { status: "corrupted" });
  await rejected.close();
});

test("repeated temporary failures never replace the identity or its history", async () => {
  const { store, identity, deviceId } = await withHistory();
  for (let attempt = 0; attempt < 3; attempt++) {
    const { result } = await failing("sign", () => loadDevice(store));
    assert.deepEqual(result.local, { status: "unavailable" });
    await result.close();
  }
  await recovered(store, identity, deviceId);
  await recovered(store, identity, deviceId);
});

test("genuine integrity failures stay corrupted and are distinct from a missing identity", async () => {
  assert.deepEqual((await loadDevice(memoryStore())).local, {
    status: "empty",
  });

  const substituted = await withHistory();
  const other = await withHistory();
  const vault = substituted.store.data.get("vault:keys") as Record<
    string,
    unknown
  >;
  const foreign = other.store.data.get("vault:keys") as Record<string, unknown>;
  substituted.store.data.set("vault:keys", {
    ...vault,
    device: foreign.device,
  });
  const before = contents(substituted.store);
  const swapped = await loadDevice(substituted.store);
  assert.deepEqual(swapped.local, { status: "corrupted" });
  assert.deepEqual(phaseOf(swapped.local.status), {
    phase: "fatal",
    reason: "corrupted",
  });
  await swapped.close();
  assert.deepEqual(contents(substituted.store), before);

  const forged = await withHistory();
  const roster = forged.store.data.get("vault:roster") as {
    signature: string;
  };
  const flipped =
    (roster.signature[0] === "A" ? "B" : "A") + roster.signature.slice(1);
  forged.store.data.set("vault:roster", { ...roster, signature: flipped });
  const tampered = await loadDevice(forged.store);
  assert.deepEqual(tampered.local, { status: "corrupted" });
  await tampered.close();
});

const prekeyPrefix = new TextEncoder().encode("ghostx/prekeys/v2\0");

const prekeyCheck = (args: unknown[]) => {
  const data = new Uint8Array(args.at(-1) as Uint8Array);
  return prekeyPrefix.every((byte, i) => data[i] === byte);
};

function creatingPrekeysWith(
  store: ReturnType<typeof memoryStore>,
  attempt: () => Promise<boolean>,
): () => void {
  const add = store.add;
  store.add = (name, key, value) =>
    name === "vault" && key === "prekeys" ? attempt() : add(name, key, value);
  return () => {
    store.add = add;
  };
}

async function messagingKeys(
  store: ReturnType<typeof memoryStore>,
): Promise<unknown> {
  const loaded = await loadDevice(store);
  const local = ready(loaded.local);
  assert.notEqual(local.prekeys, null, "the prekeys are restored");
  await loaded.close();
  return store.data.get("vault:prekeys");
}

function flippedMac(record: unknown): unknown {
  const stored = record as { mac: string };
  return {
    ...stored,
    mac: (stored.mac[0] === "A" ? "B" : "A") + stored.mac.slice(1),
  };
}

test("a temporary browser error while checking stored prekeys is unavailable and changes nothing", async () => {
  const { store, identity, deviceId } = await withHistory();
  const prekeys = store.data.get("vault:prekeys");
  const before = contents(store);
  const { result, failed } = await failing(
    "verify",
    () => loadDevice(store),
    prekeyCheck,
  );
  assert.equal(failed, 1);
  assert.equal(result.local.status, "unavailable");
  await result.close();
  assert.deepEqual(contents(store), before);
  await recovered(store, identity, deviceId);
  assert.deepEqual(await messagingKeys(store), prekeys);
});

test("a failed write while creating missing prekeys is unavailable and the prekeys are created later", async () => {
  const { store, identity, deviceId } = await withHistory();
  store.data.delete("vault:prekeys");
  const before = contents(store);
  const restore = creatingPrekeysWith(store, async () => false);
  const failed = await loadDevice(store);
  restore();
  assert.equal(failed.local.status, "unavailable");
  await failed.close();
  assert.deepEqual(contents(store), before, "nothing was written");
  await recovered(store, identity, deviceId);
  assert.ok(store.data.has("vault:prekeys"), "the prekeys are created later");
  await messagingKeys(store);
});

test("a temporary browser error while checking prekeys written by another tab is unavailable", async () => {
  const { store, identity, deviceId } = await withHistory();
  const theirs = store.data.get("vault:prekeys");
  store.data.delete("vault:prekeys");
  const restore = creatingPrekeysWith(store, async () => {
    store.data.set("vault:prekeys", structuredClone(theirs));
    return false;
  });
  const { result, failed } = await failing(
    "verify",
    () => loadDevice(store),
    prekeyCheck,
  );
  restore();
  assert.equal(failed, 1);
  assert.equal(result.local.status, "unavailable");
  await result.close();
  await recovered(store, identity, deviceId);
  assert.deepEqual(await messagingKeys(store), theirs);
});

test("invalid prekeys still fail closed, and tabs creating prekeys together converge on one valid record", async () => {
  const tampered = await withHistory();
  tampered.store.data.set(
    "vault:prekeys",
    flippedMac(tampered.store.data.get("vault:prekeys")),
  );
  const before = contents(tampered.store);
  const closed = await loadDevice(tampered.store);
  assert.equal(ready(closed.local).prekeys, null);
  await closed.close();
  assert.deepEqual(contents(tampered.store), before);

  const raced = await withHistory();
  const theirs = raced.store.data.get("vault:prekeys");
  raced.store.data.delete("vault:prekeys");
  const restore = creatingPrekeysWith(raced.store, async () => {
    raced.store.data.set("vault:prekeys", structuredClone(theirs));
    return false;
  });
  const won = await loadDevice(raced.store);
  restore();
  assert.notEqual(ready(won.local).prekeys, null);
  await won.close();
  assert.deepEqual(raced.store.data.get("vault:prekeys"), theirs);

  const forged = await withHistory();
  const forgedRecord = flippedMac(forged.store.data.get("vault:prekeys"));
  forged.store.data.delete("vault:prekeys");
  const undo = creatingPrekeysWith(forged.store, async () => {
    forged.store.data.set("vault:prekeys", structuredClone(forgedRecord));
    return false;
  });
  const rejected = await loadDevice(forged.store);
  undo();
  assert.equal(ready(rejected.local).prekeys, null);
  await rejected.close();

  const shared = await withHistory();
  shared.store.data.delete("vault:prekeys");
  const tabs = await Promise.all([
    loadDevice(shared.store),
    loadDevice(shared.store),
  ]);
  for (const tab of tabs) {
    assert.notEqual(ready(tab.local).prekeys, null);
    await tab.close();
  }
  const record = shared.store.data.get("vault:prekeys");
  assert.deepEqual(await messagingKeys(shared.store), record);
});

function watched(store: ReturnType<typeof memoryStore>) {
  const usage = { closes: 0, late: [] as string[] };
  const methods = ["get", "getAll", "put", "add", "swap", "delete", "clear"];
  const target = store as unknown as Record<
    string,
    (...args: unknown[]) => Promise<unknown>
  >;
  for (const name of methods) {
    const original = target[name];
    target[name] = (...args: unknown[]) => {
      if (usage.closes > 0) {
        usage.late.push(`${name} ${args.slice(0, 2).join(":")}`);
      }
      return original.apply(store, args);
    };
  }
  const close = store.close;
  store.close = () => {
    usage.closes += 1;
    close.call(store);
  };
  return usage;
}

async function releasing<T>(
  run: () => Promise<T>,
): Promise<{ result: T; released: number; closed: number }> {
  const identity = IdentityKey.prototype.release;
  const exchange = ExchangeKey.prototype.release;
  const closes = [History, Trust, Pairs].map((type) => ({
    proto: type.prototype as { close(): Promise<void> },
    close: type.prototype.close,
  }));
  let released = 0;
  let closed = 0;
  IdentityKey.prototype.release = function () {
    released += 1;
    identity.call(this);
  };
  ExchangeKey.prototype.release = function () {
    released += 1;
    exchange.call(this);
  };
  for (const { proto, close } of closes) {
    proto.close = function () {
      closed += 1;
      return close.call(this);
    };
  }
  try {
    return { result: await run(), released, closed };
  } finally {
    IdentityKey.prototype.release = identity;
    ExchangeKey.prototype.release = exchange;
    for (const { proto, close } of closes) {
      proto.close = close;
    }
  }
}

test("a failed store open waits for the other stores, then releases the keys and closes the store once", async () => {
  const { store, identity, deviceId } = await withHistory();
  store.data.delete("vault:prekeys");
  store.data.delete("vault:roster");
  const usage = watched(store);
  let signal!: () => void;
  const prekeysFailed = new Promise<void>((resolve) => {
    signal = resolve;
  });
  const restore = creatingPrekeysWith(store, async () => {
    signal();
    return false;
  });
  let unblock!: () => void;
  const gate = new Promise<void>((resolve) => {
    unblock = resolve;
  });
  const get = store.get;
  store.get = async (name, key) => {
    if (name === "vault" && key === "roster") {
      await gate;
    }
    return get(name, key);
  };
  const { result, released, closed } = await releasing(async () => {
    const loading = loadDevice(store);
    await prekeysFailed;
    await new Promise((resolve) => setImmediate(resolve));
    unblock();
    return loading;
  });
  store.get = get;
  restore();
  assert.equal(result.local.status, "unavailable");
  assert.deepEqual(usage.late, [], "no store operation after the store closed");
  assert.equal(usage.closes, 1);
  assert.equal(released, 3, "the root, device and exchange keys are released");
  assert.equal(closed, 3, "the opened history, trust and pairs stores are closed");
  await result.close();
  assert.equal(usage.closes, 1, "closing the failed result closes nothing again");
  await recovered(store, identity, deviceId);
  await messagingKeys(store);
});

test("several failing store opens release the keys once and close the store once", async () => {
  const { store, identity, deviceId } = await withHistory();
  store.data.delete("vault:prekeys");
  store.data.delete("vault:roster");
  const usage = watched(store);
  const undoPrekeys = creatingPrekeysWith(store, async () => false);
  const undoRoster = rebuildingWith(store, async () => false);
  const { result, released, closed } = await releasing(() =>
    loadDevice(store),
  );
  undoRoster();
  undoPrekeys();
  assert.equal(result.local.status, "unavailable");
  assert.deepEqual(usage.late, [], "no store operation after the store closed");
  assert.equal(usage.closes, 1);
  assert.equal(released, 3, "each key is released exactly once");
  assert.equal(closed, 3, "each opened store is closed exactly once");
  await recovered(store, identity, deviceId);
  assert.ok(store.data.has("vault:roster") && store.data.has("vault:prekeys"));
});
