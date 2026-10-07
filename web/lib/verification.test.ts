import assert from "node:assert/strict";
import { test } from "node:test";
import { Conversations } from "./conversations.ts";
import { rosterFingerprint } from "./device.ts";
import { pairAddress } from "./pairs.ts";
import {
  type SecureDevice,
  freePort,
  linkedDevice,
  memoryStore,
  secureDevice,
  startServer,
  stopServer,
  useServer,
} from "./testing.ts";
import { createVault } from "./vault.ts";

useServer();

type Store = ReturnType<typeof memoryStore>;

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function device(port: number, store: Store) {
  return wrap(await secureDevice(port, { store, inbox: false }));
}

async function linked(port: number, root: SecureDevice) {
  return wrap(await linkedDevice(port, root, { inbox: false }));
}

async function wrap(secure: SecureDevice) {
  const { restored } = await secure.history.restore();
  const conversations = new Conversations(secure.messenger, secure.id, {
    history: secure.history,
    restored,
  });
  conversations.start();
  await until(() => conversations.state.connected, "connected");
  return {
    ...secure,
    conversations,
    shutdown: async () => {
      conversations.stop();
      await secure.shutdown();
    },
  };
}

async function identityStore(): Promise<Store> {
  const store = memoryStore();
  assert.equal((await createVault(store)).status, "ready");
  return store;
}

async function own(d: SecureDevice) {
  assert.ok(d.devices.roster);
  const print = await rosterFingerprint(d.devices.roster);
  assert.ok(print);
  return print;
}

function address(d: SecureDevice): string {
  return pairAddress(d.id, d.deviceId);
}

function thread(conversations: Conversations, peer: string): (string | null)[] {
  return (
    conversations.state.conversations
      .find((c) => c.identity === peer)
      ?.messages.map((m) => m.body) ?? []
  );
}

test("verify, detect a device change, and re-verify with a real server", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const storeA = memoryStore();
  let a = await device(port, storeA);
  const bStore = await identityStore();
  let b = await device(port, bStore);
  const bKeys = b.keys;
  const idB = bKeys.identity;
  const idA = a.keys.identity;

  assert.equal(a.trust.view(idB).state, "unavailable");
  assert.equal(await a.messenger.lookup(idB), true);
  await until(() => a.trust.view(idB).state === "unverified", "unverified");
  const bPrint = await own(b);
  assert.deepEqual(a.trust.view(idB).current, bPrint);
  assert.equal(b.conversations.state.connected, true);

  assert.equal(await a.trust.verify(idB, bPrint.value), true);
  assert.equal(a.trust.view(idB).state, "verified");

  a.conversations.open(idB);
  const first = a.conversations.send("verified hello");
  assert.ok(first.accepted);
  if (first.accepted) {
    assert.equal(await first.delivery, "queued");
  }
  await until(() => thread(b.conversations, idA).length === 1, "b receives");
  assert.deepEqual(thread(b.conversations, idA), ["verified hello"]);
  b.conversations.open(idA);
  const reply = b.conversations.send("reply");
  assert.ok(reply.accepted);
  await until(() => thread(a.conversations, idB).length === 2, "a receives");
  assert.equal(a.trust.view(idB).state, "verified");

  await a.shutdown();
  a = await device(port, storeA);
  assert.equal(a.trust.view(idB).state, "unavailable");
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "verified", "reload");
  assert.deepEqual(thread(a.conversations, idB), ["verified hello", "reply"]);

  await stopServer(server);
  await until(() => !a.conversations.state.connected, "disconnected");
  assert.equal(a.trust.view(idB).state, "verified");
  await startServer(port);
  await until(
    () => a.conversations.state.connected && b.conversations.state.connected,
    "reconnected",
  );
  assert.equal(await a.messenger.lookup(idB), true);
  assert.equal(a.trust.view(idB).state, "verified");

  const b2 = await linked(port, b);
  const rotated = await own(b);
  assert.notEqual(rotated.value, bPrint.value);

  b2.conversations.open(idA);
  const changedMessage = b2.conversations.send("from the new device");
  assert.ok(changedMessage.accepted);
  await until(
    () => thread(a.conversations, idB).length === 3,
    "a receives from new key",
  );
  await until(() => a.trust.view(idB).state === "changed", "changed");
  assert.deepEqual(a.trust.view(idB).current, rotated);
  assert.deepEqual(a.trust.view(idB).verified, bPrint);
  assert.equal(
    a.conversations.state.conversations.find((c) => c.identity === idB)?.unread,
    1,
  );
  assert.equal(await a.trust.verify(idB, bPrint.value), false);

  await a.trust.flush();
  await a.shutdown();
  a = await device(port, storeA);
  assert.equal(a.trust.view(idB).state, "changed");
  await a.messenger.lookup(idB);
  await until(
    () => a.trust.view(idB).current?.value === rotated.value,
    "observed rotated key",
  );
  assert.equal(a.trust.view(idB).state, "changed");
  assert.deepEqual(thread(a.conversations, idB), [
    "verified hello",
    "reply",
    "from the new device",
  ]);

  assert.equal(await a.trust.verify(idB, rotated.value), true);
  assert.equal(a.trust.view(idB).state, "verified");
  a.conversations.open(idB);
  const after = a.conversations.send("after re-verification");
  assert.ok(after.accepted);
  if (after.accepted) {
    assert.equal(await after.delivery, "queued");
  }
  for (const d of [b, b2]) {
    await until(
      () => thread(d.conversations, idA).includes("after re-verification"),
      "every device of b receives",
    );
  }

  for (const frame of [...a.frames, ...b.frames, ...b2.frames]) {
    for (const secret of [
      "verified hello",
      "from the new device",
      "after re-verification",
    ]) {
      assert.ok(!frame.includes(secret), "plaintext crossed the wire");
    }
    assert.ok(!frame.includes(bPrint.value) && !frame.includes(rotated.value));
    assert.ok(
      !/verif|trust|fingerprint/i.test(
        frame.replace(/"[A-Za-z0-9_-]{20,}"/g, ""),
      ),
    );
  }
});

test("verification is independent of sessions, connections, and presence", async () => {
  const port = await freePort();
  await startServer(port);
  const storeA = memoryStore();
  const a = await device(port, storeA);
  const bStore = await identityStore();
  const b1 = await device(port, bStore);
  const b2 = await device(port, bStore);
  const bKeys = b1.keys;
  const idB = bKeys.identity;

  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "unverified", "observed");
  assert.equal(await a.trust.verify(idB, (await own(b1)).value), true);
  await b1.shutdown();
  await a.messenger.lookup(idB);
  assert.equal(a.trust.view(idB).state, "verified");
  await b2.shutdown();
  assert.equal(await a.messenger.lookup(idB), true);
  assert.equal(a.trust.view(idB).state, "verified");
  const b3 = await device(port, bStore);
  assert.equal(await a.messenger.lookup(idB), true);
  assert.equal(a.trust.view(idB).state, "verified");
  await b3.shutdown();
});

test("another client's verification never changes local trust", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port, memoryStore());
  const c = await device(port, memoryStore());
  const bStore = await identityStore();
  const b = await device(port, bStore);
  const idB = b.id;
  const bPrint = await own(b);

  await c.messenger.lookup(idB);
  await until(() => c.trust.view(idB).state === "unverified", "c observed");
  assert.equal(await c.trust.verify(idB, bPrint.value), true);
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "unverified", "a observed");
  assert.equal(a.trust.view(idB).state, "unverified");
  await a.messenger.lookup(c.keys.identity);
  await until(
    () => a.trust.view(c.keys.identity).state === "unverified",
    "a sees c unverified",
  );
});

test("verification survives ratchet advancement and reconnects but not a device change", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port, memoryStore());
  const bStore = await identityStore();
  let b = await device(port, bStore);
  const bKeys = b.keys;
  const idA = a.keys.identity;
  const idB = bKeys.identity;
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "unverified", "observed");
  assert.equal(await a.trust.verify(idB, (await own(b)).value), true);

  b.conversations.open(idA);
  for (let i = 0; i < 8; i++) {
    const attempt = b.conversations.send(`advancing ${i}`);
    assert.ok(attempt.accepted);
    if (attempt.accepted) {
      assert.equal(await attempt.delivery, "queued");
    }
    await until(() => thread(a.conversations, idB).length === i + 1, `rx ${i}`);
    assert.equal(a.trust.view(idB).state, "verified");
  }
  const sessionBefore = a.pairs.id(address(b));
  await b.shutdown();
  b = await device(port, bStore);
  b.conversations.open(idA);
  const again = b.conversations.send("after reconnect");
  assert.ok(again.accepted);
  await until(() => thread(a.conversations, idB).length === 9, "reconnect rx");
  assert.equal(a.pairs.id(address(b)), sessionBefore);
  await a.messenger.lookup(idB);
  assert.equal(a.trust.view(idB).state, "verified");

  await linked(port, b);
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "changed", "changed");
  assert.equal(await a.trust.verify(idB, (await own(b)).value), true);
  assert.equal(a.trust.view(idB).state, "verified");
});

test("ratchet key changes and session resets never alter verification; device changes do", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port, memoryStore());
  const bStore = await identityStore();
  let b = await device(port, bStore);
  const idB = b.id;
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "unverified", "observed");
  assert.equal(await a.trust.verify(idB, (await own(b)).value), true);

  const ratchetKey = async () =>
    a.pairs.transact(address(b), async (state) => ({
      state,
      value: Buffer.from(state.own.publicKey).toString("base64url"),
    }));
  const exchange = async (rounds: number, label: string) => {
    for (let i = 0; i < rounds; i++) {
      assert.equal((await a.messenger.send(idB, `${label} a${i}`)).ok, true);
      await until(
        () => thread(b.conversations, a.id).includes(`${label} a${i}`),
        `b rx ${label}`,
      );
      assert.equal((await b.messenger.send(a.id, `${label} b${i}`)).ok, true);
      await until(
        () => thread(a.conversations, idB).includes(`${label} b${i}`),
        "a rx",
      );
    }
  };
  await exchange(1, "first");
  const keys = new Set([await ratchetKey()]);
  for (let i = 0; i < 4; i++) {
    await exchange(1, `round ${i}`);
    keys.add(await ratchetKey());
  }
  assert.equal(keys.size, 5);
  assert.equal(a.trust.view(idB).state, "verified");

  const sessionBefore = a.pairs.id(address(b));
  await b.shutdown();
  bStore.data.delete(`pairs:${pairAddress(a.id, a.deviceId)}`);
  b = await device(port, bStore);
  assert.equal((await a.messenger.send(idB, "lost before recovery")).ok, true);
  await until(
    () => thread(b.conversations, a.id).includes(null),
    "undecryptable arrives",
  );
  await until(
    () =>
      a.pairs.state(address(b)) === "established" &&
      a.pairs.id(address(b)) !== sessionBefore,
    "recovered session",
  );
  await exchange(1, "after reset");
  assert.notEqual(a.pairs.id(address(b)), sessionBefore);
  assert.equal(a.trust.view(idB).state, "verified");

  const b2 = await linked(port, b);
  assert.equal((await b2.messenger.send(a.id, "new device hello")).ok, true);
  await until(
    () => thread(a.conversations, idB).includes("new device hello"),
    "a rx from new device",
  );
  await exchange(1, "new long-term key");
  await a.messenger.lookup(idB);
  await until(() => a.trust.view(idB).state === "changed", "changed");
  await exchange(2, "still changed");
  assert.equal(a.trust.view(idB).state, "changed");
  assert.equal(await a.trust.verify(idB, (await own(b)).value), true);
  assert.equal(a.trust.view(idB).state, "verified");
});
