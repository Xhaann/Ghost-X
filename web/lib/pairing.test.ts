import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64Url } from "./base64.ts";
import { Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import { Messenger } from "./messenger.ts";
import { Pairing } from "./pairing.ts";
import { Pairs } from "./pairs.ts";
import { PrekeyStore, poolSize } from "./prekeys.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  freePort,
  memoryStore,
  secureDevice,
  startServer,
  stopServer,
  useServer,
} from "./testing.ts";
import { Trust } from "./trust.ts";
import { type Unlocked, loadVault } from "./vault.ts";

useServer();

type Store = ReturnType<typeof memoryStore>;
type Json = Record<string, unknown>;

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function device(port: number, store: Store = memoryStore()) {
  return secureDevice(port, { store });
}

function frames(list: string[], type: string): Json[] {
  return list.map((f) => JSON.parse(f) as Json).filter((f) => f.type === type);
}

test("establishes a session with an offline recipient that completes on reconnect", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  let b = await device(port, storeB);
  const idB = b.id;
  const published = frames(b.frames, "prekeys").find(
    (f) => (f.payload as Json).device,
  )?.payload as Json;
  assert.equal((published.onetime as Json[]).length, poolSize);
  await b.shutdown();

  const a = await device(port);
  assert.equal(await a.pairing.initiate(idB), "pending");
  assert.equal(a.pairs.state(idB), "pending");
  const sent = frames(a.frames, "initiate").at(-1)?.payload as Json;
  assert.deepEqual(Object.keys(sent).sort(), [
    "confirm",
    "device",
    "ephemeral",
    "onetime",
    "proof",
    "ratchet",
    "signed",
    "to",
    "version",
  ]);
  const bundle = frames(a.frames, "bundle").find(
    (f) => (f.payload as Json).bundles,
  )?.payload as Json;
  const reserved = ((bundle.bundles as Json[])[0].onetime as Json).id;
  assert.equal(sent.onetime, reserved);

  b = await device(port, storeB);
  assert.equal(b.id, idB);
  await until(
    () => b.pairs.state(a.id) === "established",
    "responder established",
  );
  await until(
    () => a.pairs.state(idB) === "established",
    "initiator established",
  );
  assert.equal(a.pairs.id(idB), b.pairs.id(a.id));
  assert.ok(!b.prekeys.inventory.onetime.includes(reserved as number));
  assert.equal(
    frames(b.frames, "initiation").length,
    1,
    "initiation delivered exactly once",
  );
  assert.deepEqual(await a.messenger.send(idB, "after async setup", "m1"), {
    ok: true,
  });

  for (const frame of [...a.frames, ...b.frames]) {
    assert.ok(!frame.includes("after async setup"));
    assert.ok(!/private|pkcs8/i.test(frame));
  }
});

test("establishes immediately when the recipient is online and survives reloads", async () => {
  const port = await freePort();
  await startServer(port);
  const storeA = memoryStore();
  const storeB = memoryStore();
  let a = await device(port, storeA);
  let b = await device(port, storeB);
  assert.equal(await a.pairing.initiate(b.id), "pending");
  await until(() => a.pairs.state(b.id) === "established", "established");
  const id = a.pairs.id(b.id);
  await a.shutdown();
  await b.shutdown();
  a = await device(port, storeA);
  b = await device(port, storeB);
  assert.equal(a.pairs.state(b.id), "established");
  assert.equal(b.pairs.state(a.id), "established");
  assert.equal(a.pairs.id(b.id), id);
  assert.equal(await a.pairing.initiate(b.id), "established");
});

test("a replayed initiation never creates a second session", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port);
  const b = await device(port);
  assert.equal(await a.pairing.initiate(b.id), "pending");
  await until(() => a.pairs.state(b.id) === "established", "established");
  const initiation = frames(b.frames, "initiation")[0];
  const first = b.pairs.id(a.id);
  const accepts = frames(b.frames, "accept").length;
  const inventory = b.prekeys.inventory.onetime.length;

  for (let i = 0; i < 3; i++) {
    b.deliver(JSON.stringify(initiation));
  }
  const noOnetime = {
    ...initiation,
    payload: { ...(initiation.payload as Json), onetime: null },
  };
  b.deliver(JSON.stringify(noOnetime));
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(frames(b.frames, "accept").length, accepts);
  assert.equal(b.pairs.id(a.id), first);
  assert.equal(b.prekeys.inventory.onetime.length, inventory);

  const replay = await a.client.request({
    type: "initiate",
    payload: frames(a.frames, "initiate")[0].payload as never,
  });
  assert.equal(replay?.type, "error");
});

test("a replay without a one-time prekey is caught by the consumed-initiation record", async () => {
  const port = await freePort();
  await startServer(port);
  const b = await device(port);
  for (let i = 0; i < poolSize + 1; i++) {
    const reply = await b.client.request({
      type: "bundle",
      payload: { identity: b.id },
    });
    assert.equal(reply?.type, "bundle");
  }
  const a = await device(port);
  assert.equal(await a.pairing.initiate(b.id), "pending");
  const sent = frames(a.frames, "initiate").at(-1)?.payload as Json;
  assert.equal(sent.onetime === null || typeof sent.onetime === "number", true);
  await until(() => a.pairs.state(b.id) === "established", "established");
  const initiation = frames(b.frames, "initiation")[0];
  const accepts = frames(b.frames, "accept").length;
  b.deliver(JSON.stringify(initiation));
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(frames(b.frames, "accept").length, accepts);
});

test("malicious bundle substitutions are rejected before any initiation", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port);
  const b = await device(port);
  const c = await device(port);
  const genuine = await a.client.request({
    type: "bundle",
    payload: { identity: b.id },
  });
  const other = await a.client.request({
    type: "bundle",
    payload: { identity: c.id },
  });
  assert.ok(genuine?.type === "bundle" && other?.type === "bundle");
  const g = genuine.payload;
  const o = other.payload;
  const gb = g.bundles[0];
  const ob = o.bundles[0];
  const gOnetime = gb.onetime;
  assert.ok(gOnetime && ob.onetime);
  const substitutions = [
    { ...g, key: o.key, signature: o.signature },
    { ...g, bundles: [{ ...gb, signed: ob.signed }] },
    {
      ...g,
      bundles: [{ ...gb, signed: { ...gb.signed, key: ob.signed.key } }],
    },
    {
      ...g,
      bundles: [{ ...gb, signed: { ...gb.signed, id: gb.signed.id + 1 } }],
    },
    {
      ...g,
      bundles: [
        { ...gb, signed: { ...gb.signed, signature: ob.signed.signature } },
      ],
    },
    { ...g, bundles: [{ ...gb, onetime: ob.onetime }] },
    {
      ...g,
      bundles: [{ ...gb, onetime: { ...gOnetime, id: gOnetime.id + 1 } }],
    },
    {
      ...g,
      bundles: [{ ...gb, onetime: { ...gOnetime, key: gb.signed.key } }],
    },
    { ...g, bundles: [{ ...gb, device: ob.device }] },
    {
      ...g,
      bundles: [
        { ...gb, onetime: { ...gOnetime, signature: gb.signed.signature } },
      ],
    },
  ];
  const original = a.client.request.bind(a.client);
  for (const payload of substitutions) {
    a.client.request = (async (...args: Parameters<Client["request"]>) =>
      args[0].type === "bundle"
        ? { type: "bundle", id: "q", payload }
        : original(...args)) as Client["request"];
    const before = frames(a.frames, "initiate").length;
    assert.equal(await a.pairing.initiate(b.id), "invalid_bundle");
    assert.equal(frames(a.frames, "initiate").length, before);
    assert.equal(a.pairs.state(b.id), "none");
  }
  a.client.request = (async (...args: Parameters<Client["request"]>) =>
    args[0].type === "bundle"
      ? {
          type: "bundle",
          id: "q",
          payload: { ...g, identity: c.id },
        }
      : original(...args)) as Client["request"];
  assert.equal(await a.pairing.initiate(b.id), "failed");
  a.client.request = original;
  assert.equal(await a.pairing.initiate(b.id), "pending");
  await until(() => a.pairs.state(b.id) === "established", "genuine");
});

test("one-time prekeys are reserved atomically, consumed once, and replenished", async () => {
  const port = await freePort();
  await startServer(port);
  const b = await device(port);
  const initiators = await Promise.all(
    Array.from({ length: 6 }, () => device(port)),
  );
  const results = await Promise.all(
    initiators.map((i) => i.pairing.initiate(b.id)),
  );
  assert.ok(results.every((r) => r === "pending"));
  const used = initiators.map(
    (i) => (frames(i.frames, "initiate").at(-1)?.payload as Json).onetime,
  );
  assert.equal(new Set(used).size, used.length);
  await until(
    () => initiators.every((i) => i.pairs.state(b.id) === "established"),
    "all established",
  );
  for (const id of used) {
    assert.ok(!b.prekeys.inventory.onetime.includes(id as number));
  }

  for (let i = 0; i < poolSize; i++) {
    await b.client.request({ type: "bundle", payload: { identity: b.id } });
  }
  const drained = await b.client.request({
    type: "bundle",
    payload: { identity: b.id },
  });
  assert.ok(drained?.type === "bundle");
  assert.equal(drained.payload.bundles[0].onetime, null);
  const before = b.prekeys.inventory.onetime.at(-1) ?? 0;
  assert.equal(await b.pairing.publish(), true);
  assert.ok((b.prekeys.inventory.onetime.at(-1) ?? 0) > before);
  const refilled = await b.client.request({
    type: "bundle",
    payload: { identity: b.id },
  });
  assert.ok(refilled?.type === "bundle" && refilled.payload.bundles[0].onetime);
  assert.ok(b.prekeys.inventory.onetime.length <= 40);
});

test("signed prekey rotation keeps one previous key for delayed initiations", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  let b = await device(port, storeB);
  const first = b.prekeys.inventory.signed;
  await b.shutdown();
  const a = await device(port);
  assert.equal(await a.pairing.initiate(b.id), "pending");
  const d = await device(port);

  b = await device(port, storeB);
  await until(() => a.pairs.state(b.id) === "established", "a established");
  assert.equal(await b.prekeys.rotate(), true);
  assert.equal(await b.pairing.publish(), true);
  assert.equal(b.prekeys.inventory.previous, first);
  assert.equal(await d.pairing.initiate(b.id), "pending");
  await until(() => d.pairs.state(b.id) === "established", "d established");
  const used = (frames(d.frames, "initiate").at(-1)?.payload as Json).signed;
  assert.equal(used, first + 1);

  assert.equal(await b.prekeys.rotate(), true);
  assert.equal(await b.prekeys.rotate(), true);
  assert.equal(b.prekeys.inventory.previous, first + 2);
  const stale = frames(b.frames, "initiation")[0];
  const accepts = frames(b.frames, "accept").length;
  b.deliver(
    JSON.stringify({
      ...stale,
      payload: {
        ...(stale.payload as Json),
        ephemeral: (stale.payload as Json).key,
      },
    }),
  );
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(frames(b.frames, "accept").length, accepts);
});

test("verification survives prekey rotation and asynchronous sessions but not a key change", async () => {
  const port = await freePort();
  await startServer(port);
  const storeB = memoryStore();
  const a = await device(port);
  let b = await device(port, storeB);
  const { fingerprint } = await import("./fingerprint.ts");
  const own = await fingerprint(b.id, b.keys.exchange.publicKey);
  assert.ok(own);
  await a.messenger.lookup(b.id);
  await until(() => a.trust.view(b.id).state === "unverified", "observed");
  assert.equal(await a.trust.verify(b.id, own.value), true);

  assert.equal(await b.prekeys.rotate(), true);
  assert.equal(await b.pairing.publish(), true);
  assert.equal(await a.pairing.initiate(b.id), "pending");
  await until(() => a.pairs.state(b.id) === "established", "established");
  assert.equal(a.trust.view(b.id).state, "verified");

  await b.shutdown();
  const changed = memoryStore();
  for (const [key, value] of storeB.data) {
    if (key === "vault:keys") {
      const { ExchangeKey } = await import("./encryption.ts");
      const fresh = await ExchangeKey.create();
      changed.data.set(key, {
        ...(value as Json),
        exchangeKey: fresh.key.publicKey,
        exchange: fresh.privateKey,
      });
    }
  }
  const idB = b.id;
  b = await device(port, changed);
  assert.equal(b.id, idB);
  await a.messenger.lookup(b.id);
  await until(() => a.trust.view(b.id).state === "changed", "changed");
  const renewed = await fingerprint(b.id, b.keys.exchange.publicKey);
  assert.ok(renewed);
  assert.equal(await a.trust.verify(b.id, renewed.value), true);
});

test("the server never receives private prekey material and cannot complete a handshake", async () => {
  const port = await freePort();
  const server = await startServer(port);
  const a = await device(port);
  const b = await device(port);
  assert.equal(await a.pairing.initiate(b.id), "pending");
  await until(() => a.pairs.state(b.id) === "established", "established");
  const outbound = [...a.frames, ...b.frames]
    .map((f) => JSON.parse(f) as Json)
    .filter(
      (f) =>
        ["prekeys", "initiate", "accept"].includes(f.type as string) && f.id,
    );
  for (const frame of outbound) {
    const text = JSON.stringify(frame.payload);
    assert.ok(!/private|secret|root/i.test(text));
  }
  const prekeyFrame = frames(b.frames, "prekeys").find((f) => f.id)
    ?.payload as Json;
  assert.deepEqual(Object.keys(prekeyFrame).sort(), [
    "device",
    "onetime",
    "signed",
  ]);
  assert.deepEqual(Object.keys(prekeyFrame.signed as Json).sort(), [
    "id",
    "key",
    "signature",
  ]);
  await stopServer(server);
});

test("a stripped one-time prekey or a stale replayed bundle is handled safely", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await device(port);
  const b = await device(port);
  const fresh = await a.client.request({
    type: "bundle",
    payload: { identity: b.id },
  });
  assert.ok(fresh?.type === "bundle");
  const stale = structuredClone(fresh.payload);
  const original = a.client.request.bind(a.client);
  a.client.request = (async (...args: Parameters<Client["request"]>) =>
    args[0].type === "bundle"
      ? {
          type: "bundle",
          id: "q",
          payload: {
            ...fresh.payload,
            bundles: [{ ...fresh.payload.bundles[0], onetime: null }],
          },
        }
      : original(...args)) as Client["request"];
  assert.equal(await a.pairing.initiate(b.id), "pending");
  assert.equal(
    (frames(a.frames, "initiate").at(-1)?.payload as Json).onetime,
    null,
  );
  await until(() => a.pairs.state(b.id) === "established", "three-key path");

  for (let i = 0; i < 2; i++) {
    assert.equal(await b.prekeys.rotate(), true);
    assert.equal(await b.pairing.publish(), true);
  }
  const c = await device(port);
  const real = c.client.request.bind(c.client);
  c.client.request = (async (...args: Parameters<Client["request"]>) =>
    args[0].type === "bundle"
      ? { type: "bundle", id: "q", payload: stale }
      : real(...args)) as Client["request"];
  assert.equal(await c.pairing.initiate(b.id), "failed");
  assert.equal(c.pairs.state(b.id), "none");
  const error = frames(c.frames, "error").at(-1)?.payload as Json;
  assert.equal(error.code, "stale_session");
});

test("only a missing session triggers recovery; pending or established sessions never re-key on input", async () => {
  const port = await freePort();
  await startServer(port);
  const { encodeHeader, generateRatchetKey } = await import("./ratchet.ts");
  const probe = async () => {
    const header = encodeHeader({
      session: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
      ratchet: (await generateRatchetKey()).publicKey,
      previous: 0,
      n: 0,
    });
    assert.ok(header);
    return new Uint8Array([...header, ...new Uint8Array(17)]);
  };
  const initiations = (d: { frames: string[] }) =>
    frames(d.frames, "initiate").filter((f) => (f.payload as Json).to).length;

  const storeB = memoryStore();
  let b = await device(port, storeB);
  const idB = b.id;
  await b.shutdown();
  const a = await device(port);
  assert.equal(await a.pairing.initiate(idB), "pending");
  const pendingCount = initiations(a);
  assert.equal(await a.pairing.open(idB, await probe()), null);
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(initiations(a), pendingCount);
  assert.equal(a.pairs.state(idB), "pending");

  b = await device(port, storeB);
  await until(() => a.pairs.state(idB) === "established", "established");
  const session = a.pairs.id(idB);
  assert.equal(await a.pairing.open(idB, await probe()), null);
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(initiations(a), pendingCount);
  assert.equal(a.pairs.id(idB), session);

  const c = await device(port);
  assert.equal(await c.pairing.open(idB, await probe()), null);
  await until(() => initiations(c) === 1, "recovery initiation");
  await until(() => c.pairs.state(idB) === "established", "recovered");
});
