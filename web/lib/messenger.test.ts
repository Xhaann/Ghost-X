import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { ExchangeKey, type KeyBundle } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import { createMessageId, maxBodySize } from "./protocol.ts";
import {
  type MemoryStore,
  type SecureDevice,
  freePort,
  memoryStore,
  secureDevice,
  startServer,
  useServer,
} from "./testing.ts";
import { loadVault } from "./vault.ts";

useServer();

type Peer = SecureDevice;

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

async function stranger(): Promise<string> {
  return (await IdentityKey.generate()).identity;
}

async function identityStore(): Promise<MemoryStore> {
  const store = memoryStore();
  assert.equal((await loadVault(store)).status, "ready");
  return store;
}

async function conflictingDevice(source: MemoryStore): Promise<MemoryStore> {
  const store = memoryStore();
  const fresh = await ExchangeKey.create();
  store.data.set("vault:keys", {
    ...(source.data.get("vault:keys") as Json),
    exchangeKey: fresh.key.publicKey,
    exchange: fresh.privateKey,
  });
  return store;
}

function peer(port: number, store = memoryStore()): Promise<Peer> {
  return secureDevice(port, { store });
}

async function barrier(p: Peer): Promise<void> {
  const reply = await p.client.request({
    type: "ping",
    payload: { sentAt: 1 },
  });
  assert.equal(reply?.type, "pong");
}

async function settle(...peers: Peer[]): Promise<void> {
  for (const p of peers) {
    await barrier(p);
  }
  await new Promise((resolve) => setTimeout(resolve, 50));
  for (const p of peers) {
    await barrier(p);
  }
}

function frames(list: string[], type: string): Json[] {
  return list
    .map((raw) => JSON.parse(raw) as Json)
    .filter((frame) => frame.type === type);
}

function deliveries(p: Peer): Json[] {
  return frames(p.received, "message").map((f) => f.payload as Json);
}

function lastDelivery(p: Peer): Json {
  const all = deliveries(p);
  assert.ok(all.length > 0);
  return structuredClone(all.at(-1) as Json);
}

function inject(p: Peer, payload: Json) {
  p.deliver(JSON.stringify({ type: "message", payload }));
}

function flip(text: string, index: number): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 1;
  return encodeBase64Url(bytes);
}

function bodies(p: Peer): (string | null)[] {
  return p.inbox.map((m) => m.body);
}

function acks(p: Peer): Json[] {
  return frames(p.sent, "ack").map((f) => f.payload as Json);
}

async function paired(port: number): Promise<[Peer, Peer]> {
  const a = await peer(port);
  const b = await peer(port);
  assert.equal(await a.pairing.establish(b.id), "established");
  return [a, b];
}

test("activates after publishing the static key and subscribes to its queue", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  assert.equal(a.messenger.state.active, true);
  const types = a.sent.map((raw) => JSON.parse(raw).type);
  assert.ok(types.indexOf("publish") < types.indexOf("fetch"));
  assert.equal(frames(a.sent, "session").length, 0);
  assert.equal(frames(a.received, "fetched").length, 1);
});

test("sends only ratchet ciphertext with a fresh message identifier", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  const secret = "the server must never read this 🔒";

  assert.deepEqual(await a.messenger.send(b.id, secret), { ok: true });
  await until(() => b.inbox.length === 1, "delivery");
  const send = frames(a.sent, "send")[0].payload as Json;
  assert.deepEqual(Object.keys(send).sort(), ["ciphertext", "id", "to"]);
  assert.match(send.id as string, /^[A-Za-z0-9_-]{22}$/);
  const ciphertext = decodeBase64Url(
    send.ciphertext,
    Math.floor(((send.ciphertext as string).length * 3) / 4),
  );
  assert.ok(ciphertext);
  assert.equal(ciphertext[0], 1);
  assert.deepEqual(b.inbox, [{ id: send.id, from: a.id, body: secret }]);
  assert.deepEqual(lastDelivery(b), {
    id: send.id,
    from: a.id,
    key: a.keys.exchange.publicKey,
    signature: deliveries(b)[0].signature,
    ciphertext: send.ciphertext,
  });
  await until(() => acks(b).length === 1, "acknowledged");
  assert.deepEqual(acks(b)[0], { from: a.id, id: send.id });
  await until(() => a.receipts.length === 1, "receipt");
  assert.deepEqual(a.receipts[0], {
    to: b.id,
    id: send.id,
    status: "delivered",
  });
  await until(() => frames(a.sent, "clear").length === 1, "cleared");

  const encoded = encodeBase64Url(new TextEncoder().encode(secret));
  for (const frame of [...a.sent, ...a.received, ...b.sent, ...b.received]) {
    assert.ok(!frame.includes(secret), "plaintext crossed the wire");
    assert.ok(!frame.includes(encoded), "encoded plaintext crossed the wire");
    assert.ok(!/private|pkcs8|"root"|"chain"/i.test(frame));
  }
  const second = await a.messenger.send(b.id, "again");
  assert.deepEqual(second, { ok: true });
  const ids = frames(a.sent, "send").map((f) => (f.payload as Json).id);
  const texts = frames(a.sent, "send").map(
    (f) => (f.payload as Json).ciphertext,
  );
  assert.notEqual(ids[0], ids[1]);
  assert.notEqual(texts[0], texts[1]);
});

test("acknowledges only after the receiver durably accepted the message", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  b.failStorage(true);
  assert.deepEqual(await a.messenger.send(b.id, "must survive"), { ok: true });
  await until(() => deliveries(b).length === 1, "delivered to b");
  await settle(a, b);
  assert.equal(acks(b).length, 0);
  assert.equal(b.inbox.length, 0);
  assert.equal(a.receipts.length, 0);

  b.failStorage(false);
  await b.client.request({ type: "fetch", payload: {} });
  await until(() => b.inbox.length === 1, "redelivered");
  assert.equal(b.inbox[0].body, "must survive");
  await until(() => acks(b).length === 1, "acknowledged");
  await until(() => a.receipts.length === 1, "receipt");
});

test("tampered, misdirected, or rebound deliveries never decrypt or advance the ratchet", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  const c = await peer(port);
  assert.equal(await c.pairing.establish(b.id), "established");

  b.hold(true);
  await a.messenger.send(b.id, "original");
  await until(() => frames(b.received, "message").length === 1, "held");
  b.hold(false);
  const good = lastDelivery(b);
  await c.messenger.send(b.id, "from c");
  await until(() => b.inbox.length === 1, "c to b");
  const fromC = lastDelivery(b);
  const state = async () =>
    b.pairs.transact(a.id, async (s) => ({
      state: s,
      value: JSON.stringify([s.receiving?.n ?? null, s.skipped.length]),
    }));
  const before = await state();

  const text = good.ciphertext as string;
  const mutations: Record<string, Json> = {
    "header version": { ...good, ciphertext: flip(text, 0) },
    "header session": { ...good, ciphertext: flip(text, 5) },
    "header ratchet key": { ...good, ciphertext: flip(text, 20) },
    "header previous": { ...good, ciphertext: flip(text, 50) },
    "header number": { ...good, ciphertext: flip(text, 56) },
    body: { ...good, ciphertext: flip(text, 70) },
    tag: {
      ...good,
      ciphertext: flip(text, -1 + Math.floor((text.length * 3) / 4)),
    },
    "message id": { ...good, id: createMessageId() },
    "sender identity": {
      ...good,
      from: c.id,
      key: fromC.key,
      signature: fromC.signature,
    },
    "another session's ciphertext": { ...good, ciphertext: fromC.ciphertext },
    "static binding": { ...good, signature: fromC.signature },
    truncated: { ...good, ciphertext: text.slice(0, text.length - 8) },
  };
  for (const [name, payload] of Object.entries(mutations)) {
    const count = b.inbox.length;
    inject(b, payload);
    await settle(b);
    assert.ok(
      b.inbox.length === count || b.inbox.at(-1)?.body === null,
      `${name} produced plaintext`,
    );
    assert.equal(await state(), before, `${name} moved the ratchet`);
  }
  inject(b, good);
  await until(() => bodies(b).includes("original"), "control");
  assert.notEqual(await state(), before);
});

test("replayed and duplicated deliveries create exactly one message", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  b.hold(true);
  await a.messenger.send(b.id, "exactly once");
  await until(() => frames(b.received, "message").length === 1, "held");
  b.hold(false);
  const frame = lastDelivery(b);
  inject(b, frame);
  inject(b, frame);
  inject(b, frame);
  await settle(b);
  assert.deepEqual(bodies(b), ["exactly once"]);
  assert.equal(acks(b).length, 3);

  b.messenger.stop();
  b.messenger.start();
  await until(() => b.messenger.state.active, "re-established");
  inject(b, frame);
  inject(b, { ...frame, id: createMessageId() });
  await settle(b);
  assert.deepEqual(bodies(b), ["exactly once", null]);
});

test("reports unavailable recipients, pending sessions, and invalid input without sending", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const absent = await stranger();
  assert.deepEqual(await a.messenger.send(absent, "x"), {
    ok: false,
    reason: "recipient_unavailable",
  });
  for (const [to, body, id, reason] of [
    ["not-an-identity", "x", createMessageId(), "invalid_payload"],
    [a.id, "x", createMessageId(), "invalid_payload"],
    [absent, "x", "m1", "invalid_payload"],
    [absent, "", createMessageId(), "invalid_payload"],
    [absent, "a\u0000", createMessageId(), "invalid_payload"],
    [
      absent,
      "a".repeat(maxBodySize + 1),
      createMessageId(),
      "message_too_large",
    ],
  ] as const) {
    assert.deepEqual(await a.messenger.send(to, body, id), {
      ok: false,
      reason,
    });
  }
  assert.equal(frames(a.sent, "send").length, 0);
  assert.equal(frames(a.sent, "bundle").length, 1);
});

test("a second session cannot bind a different static key", async () => {
  const port = await freePort();
  await startServer(port);
  const first = await identityStore();
  await peer(port, first);
  const conflicting = await secureDevice(port, {
    store: await conflictingDevice(first),
    wait: false,
  });
  await until(
    () => frames(conflicting.received, "error").length > 0,
    "conflict rejected",
  );
  assert.equal(conflicting.messenger.state.active, false);
});

test("reports only verified static key bundles from lookups and deliveries", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  const c = await peer(port);
  const seen: string[] = [];
  a.messenger.onKey((bundle: KeyBundle) =>
    seen.push(
      `${bundle.key === b.keys.exchange.publicKey ? "b" : bundle.key === c.keys.exchange.publicKey ? "c" : "?"}:${bundle.identity === (bundle.key === b.keys.exchange.publicKey ? b.id : c.id)}`,
    ),
  );
  assert.equal(await a.messenger.lookup(b.id), true);
  assert.equal(await a.messenger.lookup("not-an-identity"), false);
  assert.equal(await a.messenger.lookup(await stranger()), false);
  await b.messenger.send(a.id, "y");
  await until(() => a.inbox.length === 1, "delivery");
  inject(a, {
    ...lastDelivery(a),
    id: createMessageId(),
    key: c.keys.exchange.publicKey,
  });
  await until(() => a.inbox.length === 2, "forged processed");
  assert.equal(a.inbox[1].body, null);
  assert.deepEqual(seen, ["b:true", "b:true"]);
  a.messenger.stop();
  assert.equal(await a.messenger.lookup(b.id), false);
});

test("processes nothing while inactive or stopped and starts only once", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  b.messenger.start();
  await a.messenger.send(b.id, "first");
  await until(() => b.inbox.length === 1, "delivery");
  const frame = lastDelivery(b);
  b.messenger.stop();
  inject(b, { ...frame, id: createMessageId() });
  await settle(b);
  assert.equal(b.inbox.length, 1);
  assert.deepEqual(await b.messenger.send(a.id, "x"), {
    ok: false,
    reason: "authentication_required",
  });
  assert.equal(frames(b.sent, "publish").length, 1);
});

test("surfaces queue limits without retrying", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  await b.shutdown();
  let result = await a.messenger.send(b.id, "fill 0");
  let sent = 0;
  while (result.ok) {
    sent += 1;
    result = await a.messenger.send(b.id, `fill ${sent}`);
  }
  assert.equal(sent, 128);
  assert.deepEqual(result, { ok: false, reason: "queue_full" });
  assert.equal(frames(a.sent, "send").length, sent + 1);
});

test("fuzzed queued deliveries never yield foreign plaintext or move the ratchet", async () => {
  const port = await freePort();
  await startServer(port);
  const [a, b] = await paired(port);
  const c = await peer(port);
  b.hold(true);
  const bodiesSent = ["fuzz zero", "fuzz one", "fuzz two"];
  for (const body of bodiesSent) {
    await a.messenger.send(b.id, body);
  }
  await until(() => deliveries(b).length === 3, "held deliveries");
  b.hold(false);
  const pool = deliveries(b);
  const state = async () =>
    b.pairs.transact(a.id, async (s) => ({
      state: s,
      value: JSON.stringify([s.receiving?.n ?? null, s.skipped.length]),
    }));
  const snapshot = await state();
  let seed = 0x5eed17;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 300);
  for (let i = 0; i < iterations; i++) {
    const base = structuredClone(pool[random(pool.length)]);
    const text = base.ciphertext as string;
    const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
    assert.ok(bytes);
    let mutated: Json = base;
    switch (random(8)) {
      case 0:
        bytes[random(bytes.length)] ^= 1 << random(8);
        mutated = { ...base, ciphertext: encodeBase64Url(bytes) };
        break;
      case 1:
        mutated = {
          ...base,
          ciphertext: encodeBase64Url(
            bytes.slice(0, 60 + random(bytes.length - 60)),
          ),
        };
        break;
      case 2:
        mutated = { ...base, id: createMessageId() };
        break;
      case 3:
        mutated = { ...base, from: c.id };
        break;
      case 4: {
        const view = new DataView(bytes.buffer);
        view.setUint32(53, random(2) ? 2 ** 32 - 1 - random(5) : random(400));
        mutated = { ...base, ciphertext: encodeBase64Url(bytes) };
        break;
      }
      case 5:
        bytes.set(crypto.getRandomValues(new Uint8Array(16)), 1);
        mutated = { ...base, ciphertext: encodeBase64Url(bytes) };
        break;
      case 6:
        mutated = { ...base, key: c.keys.exchange.publicKey };
        break;
      default:
        mutated = {
          ...base,
          ciphertext: encodeBase64Url(
            new Uint8Array([
              ...bytes,
              ...crypto.getRandomValues(new Uint8Array(1 + random(32))),
            ]),
          ),
        };
    }
    inject(b, mutated);
    if (i % 25 === 0) {
      await settle(b);
      assert.equal(await state(), snapshot);
      assert.ok(b.inbox.every((m) => m.body === null));
    }
  }
  await settle(b);
  assert.equal(await state(), snapshot);
  assert.ok(b.inbox.every((m) => m.body === null));
  for (const delivery of pool) {
    inject(b, delivery);
  }
  await until(
    () => bodiesSent.every((body) => bodies(b).includes(body)),
    "genuine deliveries after fuzzing",
  );
  assert.equal(bodies(b).filter((body) => body !== null).length, 3);
});
