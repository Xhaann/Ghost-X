import assert from "node:assert/strict";
import { test } from "node:test";
import { Authenticator } from "./auth.ts";
import { encodeBase64Url } from "./base64.ts";
import { Client } from "./client.ts";
import { ExchangeKey } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import {
  type Incoming,
  Messenger,
  type MessengerState,
  maxPendingDecryptions,
} from "./messenger.ts";
import { maxBodySize } from "./protocol.ts";
import { WebSocketTransport } from "./socket.ts";
import {
  created,
  freePort,
  startServer,
  track,
  useServer,
  waitFor,
} from "./testing.ts";

useServer();

type Keys = { identity: IdentityKey; exchange: ExchangeKey };

type Peer = {
  client: Client;
  keys: Keys;
  messenger: Messenger;
  inbox: Incoming[];
  states: MessengerState[];
  socket: WebSocket;
  sent: string[];
  received: string[];
};

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 5000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

async function keys(): Promise<Keys> {
  const [identity, exchange] = await Promise.all([
    IdentityKey.generate(),
    ExchangeKey.generate(),
  ]);
  return { identity, exchange };
}

async function peer(port: number, own?: Keys, wait = true): Promise<Peer> {
  const before = created.length;
  const transport = track(
    new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
  );
  const sent: string[] = [];
  const received: string[] = [];
  const send = transport.send.bind(transport);
  transport.send = (data: string) => {
    sent.push(data);
    return send(data);
  };
  transport.onData((data) => received.push(data));
  const client = track(new Client(transport));
  const k = own ?? (await keys());
  const auth = new Authenticator(client, k.identity);
  const messenger = new Messenger(client, auth, k.identity, k.exchange);
  track({ close: () => messenger.stop() });
  track({ close: () => auth.stop() });
  const inbox: Incoming[] = [];
  const states: MessengerState[] = [];
  messenger.onMessage((message) => inbox.push(message));
  messenger.onState((state) => states.push(state));
  auth.start();
  messenger.start();
  client.open();
  await waitFor(client, "connected");
  const socket = created[before];
  if (wait) {
    await until(() => messenger.state.active, "messenger active");
  }
  return { client, keys: k, messenger, inbox, states, socket, sent, received };
}

async function barrier(p: Peer): Promise<void> {
  const reply = await p.client.request({
    type: "ping",
    payload: { sentAt: 1 },
  });
  assert.equal(reply?.type, "pong");
}

function lastDelivery(p: Peer): Record<string, string> {
  const raw = [...p.received]
    .reverse()
    .find((r) => r.includes('"type":"message"'));
  assert.ok(raw);
  return JSON.parse(raw).payload;
}

function inject(p: Peer, payload: Record<string, string>) {
  p.socket.dispatchEvent(
    new MessageEvent("message", {
      data: JSON.stringify({ type: "message", payload }),
    }),
  );
}

function flipText(text: string): string {
  const bytes = Uint8Array.from(
    atob(text.replaceAll("-", "+").replaceAll("_", "/")),
    (c) => c.charCodeAt(0),
  );
  bytes[0] ^= 1;
  return encodeBase64Url(bytes);
}

test("activates only after authentication and key publication", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);

  assert.deepEqual(a.states, [{ active: true }]);
  const types = a.sent.map((frame) => JSON.parse(frame).type);
  assert.deepEqual(types, ["challenge", "authenticate", "publish"]);
  const publish = JSON.parse(a.sent[2]);
  assert.deepEqual(Object.keys(publish.payload).sort(), ["key", "signature"]);
  assert.equal(publish.payload.key, a.keys.exchange.publicKey);
  const lookup = await b.client.request({
    type: "key",
    payload: { identity: a.keys.identity.identity },
  });
  assert.ok(lookup?.type === "key");
  assert.equal(lookup.payload.key, a.keys.exchange.publicKey);
});

test("refuses to send before activation", async () => {
  const port = await freePort();
  const client = track(
    new Client(track(new WebSocketTransport(`ws://127.0.0.1:${port}/ws`))),
  );
  const k = await keys();
  const messenger = new Messenger(
    client,
    new Authenticator(client, k.identity),
    k.identity,
    k.exchange,
  );
  track({ close: () => messenger.stop() });
  messenger.start();

  assert.deepEqual(await messenger.send("B".repeat(42) + "A", "x"), {
    ok: false,
    reason: "authentication_required",
  });
  assert.equal(created.length, 0);
});

test("delivers end-to-end encrypted messages without plaintext on the wire", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const secret = "the server must never read this 🔒";

  assert.deepEqual(
    await a.messenger.send(b.keys.identity.identity, secret, "m1"),
    { ok: true },
  );
  await until(() => b.inbox.length === 1, "delivery");

  assert.deepEqual(b.inbox, [
    { id: "m1", from: a.keys.identity.identity, body: secret },
  ]);
  const encoded = encodeBase64Url(new TextEncoder().encode(secret));
  for (const frame of [...a.sent, ...b.received, ...a.received]) {
    assert.ok(!frame.includes(secret), "plaintext crossed the wire");
    assert.ok(!frame.includes(encoded), "encoded plaintext crossed the wire");
  }
  const sendFrame = JSON.parse(
    a.sent.find((f) => f.includes('"type":"send"')) ?? "{}",
  );
  assert.deepEqual(Object.keys(sendFrame.payload).sort(), [
    "ciphertext",
    "iv",
    "salt",
    "to",
  ]);
  const delivered = lastDelivery(b);
  assert.equal(delivered.ciphertext, sendFrame.payload.ciphertext);
  assert.equal(delivered.salt, sendFrame.payload.salt);
  assert.equal(delivered.iv, sendFrame.payload.iv);
  assert.equal(delivered.key, a.keys.exchange.publicKey);

  assert.deepEqual(
    await b.messenger.send(a.keys.identity.identity, "reply", "r1"),
    { ok: true },
  );
  await until(() => a.inbox.length === 1, "reply");
  assert.equal(a.inbox[0].body, "reply");
});

test("every session of the recipient identity decrypts once", async () => {
  const port = await freePort();
  await startServer(port);
  const bKeys = await keys();
  const a = await peer(port);
  const b1 = await peer(port, bKeys);
  const b2 = await peer(port, bKeys);

  assert.deepEqual(
    await a.messenger.send(bKeys.identity.identity, "both", "m1"),
    {
      ok: true,
    },
  );
  for (const b of [b1, b2]) {
    await until(() => b.inbox.length === 1, "delivery");
    await barrier(b);
    assert.deepEqual(b.inbox, [
      { id: "m1", from: a.keys.identity.identity, body: "both" },
    ]);
  }
});

test("a second session cannot bind a different key to the identity", async () => {
  const port = await freePort();
  await startServer(port);
  const first = await keys();
  await peer(port, first);
  const conflicting = await peer(
    port,
    { identity: first.identity, exchange: await ExchangeKey.generate() },
    false,
  );
  await until(
    () => conflicting.received.some((r) => r.includes("invalid_payload")),
    "publish rejection",
  );

  assert.equal(conflicting.messenger.state.active, false);
  assert.deepEqual(
    await conflicting.messenger.send(first.identity.identity, "x"),
    { ok: false, reason: "authentication_required" },
  );
});

test("reports unavailable recipients and invalid input without sending", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const absent = await keys();

  assert.deepEqual(await a.messenger.send(absent.identity.identity, "x"), {
    ok: false,
    reason: "recipient_unavailable",
  });
  assert.ok(!a.sent.some((f) => f.includes('"type":"send"')));

  const frames = a.sent.length;
  for (const [to, body, reason] of [
    ["bad", "x", "invalid_payload"],
    [absent.identity.identity, "", "invalid_payload"],
    [absent.identity.identity, "a\u0000", "invalid_payload"],
    [
      absent.identity.identity,
      "a".repeat(maxBodySize + 1),
      "message_too_large",
    ],
  ] as const) {
    assert.deepEqual(await a.messenger.send(to, body), { ok: false, reason });
  }
  assert.equal(a.sent.length, frames);
});

test("tampered or misdirected deliveries fail decryption", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const c = await peer(port);

  await a.messenger.send(b.keys.identity.identity, "original", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  const good = lastDelivery(b);

  await a.messenger.send(c.keys.identity.identity, "for c", "m2");
  await until(() => c.inbox.length === 1, "c delivery");
  const forC = lastDelivery(c);

  const cBundle = await c.keys.exchange.bind(c.keys.identity);
  assert.ok(cBundle);
  const mutations: Record<string, Record<string, string>> = {
    ciphertext: { ...good, ciphertext: flipText(good.ciphertext) },
    nonce: { ...good, iv: flipText(good.iv) },
    salt: { ...good, salt: flipText(good.salt) },
    "message id": { ...good, id: "other" },
    sender: {
      ...good,
      from: c.keys.identity.identity,
      key: cBundle.key,
      signature: cBundle.signature,
    },
    "sender key": { ...good, key: cBundle.key },
    "key binding": { ...good, signature: cBundle.signature },
    "other recipient": { ...forC },
  };
  for (const payload of Object.values(mutations)) {
    inject(b, payload);
  }
  await until(
    () => b.inbox.length === 1 + Object.keys(mutations).length,
    "mutations processed",
  );

  assert.deepEqual(
    b.inbox.slice(1).map((m) => m.body),
    Object.keys(mutations).map(() => null),
  );
  inject(a, { ...forC, id: "x9" });
  await until(() => a.inbox.length === 1, "a processed");
  assert.equal(a.inbox[0].body, null);
});

test("server rejects raw plaintext sends", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);

  const reply = new Promise((resolve) => {
    const release = a.client.onMessage((message) => {
      if (message.id === "plain1") {
        release();
        resolve(message);
      }
    });
  });
  a.socket.send(
    JSON.stringify({
      type: "send",
      id: "plain1",
      payload: { to: b.keys.identity.identity, body: "plaintext" },
    }),
  );
  assert.deepEqual(await reply, {
    type: "error",
    id: "plain1",
    payload: { code: "invalid_payload" },
  });
  await barrier(b);
  assert.deepEqual(b.inbox, []);
});

test("emits nothing when inactive or stopped", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  await a.messenger.send(b.keys.identity.identity, "first", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  const delivered = lastDelivery(b);

  b.messenger.stop();
  b.messenger.stop();
  inject(b, { ...delivered, id: "late" });
  await a.messenger.send(b.keys.identity.identity, "after stop", "m2");
  await barrier(b);

  assert.equal(b.inbox.length, 1);
  assert.deepEqual(b.states.at(-1), { active: false });
});

test("bounds pending decryptions", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  await a.messenger.send(b.keys.identity.identity, "seed", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  const delivered = lastDelivery(b);

  const burst = maxPendingDecryptions + 20;
  for (let i = 0; i < burst; i++) {
    inject(b, { ...delivered, id: `burst${i}` });
  }
  await until(() => b.inbox.length === 1 + burst, "burst processed");

  const failed = b.inbox.slice(1).filter((m) => m.body === null).length;
  assert.ok(failed >= burst - maxPendingDecryptions);
  assert.equal(b.inbox.slice(1).filter((m) => m.body !== null).length, 0);
});

test("starts only once", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  b.messenger.start();
  b.messenger.start();

  await a.messenger.send(b.keys.identity.identity, "once", "m1");
  await until(() => b.inbox.length === 1, "delivery");
  await barrier(b);

  assert.equal(b.inbox.length, 1);
});

test("refuses to encrypt to a substituted recipient key", async () => {
  const port = await freePort();
  await startServer(port);
  const a = await peer(port);
  const b = await peer(port);
  const c = await peer(port);
  const cBundle = await c.keys.exchange.bind(c.keys.identity);
  assert.ok(cBundle);

  const send = a.socket.send.bind(a.socket);
  a.socket.send = (data: string) => {
    const frame = JSON.parse(data);
    if (frame.type === "key") {
      queueMicrotask(() =>
        a.socket.dispatchEvent(
          new MessageEvent("message", {
            data: JSON.stringify({
              type: "key",
              id: frame.id,
              payload: {
                identity: b.keys.identity.identity,
                key: cBundle.key,
                signature: cBundle.signature,
              },
            }),
          }),
        ),
      );
      return;
    }
    send(data);
  };
  const sendsBefore = a.sent.filter((f) => f.includes('"type":"send"')).length;

  assert.deepEqual(await a.messenger.send(b.keys.identity.identity, "secret"), {
    ok: false,
    reason: "encryption_failed",
  });
  assert.equal(
    a.sent.filter((f) => f.includes('"type":"send"')).length,
    sendsBefore,
  );
  await barrier(b);
  await barrier(c);
  assert.deepEqual(b.inbox, []);
  assert.deepEqual(c.inbox, []);
});
