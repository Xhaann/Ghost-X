import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { encodeBase64Url } from "./base64.ts";
import { deriveDeviceId, signRoster } from "./device.ts";
import { ExchangeKey } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import type { Link, LinkConnection } from "./local.ts";
import { pairAddress } from "./pairs.ts";
import {
  type PeerAuthorization,
  type PeerHello,
  maxPeerPending,
  maxPeerSetup,
  parseHandshakeFrame,
  parseSessionFrame,
  peerProofMessage,
  peerTranscript,
} from "./peer.ts";
import { createMessageId, minMessageSize } from "./protocol.ts";
import { generateRatchetKey } from "./ratchet.ts";
import type { SendOutcome } from "./relay.ts";
import {
  type MemoryStore,
  type PeerCarrier,
  type PeerDevice,
  memoryStore,
  peerCarrier,
  peerDevice,
  sleep,
  useCleanup,
  wireFrames,
} from "./testing.ts";
import type { TransportKind } from "./transport.ts";

useCleanup();

const NativeWebSocket = globalThis.WebSocket;
const nativeFetch = globalThis.fetch;
const contacted: string[] = [];

before(() => {
  globalThis.WebSocket = class {
    constructor(url: string) {
      contacted.push(String(url));
      throw new Error("no server may be contacted");
    }
  } as unknown as typeof WebSocket;
  globalThis.fetch = ((input: unknown) => {
    contacted.push(String(input));
    return Promise.reject(new Error("no server may be contacted"));
  }) as typeof fetch;
});

after(() => {
  globalThis.WebSocket = NativeWebSocket;
  globalThis.fetch = nativeFetch;
  assert.deepEqual(contacted, [], "the central server was never contacted");
});

type Json = { type: string; payload: Record<string, unknown> };

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 8000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await sleep(5);
  }
}

function authenticated(...devices: PeerDevice[]): () => boolean {
  return () => devices.every((d) => d.endpoint.state === "authenticated");
}

async function linked(
  options: Parameters<typeof peerDevice>[1] = {},
  wrap: (link: Link) => Link = (link) => link,
): Promise<{ a: PeerDevice; b: PeerDevice; carrier: PeerCarrier }> {
  const carrier = await peerCarrier();
  const b = await peerDevice(carrier.listen, options);
  const a = await peerDevice(wrap(carrier.dial), options);
  await until(authenticated(a, b), "mutual authentication");
  return { a, b, carrier };
}

function bodies(d: PeerDevice): (string | null)[] {
  return d.inbox.map((m) => m.body);
}

type Edit = (frame: string, index: number) => string[];

function intercept(link: Link, edit: { out?: Edit; in?: Edit }): Link {
  return {
    connect: async (handlers) => {
      let inbound = 0;
      let outbound = 0;
      const connection = await link.connect({
        frame: (frame) => {
          for (const f of edit.in?.(frame, inbound++) ?? [frame]) {
            handlers.frame(f);
          }
        },
        closed: handlers.closed,
      });
      return {
        send: (frame) => {
          let ok = true;
          for (const f of edit.out?.(frame, outbound++) ?? [frame]) {
            ok = connection.send(f) && ok;
          }
          return ok;
        },
        close: () => connection.close(),
      };
    },
  };
}

type Raw = {
  frames: string[];
  send(frame: unknown): boolean;
  close(): void;
  readonly closed: boolean;
};

async function raw(link: Link): Promise<Raw> {
  const frames: string[] = [];
  let closed = false;
  const connection: LinkConnection = await link.connect({
    frame: (f) => frames.push(f),
    closed: () => {
      closed = true;
    },
  });
  return {
    frames,
    send: (frame) =>
      connection.send(
        typeof frame === "string" ? frame : JSON.stringify(frame),
      ),
    close: () => connection.close(),
    get closed() {
      return closed;
    },
  };
}

async function victim(options: Parameters<typeof peerDevice>[1] = {}) {
  const carrier = await peerCarrier();
  const device = await peerDevice(carrier.listen, {
    timeout: 2000,
    ...options,
  });
  const events: string[] = [];
  device.endpoint.onEvent((e) => events.push(e.type));
  return { carrier, device, events };
}

async function attack(
  target: Awaited<ReturnType<typeof victim>>,
): Promise<{ attacker: Raw; hello: PeerHello }> {
  target.device.endpoint.open();
  const attacker = await raw(target.carrier.dial);
  await until(() => attacker.frames.length >= 1, "victim hello");
  const first = parseHandshakeFrame(attacker.frames[0]);
  assert.ok(first?.type === "hello");
  return { attacker, hello: first.payload };
}

async function failed(
  target: Awaited<ReturnType<typeof victim>>,
  failure: string,
): Promise<void> {
  await until(
    () => target.device.endpoint.state !== "authenticating",
    `failure ${failure}`,
  );
  assert.equal(target.device.endpoint.state, "failed");
  assert.equal(target.device.endpoint.failure, failure);
  assert.equal(target.device.endpoint.peer, null);
  assert.deepEqual(target.events, [], "no relay event before authentication");
  await until(
    () => target.device.transport.state !== "connected",
    "connection closed",
  );
}

async function forged(
  signer: PeerDevice,
  overrides: Partial<PeerHello> = {},
): Promise<PeerHello> {
  const share = await generateRatchetKey();
  const roster = signer.devices.roster;
  assert.ok(roster);
  return {
    version: 1,
    nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    share: encodeBase64Url(share.publicKey),
    identity: signer.id,
    device: signer.deviceId,
    roster,
    ...overrides,
  };
}

async function proofOf(
  signer: PeerDevice,
  own: PeerHello,
  other: PeerHello,
  kind: TransportKind = "local",
): Promise<string> {
  const message = await peerProofMessage(kind, own, other);
  assert.ok(message);
  const signature = await signer.keys.device.sign(message);
  assert.ok(signature);
  return signature;
}

const randomTag = () =>
  encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));

function decoded(carrier: PeerCarrier): { out: Json[]; in: Json[] } {
  return {
    out: wireFrames(carrier.wire.out).map((f) => JSON.parse(f) as Json),
    in: wireFrames(carrier.wire.in).map((f) => JSON.parse(f) as Json),
  };
}

test("two endpoints authenticate each other and exchange encrypted messages directly", async () => {
  const { a, b, carrier } = await linked();
  assert.deepEqual(a.endpoint.peer, { identity: b.id, device: b.deviceId });
  assert.deepEqual(b.endpoint.peer, { identity: a.id, device: a.deviceId });
  assert.equal(a.endpoint.kind, "local");
  const secrets = ["direct hello ✓", "direct reply", "third message"];
  assert.deepEqual(await a.messenger.send(b.id, secrets[0]), {
    ok: true,
    devices: 1,
    pending: 0,
  });
  await until(() => bodies(b).includes(secrets[0]), "b receives");
  assert.deepEqual(await b.messenger.send(a.id, secrets[1]), {
    ok: true,
    devices: 1,
    pending: 0,
  });
  await until(() => bodies(a).includes(secrets[1]), "a receives");
  await a.messenger.send(b.id, secrets[2]);
  await until(() => bodies(b).includes(secrets[2]), "b receives again");
  await until(
    () => a.receipts.length === 2 && b.receipts.length === 1,
    "receipts",
  );
  assert.ok(
    [...a.receipts, ...b.receipts].every((r) => r.status === "delivered"),
  );
  assert.equal(a.pairs.state(pairAddress(b.id, b.deviceId)), "established");
  assert.equal(b.pairs.state(pairAddress(a.id, a.deviceId)), "established");

  const { out, in: inbound } = decoded(carrier);
  for (const direction of [out, inbound]) {
    assert.deepEqual(
      direction.slice(0, 2).map((f) => f.type),
      ["hello", "proof"],
    );
    assert.ok(direction.slice(2).length > 0);
    assert.ok(direction.slice(2).every((f) => f.type === "sealed"));
  }
  const bytes = Buffer.concat([...carrier.wire.out, ...carrier.wire.in]);
  const text = bytes.toString("latin1");
  for (const secret of secrets) {
    const rawSecret = Buffer.from(secret, "utf8");
    for (const variant of [
      secret,
      rawSecret.toString("base64"),
      rawSecret.toString("base64url"),
      rawSecret.toString("hex"),
    ]) {
      assert.ok(!text.includes(variant), "no plaintext on the carrier");
      assert.ok(!bytes.includes(Buffer.from(variant, "utf8")));
    }
  }
  assert.doesNotMatch(
    text,
    /"(private|privateKey|pkcs8|d|root|chain|chainKey|rootKey|secret|seed|integrity|storage|ciphertext|envelopes|initiate|accept|ack|bundle|message)"\s*:/,
  );
  assert.doesNotMatch(text, /-----BEGIN|PRIVATE KEY/);
  for (const device of [a, b]) {
    const stored = JSON.stringify([...device.store.data], (_, value) =>
      value instanceof CryptoKey
        ? { extractable: value.extractable }
        : ArrayBuffer.isView(value)
          ? Buffer.from(value.buffer).toString("hex")
          : value,
    );
    for (const secret of secrets) {
      assert.ok(!stored.includes(secret), "no plaintext at rest");
    }
    assert.ok(!stored.includes('"extractable":true'));
  }
});

test("simultaneous first messages, rapid sends and sequential order all arrive exactly once", async () => {
  const { a, b } = await linked();
  const [first, crossed] = await Promise.all([
    a.messenger.send(b.id, "crossed from a"),
    b.messenger.send(a.id, "crossed from b"),
  ]);
  assert.ok(first.ok && crossed.ok);
  await until(
    () =>
      bodies(b).includes("crossed from a") &&
      bodies(a).includes("crossed from b"),
    "crossed first messages",
  );
  const rapid = Array.from({ length: 30 }, (_, i) => `rapid ${i}`);
  const results = await Promise.all(
    rapid.map((m) => a.messenger.send(b.id, m)),
  );
  assert.ok(results.every((r) => r.ok));
  await until(() => rapid.every((m) => bodies(b).includes(m)), "rapid");
  for (let i = 0; i < 10; i++) {
    assert.ok((await b.messenger.send(a.id, `ordered ${i}`)).ok);
  }
  await until(
    () => bodies(a).filter((m) => m?.startsWith("ordered")).length === 10,
    "ordered",
  );
  assert.deepEqual(
    bodies(a).filter((m) => m?.startsWith("ordered")),
    Array.from({ length: 10 }, (_, i) => `ordered ${i}`),
  );
  const all = bodies(b).filter((m) => m !== null);
  assert.equal(new Set(all).size, all.length, "no duplicates");
  assert.ok(bodies(b).every((m) => m !== null));
});

test("a lost carrier never reconnects by itself and an explicit reconnect requires a fresh handshake", async () => {
  const { a, b, carrier } = await linked();
  await a.messenger.send(b.id, "before the drop");
  await until(() => bodies(b).includes("before the drop"), "first");
  const session = a.pairs.id(pairAddress(b.id, b.deviceId));
  carrier.drop();
  await until(
    () =>
      a.endpoint.state === "unauthenticated" &&
      b.endpoint.state === "unauthenticated",
    "both unauthenticated",
  );
  assert.equal(a.endpoint.peer, null);
  assert.deepEqual(await a.messenger.send(b.id, "while down"), {
    ok: false,
    reason: "authentication_required",
  });
  await sleep(300);
  assert.equal(a.endpoint.state, "unauthenticated", "no automatic reconnect");
  assert.equal(a.transport.state, "error");
  b.endpoint.open();
  a.endpoint.open();
  await until(authenticated(a, b), "re-authenticated");
  const hellos = decoded(carrier).out.filter((f) => f.type === "hello");
  assert.equal(hellos.length, 2);
  assert.notEqual(hellos[0].payload.nonce, hellos[1].payload.nonce);
  assert.notEqual(hellos[0].payload.share, hellos[1].payload.share);
  await a.messenger.send(b.id, "after the reconnect");
  await b.messenger.send(a.id, "reply after the reconnect");
  await until(
    () =>
      bodies(b).includes("after the reconnect") &&
      bodies(a).includes("reply after the reconnect"),
    "messages after reconnect",
  );
  assert.equal(a.pairs.id(pairAddress(b.id, b.deviceId)), session);
  assert.ok(!bodies(b).includes("while down"));
});

test("an absent peer is reported as unavailable and never produces a delivery", async () => {
  const carrier = await peerCarrier();
  const lonely = await peerDevice(carrier.dial, { timeout: 200 });
  await until(() => lonely.endpoint.state === "failed", "handshake timeout");
  assert.equal(lonely.endpoint.failure, "timeout");
  const nobody = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  assert.deepEqual(await lonely.messenger.send(nobody, "nobody"), {
    ok: false,
    reason: "authentication_required",
  });
  assert.equal(lonely.receipts.length, 0);

  const unavailable = await peerDevice(null);
  await until(() => unavailable.transport.state === "error", "unavailable");
  assert.equal(unavailable.endpoint.state, "unauthenticated");
  await sleep(100);
  assert.equal(unavailable.transport.state, "error", "no fallback carrier");
  let calls = 0;
  const refusing = await peerDevice({
    connect: () => {
      calls += 1;
      return Promise.reject(new Error("no peer"));
    },
  });
  await until(() => refusing.transport.state === "error", "refused");
  await sleep(200);
  assert.equal(calls, 1, "a failed peer link is not retried");
  assert.equal(refusing.endpoint.state, "unauthenticated");
});

test("a lost acknowledgement is retried with the same id and delivered exactly once", async () => {
  const { a, b } = await linked({ requestTimeout: 300 });
  const acknowledge = b.endpoint.acknowledge.bind(b.endpoint);
  let suppressed = 0;
  b.endpoint.acknowledge = (delivery) => {
    if (suppressed === 0) {
      suppressed += 1;
      return;
    }
    acknowledge(delivery);
  };
  const id = createMessageId();
  assert.deepEqual(await a.messenger.send(b.id, "ack goes missing", id), {
    ok: false,
    reason: "not_sent",
  });
  assert.equal(a.receipts.length, 0, "no delivery without confirmation");
  assert.equal(bodies(b).filter((m) => m === "ack goes missing").length, 1);
  assert.deepEqual(await a.messenger.send(b.id, "ack goes missing", id), {
    ok: true,
    devices: 1,
    pending: 0,
  });
  await until(() => a.receipts.length === 1, "receipt after retry");
  assert.equal(bodies(b).filter((m) => m === "ack goes missing").length, 1);
});

test("a send interrupted by a lost carrier is never reported as delivered", async () => {
  const { a, b, carrier } = await linked();
  await a.messenger.send(b.id, "warm up");
  await until(() => bodies(b).includes("warm up"), "warm");
  const pending = a.messenger.send(b.id, "interrupted");
  carrier.drop();
  const result = await pending;
  if (result.ok) {
    assert.ok(bodies(b).includes("interrupted"), "ok only after delivery");
  } else {
    assert.ok(
      ["not_sent", "session_pending", "authentication_required"].includes(
        result.reason,
      ),
    );
  }
  await until(() => a.endpoint.state === "unauthenticated", "down");
  assert.ok(a.receipts.every((r) => r.id !== undefined));
});

test("replayed and duplicated encrypted messages are rejected by the existing ratchet", async () => {
  const { a, b } = await linked();
  const send = a.endpoint.send.bind(a.endpoint);
  const captured: { id: string; ciphertext: string }[] = [];
  a.endpoint.send = (to, id, envelopes) => {
    captured.push({ id, ciphertext: envelopes[0].ciphertext });
    return send(to, id, envelopes);
  };
  await a.messenger.send(b.id, "only once");
  await until(() => bodies(b).includes("only once"), "delivered");
  const [original] = captured;
  const envelope = [{ device: b.deviceId, ciphertext: original.ciphertext }];
  assert.equal(await send(b.id, original.id, envelope), "queued");
  assert.equal(bodies(b).filter((m) => m === "only once").length, 1);
  const before = b.inbox.length;
  assert.equal(await send(b.id, createMessageId(), envelope), "queued");
  await until(
    () => b.inbox.length === before + 1,
    "replay recorded as rejected",
  );
  assert.equal(b.inbox.at(-1)?.body, null);
  assert.equal(bodies(b).filter((m) => m === "only once").length, 1);
  await a.messenger.send(b.id, "ratchet still healthy");
  await until(() => bodies(b).includes("ratchet still healthy"), "healthy");
});

test("identity spoofing, forged signatures and wrong carrier bindings fail closed", async () => {
  const claimed = await peerDevice(null, { open: false });
  const impostor = await peerDevice(null, { open: false });

  const spoof = await victim();
  const s = await attack(spoof);
  const hello = await forged(claimed);
  s.attacker.send({ type: "hello", payload: hello });
  s.attacker.send({
    type: "proof",
    payload: {
      signature: await proofOf(impostor, hello, s.hello),
      confirm: randomTag(),
    },
  });
  await failed(spoof, "signature");

  const bad = await victim();
  const t = await attack(bad);
  t.attacker.send({ type: "hello", payload: await forged(claimed) });
  t.attacker.send({
    type: "proof",
    payload: {
      signature: encodeBase64Url(crypto.getRandomValues(new Uint8Array(64))),
      confirm: randomTag(),
    },
  });
  await failed(bad, "signature");

  const carrierBound = await victim();
  const u = await attack(carrierBound);
  const legit = await forged(claimed);
  u.attacker.send({ type: "hello", payload: legit });
  u.attacker.send({
    type: "proof",
    payload: {
      signature: await proofOf(claimed, legit, u.hello, "websocket"),
      confirm: randomTag(),
    },
  });
  await failed(carrierBound, "signature");

  const unconfirmed = await victim();
  const v = await attack(unconfirmed);
  const keyless = await forged(claimed);
  v.attacker.send({ type: "hello", payload: keyless });
  v.attacker.send({
    type: "proof",
    payload: {
      signature: await proofOf(claimed, keyless, v.hello),
      confirm: randomTag(),
    },
  });
  await failed(unconfirmed, "integrity");
});

async function substitution(
  verifier: "dialer" | "listener" | null = null,
): Promise<{ a: PeerDevice; b: PeerDevice }> {
  const carrier = await peerCarrier();
  const b = await peerDevice(carrier.listen, { open: false });
  const substitute = await generateRatchetKey();
  const proof = (frame: string) => (JSON.parse(frame) as Json).type === "proof";
  const a = await peerDevice(
    intercept(carrier.dial, {
      out: (frame, i) => {
        if (verifier === "dialer" && proof(frame)) {
          return [];
        }
        if (i !== 0) {
          return [frame];
        }
        const hello = JSON.parse(frame) as Json;
        return [
          JSON.stringify({
            ...hello,
            payload: {
              ...hello.payload,
              share: encodeBase64Url(substitute.publicKey),
            },
          }),
        ];
      },
      in: (frame) => (verifier === "listener" && proof(frame) ? [] : [frame]),
    }),
    { open: false },
  );
  const histories = new Map([a, b].map((d) => [d, [d.endpoint.state]]));
  for (const [d, history] of histories) {
    d.endpoint.onState((state) => history.push(state));
  }
  b.endpoint.open();
  a.endpoint.open();
  await until(
    () =>
      [a, b].some((d) => d.endpoint.state === "failed") &&
      [a, b].every((d) => d.endpoint.state !== "authenticating"),
    "substitution detected",
  );
  for (const [d, history] of histories) {
    assert.ok(!history.includes("authenticated"), history.join(" > "));
    const detected = history.indexOf("failed");
    if (detected === -1) {
      assert.equal(d.endpoint.state, "unauthenticated");
      assert.equal(d.endpoint.failure, null);
    } else {
      assert.ok(
        history.slice(detected).every((state) => state === "failed"),
        history.join(" > "),
      );
      assert.equal(d.endpoint.failure, "signature");
    }
  }
  return { a, b };
}

test("a substituted key share is detected by the dialer when only it can verify a proof", async () => {
  const { a, b } = await substitution("dialer");
  assert.equal(a.endpoint.state, "failed");
  assert.equal(b.endpoint.state, "unauthenticated");
});

test("a substituted key share is detected by the listener when only it can verify a proof", async () => {
  const { a, b } = await substitution("listener");
  assert.equal(a.endpoint.state, "unauthenticated");
  assert.equal(b.endpoint.state, "failed");
});

test("a substituted key share or a mismatched identity never authenticates", async () => {
  await substitution();

  const stranger = await peerDevice(null, { open: false });
  const claimed = await peerDevice(null, { open: false });
  const mismatch = await victim();
  const m = await attack(mismatch);
  const hello = await forged(stranger, { identity: claimed.id });
  m.attacker.send({ type: "hello", payload: hello });
  m.attacker.send({
    type: "proof",
    payload: {
      signature: await proofOf(stranger, hello, m.hello),
      confirm: randomTag(),
    },
  });
  await failed(mismatch, "unauthorized");
});

test("a reflected proof never authenticates a roster that copies the verifier's device key", async () => {
  const target = await victim();
  const { attacker, hello: own } = await attack(target);
  const entry = own.roster.devices.find((d) => d.id === own.device);
  assert.ok(entry);
  const root = await IdentityKey.generate();
  const exchange = await ExchangeKey.generate();
  const id = await deriveDeviceId(root.identity, entry.signing);
  assert.ok(id);
  const roster = await signRoster(root, 1, [
    { id, signing: entry.signing, exchange: exchange.publicKey },
  ]);
  assert.ok(roster, "a roster may list any public signing key");
  const share = await generateRatchetKey();
  const hello: PeerHello = {
    version: 1,
    nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(32))),
    share: encodeBase64Url(share.publicKey),
    identity: root.identity,
    device: id,
    roster,
  };
  attacker.send({ type: "hello", payload: hello });
  await until(() => attacker.frames.length >= 2, "victim proof");
  const reflected = parseHandshakeFrame(attacker.frames[1]);
  assert.ok(reflected?.type === "proof");
  const transcript = peerTranscript("local", hello, own);
  assert.ok(transcript);
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", transcript),
  );
  const peerKey = await crypto.subtle.importKey(
    "raw",
    Buffer.from(own.share, "base64url"),
    { name: "X25519" },
    false,
    [],
  );
  const secret = await crypto.subtle.deriveBits(
    { name: "X25519", public: peerKey },
    share.privateKey,
    256,
  );
  const material = await crypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveKey",
  ]);
  const position =
    Buffer.compare(
      Buffer.from(hello.nonce, "base64url"),
      Buffer.from(own.nonce, "base64url"),
    ) < 0
      ? 0
      : 1;
  const context = new TextEncoder().encode("ghostx/peer/keys/v1\0");
  const info = new Uint8Array(context.length + 2);
  info.set(context);
  info.set([1, position], context.length);
  const confirmKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: digest, info },
    material,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    false,
    ["sign"],
  );
  const confirm = encodeBase64Url(
    new Uint8Array(await crypto.subtle.sign("HMAC", confirmKey, digest)),
  );
  attacker.send({
    type: "proof",
    payload: { signature: reflected.payload.signature, confirm },
  });
  await failed(target, "signature");
});

test("a recorded handshake replayed on a new connection is rejected", async () => {
  const carrier = await peerCarrier();
  const b = await peerDevice(carrier.listen);
  const a = await peerDevice(carrier.dial);
  await until(authenticated(a, b), "first session");
  const [hello, proof] = wireFrames(carrier.wire.out);
  a.endpoint.close();
  await until(() => b.endpoint.state === "unauthenticated", "b idle");
  const events: string[] = [];
  b.endpoint.onEvent((e) => events.push(e.type));
  b.endpoint.open();
  const replayer = await raw(carrier.dial);
  await until(() => replayer.frames.length >= 1, "fresh hello");
  replayer.send(hello);
  await until(() => replayer.frames.length >= 2, "victim proof");
  replayer.send(proof);
  await until(() => b.endpoint.state === "failed", "replay rejected");
  assert.equal(b.endpoint.failure, "signature");
  assert.deepEqual(events, []);
});

test("reflection, self-connection, wrong devices and stale identities are rejected", async () => {
  const reflected = await victim();
  const r = await attack(reflected);
  r.attacker.send(r.attacker.frames[0]);
  await failed(reflected, "self");

  const stranger = await peerDevice(null, { open: false });
  const other = await peerDevice(null, { open: false });
  const wrongDevice = await victim();
  const w = await attack(wrongDevice);
  w.attacker.send({
    type: "hello",
    payload: await forged(stranger, {
      device: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
    }),
  });
  await failed(wrongDevice, "unauthorized");

  const wrongRoster = await victim();
  const x = await attack(wrongRoster);
  x.attacker.send({
    type: "hello",
    payload: await forged(stranger, { roster: other.devices.roster! }),
  });
  await failed(wrongRoster, "unauthorized");

  const sameNonce = await victim();
  const n = await attack(sameNonce);
  n.attacker.send({
    type: "hello",
    payload: await forged(stranger, { nonce: n.hello.nonce }),
  });
  await failed(sameNonce, "protocol");
});

test("malformed, oversized, unknown, out-of-order and duplicate handshake frames fail closed", async () => {
  const stranger = await peerDevice(null, { open: false });
  const valid = await forged(stranger);
  const cases: [string, (target: Raw, own: PeerHello) => Promise<void>][] = [
    [
      "version",
      async (t) =>
        void t.send({ type: "hello", payload: { ...valid, version: 2 } }),
    ],
    [
      "malformed",
      async (t) =>
        void t.send({ type: "hello", payload: { ...valid, extra: 1 } }),
    ],
    [
      "malformed",
      async (t) => void t.send({ type: "hello", payload: valid, extra: true }),
    ],
    ["malformed", async (t) => void t.send("{not json")],
    ["malformed", async (t) => void t.send({ type: "teleport", payload: {} })],
    [
      "malformed",
      async (t) =>
        void t.send({ type: "message", payload: { id: "x", ciphertext: "x" } }),
    ],
    ["oversized", async (t) => void t.send("x".repeat(40 * 1024))],
    [
      "protocol",
      async (t) =>
        void t.send({
          type: "proof",
          payload: {
            signature: encodeBase64Url(new Uint8Array(64)),
            confirm: randomTag(),
          },
        }),
    ],
    [
      "protocol",
      async (t) =>
        void t.send({
          type: "sealed",
          payload: { data: encodeBase64Url(new Uint8Array(64)) },
        }),
    ],
    [
      "protocol",
      async (t) => {
        t.send({ type: "hello", payload: valid });
        await until(() => t.frames.length >= 2, "victim proof");
        t.send({ type: "hello", payload: await forged(stranger) });
      },
    ],
  ];
  for (const [failure, run] of cases) {
    const target = await victim();
    const { attacker, hello } = await attack(target);
    await run(attacker, hello);
    await failed(target, failure);
  }
});

test("a silent peer times out and leaves no timers or state behind", async () => {
  const target = await victim({ timeout: 150 });
  const { attacker } = await attack(target);
  await failed(target, "timeout");
  const states: string[] = [];
  target.device.endpoint.onState((s) => states.push(s));
  await sleep(300);
  assert.deepEqual(states, []);
  assert.ok(attacker.closed);
});

test("tampered, replayed, reordered and plaintext frames after authentication fail closed", async () => {
  const mutations: [string, Edit][] = [
    [
      "integrity",
      (frame, i) => {
        if (i !== 3) {
          return [frame];
        }
        const value = JSON.parse(frame) as Json;
        const data = Buffer.from(String(value.payload.data), "base64url");
        data[data.length - 1] ^= 1;
        return [
          JSON.stringify({
            ...value,
            payload: { data: data.toString("base64url") },
          }),
        ];
      },
    ],
    ["integrity", (frame, i) => (i === 3 ? [frame, frame] : [frame])],
    [
      "malformed",
      (frame, i) =>
        i === 3
          ? [
              JSON.stringify({
                type: "message",
                payload: { id: createMessageId(), ciphertext: "plain" },
              }),
            ]
          : [frame],
    ],
    [
      "protocol",
      (() => {
        let hello = "";
        return (frame: string, i: number) => {
          if (i === 0) {
            hello = frame;
          }
          return i === 3 ? [hello] : [frame];
        };
      })(),
    ],
  ];
  for (const [failure, edit] of mutations) {
    const held: string[] = [];
    const reorder: Edit = (frame, i) => {
      if (i === 3) {
        held.push(frame);
        return [];
      }
      return i === 4 ? [frame, ...held] : [frame];
    };
    for (const chosen of failure === "integrity" && held.length === 0
      ? [edit, reorder]
      : [edit]) {
      const carrier = await peerCarrier();
      const b = await peerDevice(carrier.listen);
      const events: string[] = [];
      b.endpoint.onEvent((e) => events.push(e.type));
      const a = await peerDevice(intercept(carrier.dial, { out: chosen }));
      await until(authenticated(a, b), "authenticated");
      void a.messenger.send(b.id, "trigger");
      void a.messenger.send(b.id, "trigger two");
      await until(() => b.endpoint.state === "failed", `${failure} detected`);
      assert.equal(b.endpoint.failure, failure);
      assert.ok(!bodies(b).includes("plain"));
    }
  }
});

test("device authorization and revocation are enforced from signed rosters without a server", async () => {
  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const b1 = await peerDevice(null, { open: false });
  const b2 = await peerDevice(carrier.dial, { root: b1.id, open: false });
  assert.equal(b2.devices.status, "pending");
  b2.endpoint.open();
  assert.equal(b2.endpoint.state, "pending");
  assert.equal(b2.endpoint.failure, "unauthorized");
  assert.equal(
    carrier.wire.out.length,
    0,
    "an unauthorized device sends nothing",
  );

  const root = b1.keys.root;
  assert.ok(root);
  const v2 = await signRoster(root, 2, [b1.devices.own, b2.devices.own]);
  assert.ok(v2 && (await b1.devices.adopt(v2)) && (await b2.devices.adopt(v2)));
  a.endpoint.open();
  b2.endpoint.open();
  await until(authenticated(a, b2), "authorized device authenticates");
  await b2.messenger.send(a.id, "from the linked device");
  await until(() => bodies(a).includes("from the linked device"), "delivered");

  const v3 = await signRoster(root, 3, [b1.devices.own]);
  assert.ok(v3);
  assert.ok(await a.trust.observe(v3));
  await until(
    () => a.endpoint.state === "failed",
    "session ends on revocation",
  );
  assert.equal(a.endpoint.failure, "revoked");
  await until(() => b2.endpoint.state === "unauthenticated", "b2 disconnected");
  assert.deepEqual(await b2.messenger.send(a.id, "after revocation"), {
    ok: false,
    reason: "authentication_required",
  });

  a.endpoint.open();
  b2.endpoint.open();
  await until(() => a.endpoint.state === "failed", "stale roster rejected");
  assert.equal(a.endpoint.failure, "stale");
  assert.ok(!bodies(a).includes("after revocation"));

  assert.ok(await b2.devices.adopt(v3));
  assert.equal(b2.devices.status, "revoked");
  b2.endpoint.open();
  await until(() => b2.endpoint.state === "revoked", "revoked device refuses");
  assert.equal(b2.endpoint.failure, "revoked");
});

test("a device that learns of its own revocation ends its active session", async () => {
  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const b1 = await peerDevice(null, { open: false });
  const b2 = await peerDevice(carrier.dial, { root: b1.id, open: false });
  const root = b1.keys.root!;
  const v2 = await signRoster(root, 2, [b1.devices.own, b2.devices.own]);
  assert.ok(v2 && (await b2.devices.adopt(v2)));
  b2.endpoint.open();
  await until(authenticated(a, b2), "authenticated");
  const v3 = await signRoster(root, 3, [b1.devices.own]);
  assert.ok(v3 && (await b2.devices.adopt(v3)));
  await until(() => b2.endpoint.state === "revoked", "own revocation");
  await until(() => a.endpoint.state === "unauthenticated", "peer sees close");
});

test("identity verification works over a direct link and detects a changed roster", async () => {
  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const b = await peerDevice(carrier.dial);
  await until(authenticated(a, b), "authenticated");
  const first = a.trust.view(b.id);
  assert.equal(first.state, "unverified");
  assert.ok(first.current);
  assert.ok(await a.trust.verify(b.id, first.current.value));
  assert.equal(a.trust.view(b.id).state, "verified");
  await a.messenger.send(b.id, "after verification");
  await until(() => bodies(b).includes("after verification"), "delivered");

  const extra = await peerDevice(null, { root: b.id, open: false });
  const v2 = await signRoster(b.keys.root!, 2, [
    b.devices.own,
    extra.devices.own,
  ]);
  assert.ok(v2 && (await b.devices.adopt(v2)));
  b.endpoint.close();
  await until(() => a.endpoint.state === "unauthenticated", "closed");
  const b2 = await peerDevice(carrier.dial, { store: b.store });
  a.endpoint.open();
  await until(authenticated(a, b2), "re-authenticated with new roster");
  assert.equal(a.trust.view(b.id).state, "changed");
  const changed = a.trust.view(b.id).current;
  assert.ok(changed && (await a.trust.verify(b.id, changed.value)));
  assert.equal(a.trust.view(b.id).state, "verified");
});

test("a direct link reaches only the linked device and never queues for unreachable devices", async () => {
  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const b1 = await peerDevice(carrier.dial, { open: false });
  const b2 = await peerDevice(null, { root: b1.id, open: false });
  const v2 = await signRoster(b1.keys.root!, 2, [
    b1.devices.own,
    b2.devices.own,
  ]);
  assert.ok(v2 && (await b1.devices.adopt(v2)));
  const parked = createMessageId();
  assert.ok(
    await a.outbox.add(
      [{ peer: b1.id, device: b2.deviceId, id: parked }],
      "parked for the other device",
      Date.now(),
    ),
  );
  b1.endpoint.open();
  await until(authenticated(a, b1), "authenticated");
  assert.equal(a.endpoint.reaches(b1.id, b1.deviceId), true);
  assert.equal(a.endpoint.reaches(b1.id, b2.deviceId), false);
  assert.deepEqual(await a.messenger.send(b1.id, "only the linked device"), {
    ok: true,
    devices: 1,
    pending: 0,
  });
  await until(() => bodies(b1).includes("only the linked device"), "b1");
  await sleep(200);
  assert.deepEqual(
    a.outbox.paths().map((p) => [p.device, p.id]),
    [[b2.deviceId, parked]],
    "nothing new is queued and the parked message is neither sent nor expired",
  );
  assert.equal(a.receipts.length, 1);
  assert.equal(a.pairs.state(pairAddress(b1.id, b2.deviceId)), "none");
});

test("an authenticated peer cannot target another device or misaddress envelopes", async () => {
  const { a, b } = await linked();
  const elsewhere = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const envelope = Buffer.alloc(minMessageSize);
  envelope[0] = 1;
  assert.equal(
    await a.endpoint.send(b.id, createMessageId(), [
      { device: elsewhere, ciphertext: envelope.toString("base64url") },
    ]),
    null,
  );
  assert.equal(
    await a.endpoint.initiate({
      version: 3,
      to: b.id,
      device: elsewhere,
      signed: 1,
      onetime: null,
      ephemeral: randomTag(),
      ratchet: randomTag(),
      proof: encodeBase64Url(new Uint8Array(64)),
      confirm: randomTag(),
    }),
    "unavailable",
  );
  await sleep(100);
  assert.equal(b.endpoint.state, "authenticated");
  assert.equal(b.inbox.length, 0);

  const events: string[] = [];
  b.endpoint.onEvent((e) => events.push(e.type));
  Object.defineProperty(a.endpoint, "peer", {
    get: () => ({ identity: b.id, device: elsewhere }),
  });
  await a.endpoint.initiate({
    version: 3,
    to: b.id,
    device: elsewhere,
    signed: 1,
    onetime: null,
    ephemeral: randomTag(),
    ratchet: randomTag(),
    proof: encodeBase64Url(new Uint8Array(64)),
    confirm: randomTag(),
  });
  await until(() => b.endpoint.state === "failed", "misdirected initiation");
  assert.equal(b.endpoint.failure, "protocol");
  assert.deepEqual(events, []);
});

test("established sessions with devices the link does not reach are never used", async () => {
  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const b1 = await peerDevice(null, { open: false });
  const b2 = await peerDevice(carrier.dial, { root: b1.id, open: false });
  const v2 = await signRoster(b1.keys.root!, 2, [
    b1.devices.own,
    b2.devices.own,
  ]);
  assert.ok(v2 && (await b1.devices.adopt(v2)) && (await b2.devices.adopt(v2)));
  b2.endpoint.open();
  await until(authenticated(a, b2), "b2 session");
  await a.messenger.send(b1.id, "to b2 while linked");
  await until(() => bodies(b2).includes("to b2 while linked"), "b2 receives");
  assert.equal(a.pairs.state(pairAddress(b1.id, b2.deviceId)), "established");
  b2.endpoint.close();
  await until(() => a.endpoint.state === "unauthenticated", "b2 gone");

  const parked = createMessageId();
  assert.ok(
    await a.outbox.add(
      [{ peer: b1.id, device: b2.deviceId, id: parked }],
      "parked",
      Date.now(),
    ),
  );
  const attempts: string[] = [];
  const send = a.endpoint.send.bind(a.endpoint);
  a.endpoint.send = (to, id, envelopes) => {
    attempts.push(...envelopes.map((e) => e.device));
    return send(to, id, envelopes);
  };
  const b1Link = await peerDevice(carrier.dial, { store: b1.store });
  a.endpoint.open();
  await until(authenticated(a, b1Link), "b1 session");
  await a.messenger.send(b1.id, "to b1 now");
  await until(() => bodies(b1Link).includes("to b1 now"), "b1 receives");
  await sleep(200);
  assert.ok(
    !attempts.includes(b2.deviceId),
    "no attempt to an unreachable device",
  );
  assert.deepEqual(
    a.outbox.paths().map((p) => p.id),
    [parked],
  );
});

function authorization(d: PeerDevice): PeerAuthorization | null {
  return d.endpoint.authorization;
}

function snapshot(store: MemoryStore): MemoryStore {
  const copy = memoryStore();
  for (const [key, value] of store.data) {
    copy.data.set(key, value);
  }
  return copy;
}

test("the authorization basis is explicit and never claims more than this device confirmed", async () => {
  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const b = await peerDevice(carrier.dial);
  await until(authenticated(a, b), "first contact");
  assert.deepEqual(authorization(a), {
    roster: 1,
    basis: "unconfirmed",
    confirmed: null,
  });
  assert.ok((await a.messenger.send(b.id, "peer roster lookups")).ok);
  assert.ok(await a.messenger.lookup(b.id));
  assert.equal(
    a.trust.confirmation(b.id),
    null,
    "a roster presented over the direct link is never confirmed",
  );
  assert.equal(authorization(a)?.basis, "unconfirmed");
  b.endpoint.close();
  await until(() => a.endpoint.state === "unauthenticated", "closed");
  assert.equal(authorization(a), null);

  const before = Date.now();
  assert.ok(await a.trust.observe(b.devices.roster, true));
  const again = await peerDevice(carrier.dial, { store: b.store });
  a.endpoint.open();
  await until(authenticated(a, again), "after an authoritative sync");
  const confirmed = authorization(a);
  assert.equal(confirmed?.basis, "confirmed");
  assert.equal(confirmed?.confirmed?.version, 1);
  assert.ok((confirmed?.confirmed?.at ?? 0) >= before);

  const extra = await peerDevice(null, { root: b.id, open: false });
  const v2 = await signRoster(b.keys.root!, 2, [
    b.devices.own,
    extra.devices.own,
  ]);
  assert.ok(v2 && (await again.devices.adopt(v2)));
  again.endpoint.close();
  await until(() => a.endpoint.state === "unauthenticated", "closed again");
  const newer = await peerDevice(carrier.dial, { store: b.store });
  a.endpoint.open();
  await until(authenticated(a, newer), "newer self-presented roster");
  assert.deepEqual(authorization(a), {
    roster: 2,
    basis: "unconfirmed",
    confirmed: { version: 1, at: confirmed!.confirmed!.at },
  });
});

test("rollback and equivocation stay rejected after restarting from persisted trust", async () => {
  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const b = await peerDevice(carrier.dial, { open: false });
  const v1Store = snapshot(b.store);
  const extra = await peerDevice(null, { root: b.id, open: false });
  const v2 = await signRoster(b.keys.root!, 2, [
    b.devices.own,
    extra.devices.own,
  ]);
  assert.ok(v2 && (await b.devices.adopt(v2)));
  b.endpoint.open();
  await until(authenticated(a, b), "pinned at version 2");
  b.endpoint.close();
  await a.shutdown();

  const restarted = await peerDevice(carrier.listen, { store: a.store });
  assert.equal(restarted.trust.pinned(b.id), 2);
  const rolledBack = await peerDevice(carrier.dial, { store: v1Store });
  await until(() => restarted.endpoint.state === "failed", "rollback");
  assert.equal(restarted.endpoint.failure, "stale");
  assert.notEqual(rolledBack.endpoint.state, "authenticated");
  await rolledBack.shutdown();

  const twinStore = snapshot(v1Store);
  const other = await peerDevice(null, { root: b.id, open: false });
  const twin = await signRoster(b.keys.root!, 2, [
    b.devices.own,
    other.devices.own,
  ]);
  assert.ok(twin && twin.signature !== v2.signature);
  const equivocating = await peerDevice(carrier.dial, {
    store: twinStore,
    open: false,
  });
  assert.ok(await equivocating.devices.adopt(twin));
  restarted.endpoint.open();
  equivocating.endpoint.open();
  await until(() => restarted.endpoint.state === "failed", "equivocation");
  assert.equal(restarted.endpoint.failure, "stale");
  assert.equal(restarted.endpoint.peer, null);
});

test("the frame counter boundary fails closed without ever reusing a nonce", async () => {
  const limit = 6;
  const { a, b, carrier } = await linked({ frames: limit });
  for (let i = 0; i < 4 && authenticated(a, b)(); i++) {
    await a.messenger.send(b.id, `bounded ${i}`);
  }
  await until(
    () => a.endpoint.state === "failed" || b.endpoint.state === "failed",
    "limit reached",
  );
  const failures = [a.endpoint.failure, b.endpoint.failure];
  assert.ok(failures.includes("limit"), JSON.stringify(failures));
  const { out, in: inbound } = decoded(carrier);
  for (const direction of [out, inbound]) {
    assert.ok(
      direction.filter((f) => f.type === "sealed").length <= limit,
      "no frame beyond the counter limit is ever sent",
    );
  }
});

test("a receiver enforces its own frame limit against a peer that ignores it", async () => {
  const carrier = await peerCarrier();
  const b = await peerDevice(carrier.listen, { frames: 4 });
  const a = await peerDevice(carrier.dial, { frames: 1000 });
  await until(authenticated(a, b), "authenticated");
  const sentByB = () =>
    decoded(carrier).in.filter((f) => f.type === "sealed").length;
  for (let i = 0; i < 5; i++) {
    a.endpoint.acknowledge({
      id: createMessageId(),
      from: b.id,
      device: b.deviceId,
      ciphertext: "",
    });
  }
  await until(() => b.endpoint.state === "failed", "receiver limit");
  assert.equal(b.endpoint.failure, "limit");
  assert.equal(
    sentByB(),
    0,
    "the receiver limit fired, not its own sender limit",
  );
});

test("frames recorded in one session never validate in a later session", async () => {
  const recorded: string[] = [];
  let connection = 0;
  const carrier = await peerCarrier();
  const b = await peerDevice(carrier.listen);
  const a = await peerDevice({
    connect: async (handlers) => {
      connection += 1;
      const current = connection;
      const inner = await carrier.dial.connect(handlers);
      let index = 0;
      return {
        send: (frame) => {
          const i = index++;
          if (current === 1 && i >= 2) {
            recorded.push(frame);
          }
          if (current === 2 && i === 2) {
            return inner.send(recorded[0]);
          }
          return inner.send(frame);
        },
        close: () => inner.close(),
      };
    },
  });
  await until(authenticated(a, b), "first session");
  await a.messenger.send(b.id, "first session message");
  await until(() => bodies(b).includes("first session message"), "delivered");
  assert.ok(recorded.length > 0);
  carrier.drop();
  await until(
    () =>
      a.endpoint.state === "unauthenticated" &&
      b.endpoint.state === "unauthenticated",
    "down",
  );
  b.endpoint.open();
  a.endpoint.open();
  await until(authenticated(a, b), "second session");
  void a.messenger.send(b.id, "second session message");
  await until(() => b.endpoint.state === "failed", "old frame rejected");
  assert.equal(b.endpoint.failure, "integrity");
  assert.equal(
    bodies(b).filter((m) => m === "first session message").length,
    1,
  );
});

test("per-connection setup and pending limits are enforced", async () => {
  const { a, b } = await linked();
  for (let i = 0; i < maxPeerSetup; i++) {
    const bundle = await a.endpoint.bundle(b.id);
    assert.ok(typeof bundle === "object");
  }
  await a.endpoint.bundle(b.id);
  await until(() => b.endpoint.state === "failed", "limit");
  assert.equal(b.endpoint.failure, "limit");

  const second = await linked({ requestTimeout: 3000 });
  second.b.endpoint.acknowledge = () => {};
  const envelope = Buffer.alloc(minMessageSize);
  envelope[0] = 1;
  const settled: SendOutcome[] = [];
  const flood = Array.from({ length: maxPeerPending + 1 }, () =>
    second.a.endpoint
      .send(second.b.id, createMessageId(), [
        {
          device: second.b.deviceId,
          ciphertext: envelope.toString("base64url"),
        },
      ])
      .then((outcome) => {
        settled.push(outcome);
        return outcome;
      }),
  );
  await sleep(1000);
  assert.deepEqual(
    settled,
    [null],
    "only the send beyond the bound settles early",
  );
  assert.equal(second.b.endpoint.state, "authenticated");
  const outcomes = await Promise.all(flood);
  assert.ok(
    outcomes.every((o) => o === null),
    "unacknowledged sends never succeed",
  );
  assert.equal(second.a.receipts.length, 0);
});

test("a closed endpoint is final and stale connections can never inject frames", async () => {
  const { a, b, carrier } = await linked();
  a.endpoint.close();
  assert.ok(a.endpoint.closed);
  assert.equal(a.endpoint.state, "unauthenticated");
  await until(() => b.endpoint.state === "unauthenticated", "peer sees close");
  a.endpoint.open();
  await sleep(100);
  assert.equal(
    a.transport.state,
    "disconnected",
    "a closed endpoint never reopens",
  );
  assert.equal(
    await a.endpoint.send(b.id, createMessageId(), [
      { device: b.deviceId, ciphertext: "x" },
    ]),
    null,
  );
  const states: string[] = [];
  a.endpoint.onState((s) => states.push(s));
  b.endpoint.open();
  a.transport.open();
  await until(() => a.transport.state === "connected", "transport reopened");
  await sleep(100);
  assert.deepEqual(
    states,
    [],
    "a closed endpoint no longer follows its carrier",
  );
  assert.equal(b.endpoint.state, "authenticating");
  a.transport.close();
  b.endpoint.close();
  const stale = await raw(carrier.dial);
  stale.send({ type: "hello", payload: await forged(a) });
  await sleep(200);
  assert.deepEqual(states, []);
  assert.equal(a.endpoint.peer, null);

  const early = await linked();
  early.a.endpoint.close();
  early.b.endpoint.close();
  const after: string[] = [];
  early.a.endpoint.onState((s) => after.push(s));
  await sleep(200);
  assert.deepEqual(after, []);
});

test("repeated connect and disconnect cycles stay deterministic", async () => {
  const { a, b, carrier } = await linked();
  for (let i = 0; i < 15; i++) {
    carrier.drop();
    await until(
      () =>
        a.endpoint.state === "unauthenticated" &&
        b.endpoint.state === "unauthenticated",
      `down ${i}`,
    );
    b.endpoint.open();
    a.endpoint.open();
    await until(authenticated(a, b), `up ${i}`);
  }
  await a.messenger.send(b.id, "after cycling");
  await until(() => bodies(b).includes("after cycling"), "delivered");
  assert.equal(bodies(b).filter((m) => m === "after cycling").length, 1);
});

test("a disconnect during authentication or ratchet setup leaves no session and recovers", async () => {
  let cut: (() => void) | null = null;
  const carrier = await peerCarrier();
  const b = await peerDevice(carrier.listen);
  const a = await peerDevice(
    intercept(carrier.dial, {
      out: (frame, i) => {
        if (i === 1 && cut) {
          const drop = cut;
          cut = null;
          setTimeout(drop, 0);
        }
        return [frame];
      },
    }),
    { open: false },
  );
  cut = () => carrier.drop();
  a.endpoint.open();
  await until(
    () =>
      cut === null &&
      a.transport.state === "error" &&
      b.transport.state === "error",
    "cut during authentication",
  );
  assert.equal(a.endpoint.state, "unauthenticated");
  assert.equal(b.endpoint.state, "unauthenticated");
  assert.equal(a.endpoint.peer, null);
  assert.equal(b.endpoint.peer, null);

  b.endpoint.open();
  a.endpoint.open();
  await until(authenticated(a, b), "authenticated");
  const establishing = a.messenger.send(b.id, "during setup");
  await sleep(1);
  carrier.drop();
  const result = await establishing;
  if (result.ok) {
    await until(
      () => bodies(b).includes("during setup"),
      "ok implies delivered",
    );
  }
  await until(
    () =>
      a.endpoint.state === "unauthenticated" &&
      b.endpoint.state === "unauthenticated",
    "down",
  );
  b.endpoint.open();
  a.endpoint.open();
  await until(authenticated(a, b), "recovered");
  assert.ok((await a.messenger.send(b.id, "after recovery")).ok);
  await until(() => bodies(b).includes("after recovery"), "delivered");
});

test("fuzzed handshake and session frames never parse loosely or crash", async () => {
  const stranger = await peerDevice(null, { open: false });
  const hello = await forged(stranger);
  const seeds: unknown[] = [
    { type: "hello", payload: hello },
    {
      type: "proof",
      payload: {
        signature: encodeBase64Url(new Uint8Array(64)),
        confirm: randomTag(),
      },
    },
    { type: "sealed", payload: { data: encodeBase64Url(new Uint8Array(40)) } },
    { type: "bundle", id: "abc", payload: {} },
    { type: "ack", payload: { id: createMessageId() } },
    { type: "initiated", id: "abc", payload: {} },
  ];
  let seed = 0x5eed;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const junk = [
    null,
    0,
    -1,
    1.5,
    "",
    "x",
    [],
    {},
    true,
    "A".repeat(43),
    2 ** 53,
  ];
  const mutate = (value: unknown, depth = 0): unknown => {
    if (typeof value !== "object" || value === null || depth > 3) {
      return random(3) === 0 ? junk[random(junk.length)] : value;
    }
    const copy: Record<string, unknown> = Array.isArray(value)
      ? ({ ...value } as Record<string, unknown>)
      : { ...(value as Record<string, unknown>) };
    const keys = Object.keys(copy);
    switch (random(4)) {
      case 0:
        if (keys.length) delete copy[keys[random(keys.length)]];
        break;
      case 1:
        copy[`k${random(5)}`] = junk[random(junk.length)];
        break;
      default:
        if (keys.length) {
          const key = keys[random(keys.length)];
          copy[key] = mutate(copy[key], depth + 1);
        }
    }
    return copy;
  };
  const rounds = Number(process.env.FUZZ_ITERATIONS ?? 3000);
  for (let i = 0; i < rounds; i++) {
    const text = JSON.stringify(mutate(seeds[random(seeds.length)]));
    const cut = random(4) === 0 ? text.slice(0, random(text.length + 1)) : text;
    for (const parse of [parseHandshakeFrame, parseSessionFrame]) {
      const parsed = parse(cut);
      if (parsed) {
        assert.deepEqual(parse(JSON.stringify(parsed)), parsed);
        assert.deepEqual(
          Object.keys(JSON.parse(cut)).sort(),
          Object.keys(parsed).sort(),
        );
      }
    }
  }

  const machineRounds = Number(process.env.FUZZ_ITERATIONS ?? 3000) / 50;
  for (let i = 0; i < machineRounds; i++) {
    const target = await victim({ timeout: 300 });
    const { attacker, hello: own } = await attack(target);
    for (let step = 0; step < 4; step++) {
      const choice = random(4);
      if (choice === 0) {
        attacker.send({ type: "hello", payload: await forged(stranger) });
      } else if (choice === 1) {
        attacker.send({
          type: "proof",
          payload: {
            signature: await proofOf(stranger, hello, own),
            confirm: randomTag(),
          },
        });
      } else {
        attacker.send(JSON.stringify(mutate(seeds[random(seeds.length)])));
      }
    }
    await until(
      () => target.device.endpoint.state === "failed",
      "fails closed",
    );
    assert.deepEqual(target.events, []);
    assert.equal(target.device.endpoint.peer, null);
  }
});
