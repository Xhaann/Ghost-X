import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64Url } from "./base64.ts";
import {
  bodySize,
  createId,
  encode,
  isValidBody,
  maxBodySize,
  createMessageId,
  isMessage,
  isMessageId,
  maxDevices,
  maxMessageSize,
  minMessageSize,
  parse,
} from "./protocol.ts";

const pong = (overrides: Record<string, unknown> = {}) =>
  JSON.stringify({
    type: "pong",
    id: "r1",
    payload: { sentAt: 1, receivedAt: 2 },
    ...overrides,
  });

test("parses a pong", () => {
  assert.deepEqual(parse(pong()), {
    type: "pong",
    id: "r1",
    payload: { sentAt: 1, receivedAt: 2 },
  });
});

test("parses errors with and without an id", () => {
  assert.deepEqual(
    parse('{"type":"error","id":"r1","payload":{"code":"invalid_payload"}}'),
    { type: "error", id: "r1", payload: { code: "invalid_payload" } },
  );
  assert.deepEqual(
    parse('{"type":"error","payload":{"code":"invalid_message"}}'),
    { type: "error", payload: { code: "invalid_message" } },
  );
});

test("rejects malformed messages", () => {
  const invalid: unknown[] = [
    undefined,
    null,
    42,
    new ArrayBuffer(4),
    "",
    "not json",
    "{",
    "null",
    "[]",
    '"pong"',
    "{}",
    '{"type":"pong","id":"r1"}',
    '{"type":"pong","id":"r1","payload":null}',
    '{"type":"pong","id":"r1","payload":[]}',
    pong({ id: undefined }),
    pong({ id: "" }),
    pong({ id: "has space" }),
    pong({ id: "a".repeat(65) }),
    pong({ id: 7 }),
    pong({ extra: true }),
    pong({ payload: { sentAt: 1 } }),
    pong({ payload: { sentAt: 1, receivedAt: 2, extra: 3 } }),
    pong({ payload: { sentAt: "1", receivedAt: 2 } }),
    pong({ payload: { sentAt: 1.5, receivedAt: 2 } }),
    pong({ payload: { sentAt: -1, receivedAt: 2 } }),
    pong({ payload: { sentAt: 2 ** 53, receivedAt: 2 } }),
    '{"type":"pong","id":"r1","payload":{"sentAt":1,"receivedAt":2},"__proto__":{}}',
    '{"type":"error","payload":{"code":"unknown_code"}}',
    '{"type":"error","payload":{"code":1}}',
    '{"type":"error","payload":{"code":"internal_error","detail":"x"}}',
    '{"type":"error","id":"bad id","payload":{"code":"internal_error"}}',
    '{"type":"error","extra":1,"payload":{"code":"internal_error"}}',
  ];

  for (const data of invalid) {
    assert.equal(parse(data), null, `accepted ${String(data)}`);
  }
});

test("parses challenge and authenticated messages", () => {
  const nonce = "A".repeat(43);
  const identity = "B".repeat(42) + "A";
  assert.deepEqual(
    parse(JSON.stringify({ type: "challenge", id: "c1", payload: { nonce } })),
    { type: "challenge", id: "c1", payload: { nonce } },
  );
  assert.deepEqual(
    parse(
      JSON.stringify({
        type: "authenticated",
        id: "p1",
        payload: { identity },
      }),
    ),
    { type: "authenticated", id: "p1", payload: { identity } },
  );
  assert.deepEqual(
    parse(
      '{"type":"error","id":"p1","payload":{"code":"authentication_failed"}}',
    ),
    { type: "error", id: "p1", payload: { code: "authentication_failed" } },
  );
});

test("rejects malformed challenge and authenticated messages", () => {
  const nonce = "A".repeat(43);
  const identity = "B".repeat(42) + "A";
  const invalid = [
    { type: "challenge", payload: { nonce } },
    { type: "challenge", id: "c1", payload: {} },
    { type: "challenge", id: "c1", payload: { nonce: nonce + "A" } },
    { type: "challenge", id: "c1", payload: { nonce: nonce.slice(1) } },
    { type: "challenge", id: "c1", payload: { nonce: "B".repeat(43) } },
    { type: "challenge", id: "c1", payload: { nonce: nonce + "=" } },
    { type: "challenge", id: "c1", payload: { nonce: 1 } },
    { type: "challenge", id: "c1", payload: { nonce, extra: 1 } },
    { type: "challenge", id: "c1", payload: { nonce }, extra: 1 },
    { type: "authenticated", payload: { identity } },
    { type: "authenticated", id: "p1", payload: {} },
    { type: "authenticated", id: "p1", payload: { identity: identity + "A" } },
    { type: "authenticated", id: "p1", payload: { identity: "B".repeat(43) } },
    { type: "authenticated", id: "p1", payload: { identity: null } },
    { type: "authenticated", id: "p1", payload: { identity, extra: 1 } },
  ];
  for (const message of invalid) {
    assert.equal(parse(JSON.stringify(message)), null, JSON.stringify(message));
  }
});

test("parses whoami and authentication_required", () => {
  const identity = "B".repeat(42) + "A";
  assert.deepEqual(
    parse(JSON.stringify({ type: "whoami", id: "w1", payload: { identity } })),
    { type: "whoami", id: "w1", payload: { identity } },
  );
  assert.deepEqual(
    parse(
      '{"type":"error","id":"w1","payload":{"code":"authentication_required"}}',
    ),
    { type: "error", id: "w1", payload: { code: "authentication_required" } },
  );
  for (const message of [
    { type: "whoami", payload: { identity } },
    { type: "whoami", id: "w1", payload: {} },
    { type: "whoami", id: "w1", payload: { identity: "short" } },
    { type: "whoami", id: "w1", payload: { identity, extra: 1 } },
  ]) {
    assert.equal(parse(JSON.stringify(message)), null);
  }
});

test("parses presence messages", () => {
  const identity = "B".repeat(42) + "A";
  assert.deepEqual(parse('{"type":"presence","id":"s1","payload":{}}'), {
    type: "presence",
    id: "s1",
    payload: {},
  });
  for (const type of ["present", "absent"]) {
    assert.deepEqual(parse(JSON.stringify({ type, payload: { identity } })), {
      type,
      payload: { identity },
    });
  }
});

test("rejects malformed presence messages", () => {
  const identity = "B".repeat(42) + "A";
  for (const message of [
    { type: "presence", payload: {} },
    { type: "presence", id: "s1", payload: { identity } },
    { type: "presence", id: "s1" },
    { type: "present", id: "p1", payload: { identity } },
    { type: "present", payload: {} },
    { type: "present", payload: { identity: "short" } },
    { type: "present", payload: { identity: "B".repeat(43) } },
    { type: "present", payload: { identity, extra: 1 } },
    { type: "absent", payload: { identity: null } },
    { type: "absent", payload: { identity }, extra: 1 },
  ]) {
    assert.equal(parse(JSON.stringify(message)), null, JSON.stringify(message));
  }
});

function b64(size: number): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(size)));
}

function sealed(size: number, version = 1): string {
  const bytes = crypto.getRandomValues(new Uint8Array(size));
  bytes[0] = version;
  return encodeBase64Url(bytes);
}

function delivery(overrides: Record<string, unknown> = {}) {
  return {
    id: createMessageId(),
    from: "B".repeat(42) + "A",
    key: b64(32),
    signature: b64(64),
    ciphertext: sealed(120),
    ...overrides,
  };
}

test("parses queue replies, key bundles, deliveries, and receipts", () => {
  const identity = "B".repeat(42) + "A";
  for (const type of ["queued", "fetched", "acked", "cleared", "published"]) {
    assert.deepEqual(parse(JSON.stringify({ type, id: "m1", payload: {} })), {
      type,
      id: "m1",
      payload: {},
    });
  }
  const bundle = { identity, key: b64(32), signature: b64(64) };
  assert.deepEqual(
    parse(JSON.stringify({ type: "key", id: "q1", payload: bundle })),
    { type: "key", id: "q1", payload: bundle },
  );
  for (const size of [minMessageSize, 200, maxMessageSize]) {
    const payload = delivery({ ciphertext: sealed(size) });
    assert.deepEqual(parse(JSON.stringify({ type: "message", payload })), {
      type: "message",
      payload,
    });
  }
  for (const status of ["delivered", "expired"]) {
    const payload = { to: identity, id: createMessageId(), status };
    assert.deepEqual(parse(JSON.stringify({ type: "receipt", payload })), {
      type: "receipt",
      payload,
    });
  }
  for (const code of [
    "recipient_unavailable",
    "message_too_large",
    "key_required",
    "duplicate_message",
    "queue_full",
  ]) {
    assert.deepEqual(
      parse(JSON.stringify({ type: "error", id: "m1", payload: { code } })),
      { type: "error", id: "m1", payload: { code } },
    );
  }
});

test("rejects malformed key bundles, deliveries, and receipts", () => {
  const identity = "B".repeat(42) + "A";
  const bundle = { identity, key: b64(32), signature: b64(64) };
  const receipt = { to: identity, id: createMessageId(), status: "delivered" };
  for (const message of [
    { type: "key", payload: bundle },
    { type: "key", id: "q1", payload: { ...bundle, key: b64(31) } },
    { type: "key", id: "q1", payload: { ...bundle, signature: b64(63) } },
    { type: "key", id: "q1", payload: { ...bundle, identity: "short" } },
    { type: "key", id: "q1", payload: { ...bundle, private: b64(32) } },
    { type: "key", id: "q1", payload: { ...bundle, sessions: [] } },
    { type: "published", payload: {} },
    { type: "queued", id: "s1", payload: { delivered: true } },
    { type: "sent", id: "s1", payload: {} },
    { type: "established", id: "k1", payload: {} },
    { type: "message", id: "m1", payload: delivery() },
    { type: "message", payload: delivery({ body: "plaintext" }) },
    { type: "message", payload: delivery({ id: "m1" }) },
    { type: "message", payload: delivery({ id: b64(15) }) },
    { type: "message", payload: delivery({ id: b64(16) + "=" }) },
    { type: "message", payload: delivery({ from: "short" }) },
    { type: "message", payload: delivery({ key: b64(33) }) },
    { type: "message", payload: delivery({ signature: "x" }) },
    { type: "message", payload: delivery({ ciphertext: undefined }) },
    { type: "message", payload: delivery({ ciphertext: 7 }) },
    { type: "message", payload: delivery({ ciphertext: "" }) },
    {
      type: "message",
      payload: delivery({ ciphertext: sealed(minMessageSize - 1) }),
    },
    {
      type: "message",
      payload: delivery({ ciphertext: sealed(maxMessageSize + 1) }),
    },
    { type: "message", payload: delivery({ ciphertext: sealed(120, 0) }) },
    { type: "message", payload: delivery({ ciphertext: sealed(120, 2) }) },
    { type: "message", payload: delivery({ ciphertext: sealed(120) + "=" }) },
    { type: "message", payload: delivery({ envelope: {} }) },
    { type: "message", payload: delivery({ status: "delivered" }) },
    { type: "message", payload: delivery(), extra: 1 },
    { type: "receipt", id: "r1", payload: receipt },
    { type: "receipt", payload: { ...receipt, status: "read" } },
    { type: "receipt", payload: { ...receipt, status: "queued" } },
    { type: "receipt", payload: { ...receipt, id: "m1" } },
    { type: "receipt", payload: { ...receipt, to: "short" } },
    { type: "receipt", payload: { ...receipt, from: identity } },
    { type: "receipt", payload: { to: identity, id: receipt.id } },
  ]) {
    assert.equal(parse(JSON.stringify(message)), null, JSON.stringify(message));
  }
});

test("message identifiers are 128-bit random and strictly validated", () => {
  const ids = new Set(Array.from({ length: 2000 }, createMessageId));
  assert.equal(ids.size, 2000);
  for (const id of ids) {
    assert.match(id, /^[A-Za-z0-9_-]{22}$/);
    assert.equal(isMessageId(id), true);
  }
  for (const bad of [
    "",
    "m1",
    createId(),
    b64(15),
    b64(17),
    b64(16) + "=",
    b64(16).slice(0, 21) + "B",
    "!".repeat(22),
    null,
    16,
  ]) {
    assert.equal(isMessageId(bad), false, String(bad));
  }
  assert.equal(isMessage(sealed(minMessageSize)), true);
  assert.equal(isMessage(sealed(maxMessageSize)), true);
  assert.equal(isMessage(sealed(maxMessageSize + 1)), false);
  assert.equal(isMessage(sealed(minMessageSize - 1)), false);
  assert.equal(isMessage(sealed(200, 0)), false);
});

test("validates message bodies like the server", () => {
  assert.equal(isValidBody("x"), true);
  assert.equal(isValidBody("tab\tline\nreturn\r"), true);
  assert.equal(isValidBody("a".repeat(maxBodySize)), true);
  assert.equal(isValidBody("é".repeat(maxBodySize / 2)), true);
  assert.equal(bodySize("é"), 2);
  for (const body of [
    "",
    "a".repeat(maxBodySize + 1),
    "é".repeat(maxBodySize / 2 + 1),
    "a\u0000",
    "a\u001b",
    "a\u007f",
    null,
    1,
  ]) {
    assert.equal(isValidBody(body), false, JSON.stringify(body));
  }
});

test("rejects unsupported message types", () => {
  for (const type of ["ping", "unknown", "PONG", "", 1, null]) {
    assert.equal(parse(pong({ type })), null, `accepted type ${type}`);
  }
});

test("encodes client messages", () => {
  assert.deepEqual(
    JSON.parse(encode({ type: "ping", payload: { sentAt: 5 } }, "r1")),
    { type: "ping", id: "r1", payload: { sentAt: 5 } },
  );
  assert.equal(
    encode({ type: "challenge", payload: {} }, "c1"),
    '{"type":"challenge","id":"c1","payload":{}}',
  );
});

test("creates unique valid ids", () => {
  const ids = new Set(Array.from({ length: 1000 }, createId));
  assert.equal(ids.size, 1000);
  for (const id of ids) {
    assert.match(id, /^[a-f0-9]{24}$/);
  }
});

function prekey(overrides: Record<string, unknown> = {}) {
  return { id: 7, key: b64(32), signature: b64(64), ...overrides };
}

function deviceBundle(overrides: Record<string, unknown> = {}) {
  return {
    device: b64(16),
    signed: prekey(),
    onetime: prekey({ id: 9 }),
    ...overrides,
  };
}

function initiationPayload(overrides: Record<string, unknown> = {}) {
  return {
    version: 2,
    from: "B".repeat(42) + "A",
    key: b64(32),
    signature: b64(64),
    device: b64(16),
    signed: 7,
    onetime: 9,
    ephemeral: b64(32),
    ratchet: b64(32),
    proof: b64(64),
    confirm: b64(32),
    ...overrides,
  };
}

test("parses prekey bundles, handshake pushes, and replies", () => {
  const identity = "B".repeat(42) + "A";
  const bundle = {
    version: 2,
    identity,
    key: b64(32),
    signature: b64(64),
    bundles: [deviceBundle(), deviceBundle({ onetime: null })],
  };
  assert.deepEqual(
    parse(JSON.stringify({ type: "bundle", id: "b1", payload: bundle })),
    { type: "bundle", id: "b1", payload: bundle },
  );
  for (const type of ["initiated", "accepted"]) {
    assert.deepEqual(parse(JSON.stringify({ type, id: "x1", payload: {} })), {
      type,
      id: "x1",
      payload: {},
    });
  }
  assert.deepEqual(
    parse(
      JSON.stringify({ type: "prekeys", id: "p1", payload: { available: 20 } }),
    ),
    { type: "prekeys", id: "p1", payload: { available: 20 } },
  );
  for (const payload of [
    initiationPayload(),
    initiationPayload({ onetime: null }),
  ]) {
    assert.deepEqual(parse(JSON.stringify({ type: "initiation", payload })), {
      type: "initiation",
      payload,
    });
  }
  const acceptance = { from: identity, ephemeral: b64(32), confirm: b64(32) };
  assert.deepEqual(
    parse(JSON.stringify({ type: "acceptance", payload: acceptance })),
    { type: "acceptance", payload: acceptance },
  );
  assert.deepEqual(
    parse(
      JSON.stringify({
        type: "error",
        id: "x",
        payload: { code: "pending_limit" },
      }),
    ),
    { type: "error", id: "x", payload: { code: "pending_limit" } },
  );
});

test("rejects malformed prekey bundles and handshake messages", () => {
  const identity = "B".repeat(42) + "A";
  const bundle = {
    version: 2,
    identity,
    key: b64(32),
    signature: b64(64),
    bundles: [deviceBundle()],
  };
  const twin = deviceBundle();
  for (const message of [
    { type: "bundle", payload: bundle },
    { type: "bundle", id: "b", payload: { ...bundle, version: 1 } },
    { type: "bundle", id: "b", payload: { ...bundle, version: "1" } },
    { type: "bundle", id: "b", payload: { ...bundle, bundles: [] } },
    { type: "bundle", id: "b", payload: { ...bundle, bundles: [twin, twin] } },
    {
      type: "bundle",
      id: "b",
      payload: {
        ...bundle,
        bundles: Array.from({ length: 5 }, () => deviceBundle()),
      },
    },
    { type: "bundle", id: "b", payload: { ...bundle, verified: true } },
    { type: "bundle", id: "b", payload: { ...bundle, identity: "x" } },
    ...[
      { device: b64(15) },
      { signed: null },
      { signed: prekey({ id: -1 }) },
      { signed: prekey({ id: 2 ** 31 }) },
      { signed: prekey({ key: b64(31) }) },
      { signed: prekey({ signature: "x" }) },
      { signed: prekey({ privateKey: b64(32) }) },
      { onetime: prekey({ id: 1.5 }) },
      { onetime: prekey({ key: b64(33) }) },
      { onetime: "none" },
      { extra: 1 },
    ].map((field) => ({
      type: "bundle",
      id: "b",
      payload: { ...bundle, bundles: [deviceBundle(field)] },
    })),
    { type: "prekeys", id: "p", payload: { available: -1 } },
    { type: "prekeys", id: "p", payload: { available: 101 } },
    { type: "prekeys", id: "p", payload: { available: 1, extra: 1 } },
    { type: "initiated", payload: {} },
    { type: "initiation", id: "x", payload: initiationPayload() },
    ...[
      { version: 1 },
      { ratchet: b64(31) },
      { ratchet: undefined },
      { from: "x" },
      { key: b64(31) },
      { device: b64(17) },
      { signed: -1 },
      { signed: "7" },
      { onetime: 1.5 },
      { onetime: "9" },
      { ephemeral: b64(31) },
      { proof: b64(63) },
      { confirm: b64(31) },
      { body: "plaintext" },
      { private: b64(32) },
    ].map((field) => ({
      type: "initiation",
      payload: initiationPayload(field),
    })),
    { type: "acceptance", payload: { from: identity, ephemeral: b64(32) } },
    {
      type: "acceptance",
      payload: { from: identity, ephemeral: b64(32), confirm: b64(31) },
    },
    {
      type: "acceptance",
      payload: {
        from: identity,
        ephemeral: b64(32),
        confirm: b64(32),
        root: b64(32),
      },
    },
  ]) {
    assert.equal(
      parse(JSON.stringify(message)),
      null,
      JSON.stringify(message).slice(0, 120),
    );
  }
});

test("fuzzed delivery and receipt frames parse only into valid queue messages", () => {
  const identity = "B".repeat(42) + "A";
  const bases = [
    JSON.stringify({ type: "message", payload: delivery() }),
    JSON.stringify({
      type: "receipt",
      payload: { to: identity, id: createMessageId(), status: "delivered" },
    }),
    JSON.stringify({ type: "queued", id: "s1", payload: {} }),
  ];
  let seed = 0x7a11;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const alphabet = '{}[]":,0123456789abcdefABCDEF-_=null truefalse';
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 20000);
  for (let i = 0; i < iterations; i++) {
    let text = bases[random(bases.length)];
    for (let k = 0, n = 1 + random(4); k < n; k++) {
      const at = random(text.length);
      const op = random(3);
      const ch = alphabet[random(alphabet.length)];
      text =
        op === 0
          ? text.slice(0, at) + text.slice(at + 1)
          : op === 1
            ? text.slice(0, at) + ch + text.slice(at)
            : text.slice(0, at) + ch + text.slice(at + 1);
    }
    const parsed = parse(text);
    if (parsed?.type === "message") {
      assert.ok(isMessageId(parsed.payload.id));
      assert.ok(isMessage(parsed.payload.ciphertext));
      assert.deepEqual(Object.keys(parsed.payload).sort(), [
        "ciphertext",
        "from",
        "id",
        "key",
        "signature",
      ]);
    } else if (parsed?.type === "receipt") {
      assert.ok(isMessageId(parsed.payload.id));
      assert.ok(["delivered", "expired"].includes(parsed.payload.status));
    } else if (parsed) {
      assert.ok(
        [
          "queued",
          "error",
          "fetched",
          "acked",
          "cleared",
          "published",
        ].includes(parsed.type),
        parsed.type,
      );
    }
  }
});
