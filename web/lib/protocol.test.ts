import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64Url } from "./base64.ts";
import {
  bodySize,
  createId,
  encode,
  isValidBody,
  maxBodySize,
  maxSessions,
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

function sessionBundle(overrides: Record<string, unknown> = {}) {
  return {
    session: b64(16),
    epoch: 0,
    key: b64(32),
    signature: b64(64),
    ...overrides,
  };
}

function envelope(overrides: Record<string, unknown> = {}) {
  return {
    session: b64(16),
    epoch: 3,
    salt: b64(32),
    iv: b64(12),
    ciphertext: b64(40),
    ...overrides,
  };
}

function delivery(
  overrides: Record<string, unknown> = {},
  sender: Record<string, unknown> = {},
  sealed: Record<string, unknown> = {},
) {
  return {
    id: "m1",
    from: "B".repeat(42) + "A",
    key: b64(32),
    signature: b64(64),
    sender: sessionBundle(sender),
    envelope: envelope(sealed),
    ...overrides,
  };
}

test("parses messaging replies, key bundles, and encrypted deliveries", () => {
  const identity = "B".repeat(42) + "A";
  for (const type of ["sent", "published", "established"]) {
    assert.deepEqual(parse(JSON.stringify({ type, id: "m1", payload: {} })), {
      type,
      id: "m1",
      payload: {},
    });
  }
  for (const sessions of [
    [],
    [sessionBundle()],
    [sessionBundle(), sessionBundle({ epoch: 2 ** 31 - 1 })],
    Array.from({ length: maxSessions }, () => sessionBundle()),
  ]) {
    const bundle = { identity, key: b64(32), signature: b64(64), sessions };
    assert.deepEqual(
      parse(JSON.stringify({ type: "key", id: "q1", payload: bundle })),
      { type: "key", id: "q1", payload: bundle },
    );
  }
  const payload = delivery();
  assert.deepEqual(parse(JSON.stringify({ type: "message", payload })), {
    type: "message",
    payload,
  });
  for (const code of [
    "recipient_unavailable",
    "message_too_large",
    "key_required",
    "duplicate_message",
    "stale_session",
    "session_limit",
  ]) {
    assert.deepEqual(
      parse(JSON.stringify({ type: "error", id: "m1", payload: { code } })),
      { type: "error", id: "m1", payload: { code } },
    );
  }
});

test("rejects malformed key bundles and deliveries", () => {
  const identity = "B".repeat(42) + "A";
  const bundle = { identity, key: b64(32), signature: b64(64), sessions: [] };
  const twin = sessionBundle();
  const badEpochs = [-1, 0.5, 2 ** 31, "0", null, Number.MAX_SAFE_INTEGER + 2];
  for (const message of [
    { type: "key", payload: bundle },
    { type: "key", id: "q1", payload: { ...bundle, key: b64(31) } },
    { type: "key", id: "q1", payload: { ...bundle, signature: b64(63) } },
    { type: "key", id: "q1", payload: { ...bundle, identity: "short" } },
    { type: "key", id: "q1", payload: { ...bundle, private: b64(32) } },
    {
      type: "key",
      id: "q1",
      payload: { identity, key: b64(32), signature: b64(64) },
    },
    { type: "key", id: "q1", payload: { ...bundle, sessions: null } },
    {
      type: "key",
      id: "q1",
      payload: { ...bundle, sessions: sessionBundle() },
    },
    { type: "key", id: "q1", payload: { ...bundle, sessions: [twin, twin] } },
    {
      type: "key",
      id: "q1",
      payload: {
        ...bundle,
        sessions: Array.from({ length: maxSessions + 1 }, () =>
          sessionBundle(),
        ),
      },
    },
    ...[
      { session: b64(15) },
      { session: b64(16) + "=" },
      { key: b64(31) },
      { signature: "x" },
      { private: b64(32) },
      ...badEpochs.map((epoch) => ({ epoch })),
    ].map((field) => ({
      type: "key",
      id: "q1",
      payload: { ...bundle, sessions: [sessionBundle(field)] },
    })),
    { type: "published", payload: {} },
    { type: "established", id: "k1", payload: { epoch: 1 } },
    { type: "message", id: "m1", payload: delivery() },
    { type: "message", payload: delivery({ body: "plaintext" }) },
    {
      type: "message",
      payload: delivery({ salt: b64(32), iv: b64(12), ciphertext: b64(40) }),
    },
    { type: "message", payload: delivery({ id: "bad id" }) },
    { type: "message", payload: delivery({ from: "short" }) },
    { type: "message", payload: delivery({ key: b64(33) }) },
    { type: "message", payload: delivery({ signature: "x" }) },
    { type: "message", payload: delivery({ sender: undefined }) },
    { type: "message", payload: delivery({ envelope: undefined }) },
    { type: "message", payload: delivery({ envelope: [envelope()] }) },
    ...badEpochs.map((epoch) => ({
      type: "message",
      payload: delivery({}, { epoch }),
    })),
    ...badEpochs.map((epoch) => ({
      type: "message",
      payload: delivery({}, {}, { epoch }),
    })),
    { type: "message", payload: delivery({}, { session: b64(17) }) },
    { type: "message", payload: delivery({}, { key: b64(31) }) },
    { type: "message", payload: delivery({}, { extra: 1 }) },
    { type: "message", payload: delivery({}, {}, { session: "" }) },
    { type: "message", payload: delivery({}, {}, { salt: b64(31) }) },
    { type: "message", payload: delivery({}, {}, { iv: b64(16) }) },
    { type: "message", payload: delivery({}, {}, { iv: b64(12) + "=" }) },
    { type: "message", payload: delivery({}, {}, { ciphertext: "" }) },
    { type: "message", payload: delivery({}, {}, { ciphertext: b64(16) }) },
    {
      type: "message",
      payload: delivery({}, {}, { ciphertext: b64(maxBodySize + 17) }),
    },
    { type: "message", payload: delivery({}, {}, { ciphertext: 7 }) },
    { type: "message", payload: delivery({}, {}, { body: "plaintext" }) },
    { type: "message", payload: delivery(), extra: 1 },
  ]) {
    assert.equal(parse(JSON.stringify(message)), null, JSON.stringify(message));
  }
  for (const ciphertext of [b64(17), b64(maxBodySize + 16)]) {
    assert.ok(
      parse(
        JSON.stringify({
          type: "message",
          payload: delivery({}, {}, { ciphertext }),
        }),
      ),
    );
  }
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
