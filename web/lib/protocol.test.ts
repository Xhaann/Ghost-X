import assert from "node:assert/strict";
import { test } from "node:test";
import {
  bodySize,
  createId,
  encode,
  isValidBody,
  maxBodySize,
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

test("parses messaging replies and deliveries", () => {
  const from = "B".repeat(42) + "A";
  assert.deepEqual(parse('{"type":"sent","id":"m1","payload":{}}'), {
    type: "sent",
    id: "m1",
    payload: {},
  });
  assert.deepEqual(
    parse(
      JSON.stringify({
        type: "message",
        payload: { id: "m1", from, body: "hi\n" },
      }),
    ),
    { type: "message", payload: { id: "m1", from, body: "hi\n" } },
  );
  for (const code of ["recipient_unavailable", "message_too_large"]) {
    assert.deepEqual(
      parse(JSON.stringify({ type: "error", id: "m1", payload: { code } })),
      { type: "error", id: "m1", payload: { code } },
    );
  }
});

test("rejects malformed messaging frames", () => {
  const from = "B".repeat(42) + "A";
  for (const message of [
    { type: "sent", payload: {} },
    { type: "sent", id: "m1", payload: { to: from } },
    { type: "message", id: "m1", payload: { id: "m1", from, body: "x" } },
    { type: "message", payload: { from, body: "x" } },
    { type: "message", payload: { id: "", from, body: "x" } },
    { type: "message", payload: { id: "bad id", from, body: "x" } },
    { type: "message", payload: { id: "a".repeat(65), from, body: "x" } },
    { type: "message", payload: { id: 1, from, body: "x" } },
    { type: "message", payload: { id: "m1", body: "x" } },
    { type: "message", payload: { id: "m1", from, body: "" } },
    { type: "message", payload: { id: "m1", from, body: 1 } },
    { type: "message", payload: { id: "m1", from: "short", body: "x" } },
    { type: "message", payload: { id: "m1", from, body: "x", to: from } },
    { type: "message", payload: { id: "m1", from, body: "a\u0000b" } },
    {
      type: "message",
      payload: { id: "m1", from, body: "a".repeat(maxBodySize + 1) },
    },
    { type: "message", payload: { id: "m1", from, body: "x" }, extra: 1 },
  ]) {
    assert.equal(parse(JSON.stringify(message)), null, JSON.stringify(message));
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
