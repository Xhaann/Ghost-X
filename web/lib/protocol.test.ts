import assert from "node:assert/strict";
import { test } from "node:test";
import { createId, encode, parse } from "./protocol.ts";

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

test("parses challenge and proven messages", () => {
  const nonce = "A".repeat(43);
  const identity = "B".repeat(42) + "A";
  assert.deepEqual(
    parse(JSON.stringify({ type: "challenge", id: "c1", payload: { nonce } })),
    { type: "challenge", id: "c1", payload: { nonce } },
  );
  assert.deepEqual(
    parse(JSON.stringify({ type: "proven", id: "p1", payload: { identity } })),
    { type: "proven", id: "p1", payload: { identity } },
  );
  assert.deepEqual(
    parse('{"type":"error","id":"p1","payload":{"code":"invalid_proof"}}'),
    { type: "error", id: "p1", payload: { code: "invalid_proof" } },
  );
});

test("rejects malformed challenge and proven messages", () => {
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
    { type: "proven", payload: { identity } },
    { type: "proven", id: "p1", payload: {} },
    { type: "proven", id: "p1", payload: { identity: identity + "A" } },
    { type: "proven", id: "p1", payload: { identity: "B".repeat(43) } },
    { type: "proven", id: "p1", payload: { identity: null } },
    { type: "proven", id: "p1", payload: { identity, extra: 1 } },
  ];
  for (const message of invalid) {
    assert.equal(parse(JSON.stringify(message)), null, JSON.stringify(message));
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
