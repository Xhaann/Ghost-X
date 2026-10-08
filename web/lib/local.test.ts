import assert from "node:assert/strict";
import { test } from "node:test";
import {
  type Link,
  type LinkConnection,
  type LinkHandlers,
  LocalTransport,
} from "./local.ts";
import { maxFrameSize } from "./transport.ts";
import type { TransportError, TransportState } from "./transport.ts";

type Attempt = {
  handlers: LinkHandlers;
  resolve(connection: LinkConnection): void;
  reject(error: Error): void;
};

type Wire = LinkConnection & { sent: string[]; closed: number };

function controlled() {
  const attempts: Attempt[] = [];
  const link: Link = {
    connect: (handlers) =>
      new Promise((resolve, reject) => {
        attempts.push({ handlers, resolve, reject });
      }),
  };
  return { link, attempts };
}

function wire(accept = true): Wire {
  const w: Wire = {
    sent: [],
    closed: 0,
    send(frame) {
      if (!accept) {
        return false;
      }
      w.sent.push(frame);
      return true;
    },
    close() {
      w.closed += 1;
    },
  };
  return w;
}

function observe(t: LocalTransport) {
  const states: TransportState[] = [];
  const errors: TransportError[] = [];
  const frames: string[] = [];
  t.onState((s) => states.push(s));
  t.onError((e) => errors.push(e));
  t.onData((f) => frames.push(f));
  return { states, errors, frames };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

async function connected() {
  const { link, attempts } = controlled();
  const transport = new LocalTransport(link);
  const seen = observe(transport);
  transport.open();
  const w = wire();
  attempts[0].resolve(w);
  await tick();
  assert.equal(transport.state, "connected");
  return { transport, attempts, w, seen };
}

test("without a platform link the local transport is unavailable and never falls back", async () => {
  const transport = new LocalTransport(null, { timeout: 5 });
  const seen = observe(transport);
  transport.open();
  transport.open();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(transport.kind, "local");
  assert.equal(transport.state, "error");
  assert.deepEqual(seen.states, ["error"]);
  assert.deepEqual(seen.errors, ["unavailable", "unavailable"]);
  assert.equal(transport.send("{}"), "not_connected");
});

test("connects once, sends, receives, and closes deterministically", async () => {
  const { link, attempts } = controlled();
  const transport = new LocalTransport(link);
  const seen = observe(transport);
  assert.equal(transport.send("early"), "not_connected");
  transport.open();
  transport.open();
  assert.equal(attempts.length, 1);
  assert.equal(transport.send("connecting"), "not_connected");
  const w = wire();
  attempts[0].resolve(w);
  await tick();
  assert.equal(transport.send('{"type":"ping"}'), "sent");
  attempts[0].handlers.frame('{"type":"pong"}');
  transport.open();
  assert.equal(attempts.length, 1);
  transport.close();
  transport.close();
  assert.equal(w.closed, 1);
  assert.equal(transport.send("late"), "not_connected");
  attempts[0].handlers.frame('{"type":"late"}');
  attempts[0].handlers.closed();
  assert.deepEqual(w.sent, ['{"type":"ping"}']);
  assert.deepEqual(seen.frames, ['{"type":"pong"}']);
  assert.deepEqual(seen.states, ["connecting", "connected", "disconnected"]);
  assert.deepEqual(seen.errors, []);
});

test("connection failures, timeouts, and losses are reported and never retried", async () => {
  const { link, attempts } = controlled();
  const transport = new LocalTransport(link, { timeout: 30 });
  const seen = observe(transport);
  transport.open();
  attempts[0].reject(new Error("refused"));
  await tick();
  assert.equal(transport.state, "error");
  transport.open();
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal(transport.state, "error");
  const late = wire();
  attempts[1].resolve(late);
  await tick();
  assert.equal(
    late.closed,
    1,
    "a connection completing after its timeout is closed",
  );
  assert.equal(transport.state, "error");
  transport.open();
  const w = wire();
  attempts[2].resolve(w);
  await tick();
  attempts[2].handlers.closed();
  assert.equal(transport.state, "error");
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal(attempts.length, 3, "no automatic reconnection");
  assert.deepEqual(seen.errors, ["failed", "timeout", "lost"]);
  assert.equal(w.closed, 1);
});

test("frames are bounded in both directions and backpressure is explicit", async () => {
  const { transport, attempts, seen } = await connected();
  assert.equal(transport.send(""), "oversized");
  assert.equal(transport.send("x".repeat(maxFrameSize + 1)), "oversized");
  assert.equal(transport.send("é".repeat(maxFrameSize / 2 + 1)), "oversized");
  assert.equal(transport.send("x".repeat(maxFrameSize)), "sent");
  attempts[0].handlers.frame("x".repeat(maxFrameSize + 1));
  attempts[0].handlers.frame("");
  attempts[0].handlers.frame(42 as unknown as string);
  attempts[0].handlers.frame("ok");
  assert.deepEqual(seen.frames, ["ok"]);
  assert.deepEqual(seen.errors, ["oversized", "malformed", "malformed"]);

  const busy = controlled();
  const blocked = new LocalTransport(busy.link);
  blocked.open();
  busy.attempts[0].resolve(wire(false));
  await tick();
  assert.equal(blocked.send("{}"), "busy");
  const throwing = controlled();
  const broken = new LocalTransport(throwing.link);
  broken.open();
  throwing.attempts[0].resolve({
    send() {
      throw new Error("link failure");
    },
    close() {},
  });
  await tick();
  assert.equal(broken.send("{}"), "failed");
});

test("listeners detach and stale connections can never deliver", async () => {
  const { transport, attempts } = await connected();
  const frames: string[] = [];
  const release = transport.onData((f) => frames.push(f));
  attempts[0].handlers.frame("one");
  release();
  attempts[0].handlers.frame("two");
  transport.close();
  transport.open();
  const fresh = wire();
  attempts[1].resolve(fresh);
  await tick();
  const after: string[] = [];
  transport.onData((f) => after.push(f));
  attempts[0].handlers.frame("stale");
  attempts[0].handlers.closed();
  attempts[1].handlers.frame("current");
  assert.deepEqual(frames, ["one"]);
  assert.deepEqual(after, ["current"]);
  assert.equal(transport.state, "connected");
});

test("rapid open and close cycles leave exactly one live connection and no timers", async () => {
  const { link, attempts } = controlled();
  const transport = new LocalTransport(link, { timeout: 20 });
  const wires: Wire[] = [];
  for (let i = 0; i < 50; i++) {
    transport.open();
    if (i % 2 === 0) {
      transport.close();
    }
  }
  for (const attempt of attempts) {
    const w = wire();
    wires.push(w);
    attempt.resolve(w);
  }
  await tick();
  const live = wires.filter((w) => w.closed === 0);
  assert.equal(live.length, transport.state === "connected" ? 1 : 0);
  transport.close();
  assert.ok(wires.every((w) => w.closed === 1));
  const states: TransportState[] = [];
  transport.onState((s) => states.push(s));
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(states, [], "no timer outlives close");
  assert.equal(transport.state, "disconnected");
});

test("a link that throws synchronously is a failed connection", async () => {
  const transport = new LocalTransport({
    connect() {
      throw new Error("no radio");
    },
  });
  const seen = observe(transport);
  transport.open();
  await tick();
  assert.equal(transport.state, "error");
  assert.deepEqual(seen.errors, ["failed"]);
});

test("fuzzed lifecycles and frames keep every transport invariant", async () => {
  let seed = 0x1ca1;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const samples: unknown[] = [
    "",
    "{}",
    '{"type":"pong"}',
    "x".repeat(maxFrameSize),
    "x".repeat(maxFrameSize + 1),
    "é".repeat(maxFrameSize / 2),
    "é".repeat(maxFrameSize / 2 + 1),
    null,
    7,
    {},
  ];
  const rounds = Number(process.env.FUZZ_ITERATIONS ?? 300);
  for (let round = 0; round < rounds; round++) {
    const { link, attempts } = controlled();
    const transport = new LocalTransport(link, { timeout: 1 + random(5) });
    const wires: Wire[] = [];
    const frames: string[] = [];
    const settled = new Set<Attempt>();
    let deliveredWhileDown = false;
    transport.onData((f) => {
      frames.push(f);
      if (transport.state !== "connected") {
        deliveredWhileDown = true;
      }
    });
    for (let step = 0; step < 40; step++) {
      const attempt = attempts[random(attempts.length + 1)];
      switch (random(7)) {
        case 0:
          transport.open();
          break;
        case 1:
          transport.close();
          break;
        case 2:
          if (attempt && !settled.has(attempt)) {
            settled.add(attempt);
            const w = wire(random(4) !== 0);
            wires.push(w);
            attempt.resolve(w);
          }
          break;
        case 3:
          if (attempt && !settled.has(attempt)) {
            settled.add(attempt);
            attempt.reject(new Error("refused"));
          }
          break;
        case 4:
          attempt?.handlers.frame(samples[random(samples.length)] as string);
          break;
        case 5:
          attempt?.handlers.closed();
          break;
        default: {
          const strings = samples.filter((x) => typeof x === "string");
          const frame = strings[random(strings.length)] as string;
          const result = transport.send(frame);
          if (result === "sent") {
            assert.equal(transport.state, "connected");
            assert.ok(typeof frame === "string" && frame.length > 0);
          }
        }
      }
      await Promise.resolve();
      await Promise.resolve();
      const live = wires.filter((w) => w.closed === 0);
      assert.ok(live.length <= 1, "at most one live connection");
      assert.ok(wires.every((w) => w.closed <= 1));
    }
    transport.close();
    await new Promise((resolve) => setTimeout(resolve, 8));
    assert.ok(
      wires.every((w) => w.closed === 1),
      "every connection released",
    );
    assert.equal(transport.state, "disconnected");
    assert.equal(deliveredWhileDown, false);
    for (const f of frames) {
      assert.ok(
        f.length > 0 && new TextEncoder().encode(f).length <= maxFrameSize,
      );
    }
  }
});
