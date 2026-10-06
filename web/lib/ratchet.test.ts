import assert from "node:assert/strict";
import {
  createCipheriv,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  hkdfSync,
} from "node:crypto";
import { test } from "node:test";
import { encodeBase64Url } from "./base64.ts";
import { IdentityKey } from "./identity.ts";
import {
  type Binding,
  type RatchetKeyPair,
  type RatchetState,
  associatedData,
  decodeHeader,
  encodeHeader,
  generateRatchetKey,
  headerSize,
  initiatorState,
  maxSkip,
  maxSkipped,
  ratchetDecrypt,
  ratchetEncrypt,
  responderState,
} from "./ratchet.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const pkcs8Prefix = Buffer.from("302e020100300506032b656e04220420", "hex");

function seed(n: number): Buffer {
  return Buffer.alloc(32, n);
}

function nodeKey(n: number) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([pkcs8Prefix, seed(n)]),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey);
  const raw = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  return { privateKey, publicKey, raw: new Uint8Array(raw) };
}

async function webKey(n: number): Promise<RatchetKeyPair> {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    Buffer.concat([pkcs8Prefix, seed(n)]),
    { name: "X25519" },
    false,
    ["deriveBits"],
  );
  return { publicKey: nodeKey(n).raw, privateKey };
}

function sequence(...seeds: number[]) {
  const queue = [...seeds];
  return async () => {
    const next = queue.shift();
    assert.ok(next !== undefined, "generator exhausted");
    return webKey(next);
  };
}

async function bindings() {
  const [initiator, responder] = await Promise.all([
    IdentityKey.generate(),
    IdentityKey.generate(),
  ]);
  const session = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const base = {
    initiator: initiator.identity,
    responder: responder.identity,
    session,
  };
  return {
    alice: { ...base, role: "initiator" } as Binding,
    bob: { ...base, role: "responder" } as Binding,
  };
}

async function pair() {
  const { alice, bob } = await bindings();
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const spk = await generateRatchetKey();
  const first = await generateRatchetKey();
  const a = await initiatorState(secret, spk.publicKey, alice, first);
  const b = await responderState(secret, spk, first.publicKey, bob);
  return { a, b };
}

async function send(state: RatchetState, text: string) {
  const out = await ratchetEncrypt(state, encoder.encode(text));
  assert.ok(out);
  return out;
}

async function receive(state: RatchetState, message: Uint8Array<ArrayBuffer>) {
  const out = await ratchetDecrypt(state, message);
  assert.ok(out, "decryption failed");
  return { state: out.state, text: decoder.decode(out.plaintext) };
}

function fingerprint(state: RatchetState): string {
  return JSON.stringify([
    encodeBase64Url(state.root),
    state.sending && [encodeBase64Url(state.sending.key), state.sending.n],
    state.receiving && [
      encodeBase64Url(state.receiving.key),
      state.receiving.n,
    ],
    state.previous,
    encodeBase64Url(state.own.publicKey),
    state.peer && encodeBase64Url(state.peer),
    state.skipped.map((k) => [k.ratchet, k.n, encodeBase64Url(k.key)]),
  ]);
}

const ref = {
  dh: (own: number, peer: number) =>
    diffieHellman({
      privateKey: nodeKey(own).privateKey,
      publicKey: nodeKey(peer).publicKey,
    }),
  root: (rk: Buffer, dh: Buffer) => {
    const out = Buffer.from(
      hkdfSync("sha256", dh, rk, "ghostx/ratchet/v1/root\0", 64),
    );
    return [out.subarray(0, 32), out.subarray(32)] as const;
  },
  chain: (ck: Buffer) =>
    [
      createHmac("sha256", ck).update(Buffer.of(2)).digest(),
      createHmac("sha256", ck).update(Buffer.of(1)).digest(),
    ] as const,
  seal: (mk: Buffer, plaintext: string, ad: Uint8Array) => {
    const okm = Buffer.from(
      hkdfSync(
        "sha256",
        mk,
        Buffer.alloc(32),
        "ghostx/ratchet/v1/message\0",
        44,
      ),
    );
    const cipher = createCipheriv(
      "aes-256-gcm",
      okm.subarray(0, 32),
      okm.subarray(32),
    );
    cipher.setAAD(ad);
    return Buffer.concat([
      cipher.update(plaintext, "utf8"),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
  },
};

test("matches an independent Double Ratchet reference implementation", async () => {
  const { alice, bob } = await bindings();
  const secret = Buffer.alloc(32, 9);
  const SPK = 1;
  const A1 = 2;
  const B1 = 3;
  const A2 = 4;
  const B2 = 5;
  let a = await initiatorState(
    new Uint8Array(secret),
    nodeKey(SPK).raw,
    alice,
    await webKey(A1),
  );
  let b = await responderState(
    new Uint8Array(secret),
    await webKey(SPK),
    nodeKey(A1).raw,
    bob,
    sequence(B1),
  );

  const [rkA, cksA] = ref.root(secret, ref.dh(A1, SPK));
  assert.equal(encodeBase64Url(a.root), encodeBase64Url(rkA));
  assert.equal(
    encodeBase64Url(a.sending?.key ?? new Uint8Array()),
    encodeBase64Url(cksA),
  );
  const [rkB1, ckrB] = ref.root(secret, ref.dh(SPK, A1));
  const [rkB2, cksB] = ref.root(rkB1, ref.dh(B1, A1));
  assert.equal(
    encodeBase64Url(b.receiving?.key ?? new Uint8Array()),
    encodeBase64Url(ckrB),
  );
  assert.equal(
    encodeBase64Url(b.sending?.key ?? new Uint8Array()),
    encodeBase64Url(cksB),
  );
  assert.equal(encodeBase64Url(b.root), encodeBase64Url(rkB2));
  assert.deepEqual(ckrB, cksA);

  const expect = (
    sender: Binding,
    ratchet: number,
    previous: number,
    n: number,
    mk: Buffer,
    text: string,
  ) => {
    const header = encodeHeader({
      session: sender.session,
      ratchet: nodeKey(ratchet).raw,
      previous,
      n,
    });
    assert.ok(header);
    const ad = associatedData(sender, sender.role, header);
    assert.ok(ad);
    return encodeBase64Url(
      new Uint8Array(Buffer.concat([header, ref.seal(mk, text, ad)])),
    );
  };

  const [ckA1, mkA0] = ref.chain(Buffer.from(cksA));
  const [, mkA1] = ref.chain(ckA1);
  const m0 = await send(a, "first");
  a = m0.state;
  const m1 = await send(a, "second");
  a = m1.state;
  assert.equal(
    encodeBase64Url(m0.message),
    expect(alice, A1, 0, 0, mkA0, "first"),
  );
  assert.equal(
    encodeBase64Url(m1.message),
    expect(alice, A1, 0, 1, mkA1, "second"),
  );

  const r1 = await receive(b, m1.message);
  b = r1.state;
  assert.equal(r1.text, "second");
  assert.equal(b.skipped.length, 1);
  assert.equal(encodeBase64Url(b.skipped[0].key), encodeBase64Url(mkA0));

  const [, mkB0] = ref.chain(Buffer.from(cksB));
  const reply = await send(b, "reply");
  b = reply.state;
  assert.equal(
    encodeBase64Url(reply.message),
    expect(bob, B1, 0, 0, mkB0, "reply"),
  );

  const back = await ratchetDecrypt(a, reply.message, sequence(A2));
  assert.ok(back);
  a = back.state;
  assert.equal(decoder.decode(back.plaintext), "reply");
  const [rkA2, ckrA] = ref.root(Buffer.from(rkA), ref.dh(A1, B1));
  const [rkA3, cksA2] = ref.root(rkA2, ref.dh(A2, B1));
  assert.deepEqual(ckrA, cksB);
  assert.equal(encodeBase64Url(a.root), encodeBase64Url(rkA3));
  assert.equal(a.previous, 2);

  const [, mkA2] = ref.chain(cksA2);
  const third = await send(a, "after ratchet");
  a = third.state;
  assert.equal(
    encodeBase64Url(third.message),
    expect(alice, A2, 2, 0, mkA2, "after ratchet"),
  );
  const late = await receive(b, m0.message);
  b = late.state;
  assert.equal(late.text, "first");
  const next = await ratchetDecrypt(b, third.message, sequence(B2));
  assert.ok(next);
  assert.equal(decoder.decode(next.plaintext), "after ratchet");
  const [rkB3, ckrB2] = ref.root(rkB2, ref.dh(B1, A2));
  const [rkB4] = ref.root(rkB3, ref.dh(B2, A2));
  assert.deepEqual(ckrB2, cksA2);
  assert.equal(encodeBase64Url(next.state.root), encodeBase64Url(rkB4));
});

test("every message advances the chain with a distinct key in both directions", async () => {
  let { a, b } = await pair();
  const headers = new Set<string>();
  const ciphertexts = new Set<string>();
  for (let round = 0; round < 6; round++) {
    for (let i = 0; i < 3; i++) {
      const out = await send(a, `a${round}.${i}`);
      assert.equal(out.state.sending?.n, (a.sending?.n ?? 0) + 1);
      a = out.state;
      headers.add(encodeBase64Url(out.message.slice(0, headerSize)));
      ciphertexts.add(encodeBase64Url(out.message.slice(headerSize)));
      const got = await receive(b, out.message);
      b = got.state;
      assert.equal(got.text, `a${round}.${i}`);
    }
    const before = encodeBase64Url(b.own.publicKey);
    const out = await send(b, `b${round}`);
    b = out.state;
    headers.add(encodeBase64Url(out.message.slice(0, headerSize)));
    ciphertexts.add(encodeBase64Url(out.message.slice(headerSize)));
    const got = await receive(a, out.message);
    a = got.state;
    assert.equal(got.text, `b${round}`);
    assert.equal(encodeBase64Url(b.own.publicKey), before);
  }
  assert.equal(headers.size, 24);
  assert.equal(ciphertexts.size, 24);
  const header = decodeHeader((await send(a, "x")).message);
  assert.ok(header && header.n === 0 && header.previous === 3);
});

test("handles out-of-order delivery with bounded skipped keys", async () => {
  let { a, b } = await pair();
  const messages: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < 5; i++) {
    const out = await send(a, `m${i}`);
    a = out.state;
    messages.push(out.message);
  }
  for (const i of [3, 1, 4, 0, 2]) {
    const got = await receive(b, messages[i]);
    b = got.state;
    assert.equal(got.text, `m${i}`);
  }
  assert.equal(b.skipped.length, 0);
  for (const message of messages) {
    assert.equal(await ratchetDecrypt(b, message), null);
  }

  for (let i = 0; i <= maxSkip + 1; i++) {
    a = (await send(a, "flood")).state;
  }
  const far = await send(a, "too far");
  const snapshot = fingerprint(b);
  assert.equal(await ratchetDecrypt(b, far.message), null);
  assert.equal(fingerprint(b), snapshot);

  const fresh = await pair();
  let left = fresh.a;
  let right = fresh.b;
  for (let round = 0; round < 3; round++) {
    for (let i = 0; i < maxSkip; i++) {
      left = (await send(left, "gap")).state;
    }
    const out = await send(left, "after gap");
    left = out.state;
    const got = await receive(right, out.message);
    right = got.state;
    const answer = await send(right, "ack");
    right = answer.state;
    left = (await receive(left, answer.message)).state;
  }
  assert.ok(right.skipped.length <= maxSkipped);
  assert.ok(right.skipped.length > 0);
});

test("replays and stale messages never move state", async () => {
  let { a, b } = await pair();
  const first = await send(a, "one");
  a = first.state;
  b = (await receive(b, first.message)).state;
  const reply = await send(b, "two");
  b = reply.state;
  a = (await receive(a, reply.message)).state;
  const third = await send(a, "three");
  a = third.state;
  b = (await receive(b, third.message)).state;

  const before = [fingerprint(a), fingerprint(b)];
  for (const message of [first.message, third.message]) {
    assert.equal(await ratchetDecrypt(b, message), null);
  }
  assert.equal(await ratchetDecrypt(a, reply.message), null);
  assert.equal(await ratchetDecrypt(b, reply.message), null);
  assert.equal(await ratchetDecrypt(a, third.message), null);
  assert.deepEqual([fingerprint(a), fingerprint(b)], before);
  const fresh = await send(a, "four");
  assert.equal((await receive(b, fresh.message)).text, "four");
});

test("authenticates every header field, the binding, and the direction", async () => {
  const { a, b } = await pair();
  const other = await pair();
  const out = await send(a, "bound");
  const message = out.message;
  const mutate = (index: number) => {
    const copy = message.slice();
    copy[index] ^= 1;
    return copy;
  };
  for (const [name, bad] of [
    ["version", mutate(0)],
    ["session", mutate(1)],
    ["ratchet key", mutate(20)],
    ["previous", mutate(52)],
    ["message number", mutate(56)],
    ["ciphertext", mutate(headerSize + 1)],
    ["tag", mutate(message.length - 1)],
    ["truncated", message.slice(0, headerSize + 10)],
  ] as const) {
    assert.equal(await ratchetDecrypt(b, bad), null, name);
  }
  const wrongBinding = (change: Partial<Binding>): RatchetState => ({
    ...b,
    binding: { ...b.binding, ...change },
  });
  const stranger = (await IdentityKey.generate()).identity;
  for (const [name, state] of [
    ["initiator identity", wrongBinding({ initiator: stranger })],
    ["responder identity", wrongBinding({ responder: stranger })],
    ["role", wrongBinding({ role: "initiator" })],
    [
      "relabelled session",
      wrongBinding({
        session: encodeBase64Url(crypto.getRandomValues(new Uint8Array(16))),
      }),
    ],
  ] as const) {
    assert.equal(await ratchetDecrypt(state, message), null, name);
  }
  assert.equal(await ratchetDecrypt(other.b, message), null);
  const forged = {
    ...other.b,
    binding: { ...other.b.binding, session: b.binding.session },
  };
  assert.equal(await ratchetDecrypt(forged, message), null);
  assert.equal(await ratchetDecrypt(a, message), null);
  assert.equal((await receive(b, message)).text, "bound");
});

test("post-compromise security: a stolen state stops working after a fresh DH ratchet", async () => {
  let { a, b } = await pair();
  const before: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < 3; i++) {
    const m = await send(a, `before ${i}`);
    a = m.state;
    before.push(m.message);
    b = (await receive(b, m.message)).state;
    const r = await send(b, `reply ${i}`);
    b = r.state;
    before.push(r.message);
    a = (await receive(a, r.message)).state;
  }

  const stolen: RatchetState = structuredClone(b);
  const compromisedKey = encodeBase64Url(stolen.own.publicKey);
  let attackerAsBob = stolen;
  const attackerAsAlice: RatchetState = {
    ...stolen,
    binding: { ...stolen.binding, role: "initiator" },
    receiving: stolen.sending,
    sending: null,
    peer: stolen.own.publicKey,
    own: await generateRatchetKey(),
    skipped: [],
  };
  const attacker = async (
    message: Uint8Array<ArrayBuffer>,
    fromBob: boolean,
  ) => {
    if (fromBob) {
      return ratchetDecrypt(attackerAsAlice, message);
    }
    const out = await ratchetDecrypt(attackerAsBob, message);
    if (out) {
      attackerAsBob = out.state;
    }
    return out;
  };

  for (const message of before) {
    assert.equal(await ratchetDecrypt(stolen, message), null);
  }

  const leaked: string[] = [];
  const protectedAfter: string[] = [];
  const exchange = async (from: "a" | "b", text: string) => {
    if (from === "a") {
      const m = await send(a, text);
      a = m.state;
      b = (await receive(b, m.message)).state;
      const seen = await attacker(m.message, false);
      (seen ? leaked : protectedAfter).push(text);
    } else {
      const m = await send(b, text);
      b = m.state;
      a = (await receive(a, m.message)).state;
      const seen = await attacker(m.message, true);
      (seen ? leaked : protectedAfter).push(text);
    }
  };

  await exchange("b", "bob still on the compromised chain");
  await exchange("a", "alice ratchets to a new key");
  assert.notEqual(encodeBase64Url(b.own.publicKey), compromisedKey);
  await exchange("b", "bob on a fresh ratchet key");
  await exchange("a", "alice again");
  for (let i = 0; i < 5; i++) {
    await exchange(i % 2 ? "a" : "b", `later ${i}`);
  }

  assert.deepEqual(leaked, [
    "bob still on the compromised chain",
    "alice ratchets to a new key",
  ]);
  assert.deepEqual(protectedAfter, [
    "bob on a fresh ratchet key",
    "alice again",
    ...Array.from({ length: 5 }, (_, i) => `later ${i}`),
  ]);
});

test("forward secrecy and key-compromise boundaries", async () => {
  let { a, b } = await pair();
  const chain: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < 4; i++) {
    const m = await send(a, `chain ${i}`);
    a = m.state;
    chain.push(m.message);
  }
  b = (await receive(b, chain[0])).state;
  b = (await receive(b, chain[1])).state;
  const afterTwo: RatchetState = structuredClone(b);
  b = (await receive(b, chain[2])).state;
  b = (await receive(b, chain[3])).state;

  assert.equal(await ratchetDecrypt(afterTwo, chain[0]), null);
  assert.equal(await ratchetDecrypt(afterTwo, chain[1]), null);
  assert.ok(await ratchetDecrypt(afterTwo, chain[2]));
  assert.ok(await ratchetDecrypt(afterTwo, chain[3]));
  assert.equal(await ratchetDecrypt(b, chain[3]), null);

  const reply = await send(b, "new chain");
  b = reply.state;
  a = (await receive(a, reply.message)).state;
  const next = await send(a, "next chain");
  const chainOnly: RatchetState = {
    ...afterTwo,
    root: crypto.getRandomValues(new Uint8Array(32)),
  };
  assert.equal(await ratchetDecrypt(chainOnly, next.message), null);
  const otherRatchetKey: RatchetState = {
    ...afterTwo,
    own: await generateRatchetKey(),
  };
  assert.equal(await ratchetDecrypt(otherRatchetKey, next.message), null);
});

test("fuzzed ratchet messages never decrypt, never move state, and stay bounded", async () => {
  let { a, b } = await pair();
  const valid: Uint8Array<ArrayBuffer>[] = [];
  for (let i = 0; i < 4; i++) {
    const m = await send(a, `fuzz ${i}`);
    a = m.state;
    valid.push(m.message);
  }
  const reply = await send(b, "reply");
  const pool = [...valid, reply.message];
  let seed = 0x1234567;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 800);
  const snapshot = fingerprint(b);
  for (let i = 0; i < iterations; i++) {
    const base = pool[random(pool.length)];
    let m: Uint8Array<ArrayBuffer> = base.slice();
    const choice = random(6);
    if (choice === 0) {
      m[random(m.length)] ^= 1 << random(8);
    } else if (choice === 1) {
      m = m.slice(0, random(m.length));
    } else if (choice === 2) {
      const extra = crypto.getRandomValues(new Uint8Array(1 + random(64)));
      m = new Uint8Array([...m, ...extra]);
    } else if (choice === 3) {
      const view = new DataView(m.buffer);
      view.setUint32(53, random(2) ? 2 ** 32 - 1 - random(10) : random(1000));
    } else if (choice === 4) {
      const view = new DataView(m.buffer);
      view.setUint32(49, random(2) ? 2 ** 32 - 1 : random(1000));
    } else {
      m.set(crypto.getRandomValues(new Uint8Array(32)), 17);
    }
    const out = await ratchetDecrypt(b, m);
    if (out) {
      assert.ok(valid.some((v) => encodeBase64Url(v) === encodeBase64Url(m)));
    }
    assert.equal(fingerprint(b), snapshot);
  }
  for (const message of valid) {
    const out = await ratchetDecrypt(b, message);
    assert.ok(out);
    b = out.state;
    assert.ok(b.skipped.length <= maxSkipped);
  }
  for (const message of valid) {
    assert.equal(await ratchetDecrypt(b, message), null);
  }
});
