import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { initiate, respond, verifyPrekey } from "./handshake.ts";
import { Pairs, pairAddress, parsePair, pairsVersion } from "./pairs.ts";
import { PrekeyStore } from "./prekeys.ts";
import {
  type RatchetState,
  initiatorState,
  ratchetDecrypt,
  ratchetEncrypt,
  responderState,
} from "./ratchet.ts";
import { type MemoryStore, memoryStore } from "./testing.ts";
import { type Keys, type Unlocked, createVault, loadVault } from "./vault.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function local(store: MemoryStore = memoryStore()) {
  const loaded = await loadVault(store);
  const vault = (
    loaded.status === "empty" ? await createVault(store) : loaded
  ) as Unlocked;
  const pairs = await Pairs.open(
    store,
    vault.integrity,
    vault.storage,
    vault.keys.identity,
  );
  return { store, ...vault, pairs };
}

function address(keys: Keys): string {
  return pairAddress(keys.identity, keys.deviceId);
}

function deviceOf(keys: Keys) {
  return {
    id: keys.deviceId,
    signing: keys.device.identity,
    exchange: keys.exchange.publicKey,
  };
}

async function handshake() {
  const alice = await local();
  const bob = await local();
  const prekeys = await PrekeyStore.open(bob.store, bob.keys, bob.integrity);
  assert.ok(prekeys);
  const publication = await prekeys.publication();
  assert.ok(publication);
  const signed = await verifyPrekey(
    "signed",
    bob.keys.identity,
    deviceOf(bob.keys),
    publication.signed,
  );
  assert.ok(signed);
  const started = await initiate(alice.keys, {
    identity: bob.keys.identity,
    device: deviceOf(bob.keys),
    signed: { id: publication.signed.id, key: signed },
    onetime: null,
  });
  assert.ok(started);
  const aliceState = await initiatorState(
    started.pending.secret,
    signed,
    {
      initiator: alice.keys.identity,
      responder: bob.keys.identity,
      session: started.pending.id,
      role: "initiator",
    },
    started.pending.ratchet,
  );
  const outcome = await prekeys.consume(
    publication.signed.id,
    null,
    async (keys) => {
      const est = await respond(bob.keys, keys, {
        from: alice.keys.identity,
        fromDevice: deviceOf(alice.keys),
        ...started.initiation,
      });
      if (!est) {
        return null;
      }
      const ratchet = await responderState(
        est.secret,
        { publicKey: keys.signed.key, privateKey: keys.signed.privateKey },
        decodeBase64Url(started.initiation.ratchet, 32) ?? new Uint8Array(),
        {
          initiator: alice.keys.identity,
          responder: bob.keys.identity,
          session: est.id,
          role: "responder",
        },
      );
      return { id: est.id, accept: est.accept, ratchet };
    },
  );
  assert.equal(outcome.status, "consumed");
  if (outcome.status !== "consumed") {
    throw new Error("handshake failed");
  }
  return {
    alice,
    bob,
    started,
    aliceState,
    bobState: outcome.value.ratchet,
    accept: outcome.value.accept,
  };
}

function flip(text: string): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[0] ^= 1;
  return encodeBase64Url(bytes);
}

const sendText = (pairs: Pairs, peer: string, text: string) =>
  pairs.transact(peer, async (state) => {
    const out = await ratchetEncrypt(state, encoder.encode(text));
    return out && { state: out.state, value: out.message };
  });

const readText = (
  pairs: Pairs,
  peer: string,
  message: Uint8Array<ArrayBuffer>,
) =>
  pairs.transact(peer, async (state) => {
    const out = await ratchetDecrypt(state, message);
    return out && { state: out.state, value: decoder.decode(out.plaintext) };
  });

async function established() {
  const h = await handshake();
  const idA = address(h.alice.keys);
  const idB = address(h.bob.keys);
  assert.equal(
    await h.alice.pairs.savePending(
      idB,
      h.started.initiation.ephemeral,
      h.started.pending,
      h.aliceState,
    ),
    true,
  );
  assert.equal(
    await h.bob.pairs.saveResponder(
      idA,
      h.started.initiation.ephemeral,
      h.bobState,
    ),
    true,
  );
  assert.equal(
    await h.alice.pairs.accept(idB, h.started.initiation.ephemeral, h.accept),
    true,
  );
  return { ...h, idA, idB };
}

test("pending sessions only become established with a valid acceptance", async () => {
  const h = await handshake();
  const idB = address(h.bob.keys);
  const { pairs } = h.alice;
  assert.equal(pairs.state(idB), "none");
  assert.equal(
    await pairs.savePending(
      idB,
      h.started.initiation.ephemeral,
      h.started.pending,
      h.aliceState,
    ),
    true,
  );
  assert.equal(pairs.state(idB), "pending");
  assert.equal(await sendText(pairs, idB, "too early"), null);
  assert.equal(
    await pairs.accept(idB, flip(h.started.initiation.ephemeral), h.accept),
    false,
  );
  assert.equal(
    await pairs.accept(idB, h.started.initiation.ephemeral, flip(h.accept)),
    false,
  );
  assert.equal(pairs.state(idB), "pending");
  assert.equal(
    await pairs.accept(idB, h.started.initiation.ephemeral, h.accept),
    true,
  );
  assert.equal(pairs.state(idB), "established");
  const stored = h.alice.store.data.get(`pairs:${idB}`) as Record<
    string,
    unknown
  >;
  assert.equal(stored.transcript, null);
  assert.equal(stored.responder, null);
});

test("ratchet state persists encrypted and continues after reload", async () => {
  const h = await established();
  const m1 = await sendText(h.alice.pairs, h.idB, "hello bob");
  assert.ok(m1);
  assert.equal(await readText(h.bob.pairs, h.idA, m1), "hello bob");
  const reply = await sendText(h.bob.pairs, h.idA, "hello alice");
  assert.ok(reply);

  const reloaded = await local(h.alice.store);
  assert.equal(reloaded.pairs.state(h.idB), "established");
  assert.equal(await readText(reloaded.pairs, h.idB, reply), "hello alice");
  assert.equal(await readText(reloaded.pairs, h.idB, reply), null);
  const m2 = await sendText(reloaded.pairs, h.idB, "after reload");
  assert.ok(m2);
  const bobReloaded = await local(h.bob.store);
  assert.equal(await readText(bobReloaded.pairs, h.idA, m2), "after reload");
  assert.equal(await readText(bobReloaded.pairs, h.idA, m1), null);

  for (const store of [h.alice.store, h.bob.store]) {
    const record = [...store.data.entries()].find(([k]) =>
      k.startsWith("pairs:"),
    )?.[1] as Record<string, unknown>;
    assert.equal(record.v, pairsVersion);
    assert.equal((record.own as CryptoKey).extractable, false);
    assert.deepEqual(Object.keys(record.ratchet as object).sort(), [
      "ciphertext",
      "iv",
    ]);
    const text = JSON.stringify(record);
    assert.ok(!/root|chain|sending|receiving|skipped|hello|reload/.test(text));
  }
});

test("a stale tab cannot roll the ratchet back", async () => {
  const h = await established();
  const tab = await local(h.alice.store);
  const first = await sendText(h.alice.pairs, h.idB, "from tab one");
  const second = await sendText(tab.pairs, h.idB, "from tab two");
  assert.ok(first && second);
  assert.notEqual(
    encodeBase64Url(first.slice(0, 57)),
    encodeBase64Url(second.slice(0, 57)),
  );
  assert.equal(await readText(h.bob.pairs, h.idA, first), "from tab one");
  assert.equal(await readText(h.bob.pairs, h.idA, second), "from tab two");
});

test("corrupted, swapped, or outdated records fail closed", async () => {
  const h = await established();
  const other = await established();
  const key = `pairs:${h.idB}`;
  const original = h.alice.store.data.get(key) as Record<string, unknown>;
  const foreign = other.alice.store.data.get(`pairs:${other.idB}`) as Record<
    string,
    unknown
  >;
  const blob = original.ratchet as Record<string, string>;
  const cases: Record<string, unknown> = {
    "mac flipped": { ...original, mac: flip(original.mac as string) },
    "state demoted": { ...original, state: "pending" },
    "role swapped": { ...original, role: "responder" },
    "session changed": { ...original, id: encodeBase64Url(new Uint8Array(16)) },
    "ciphertext flipped": {
      ...original,
      ratchet: { ...blob, ciphertext: flip(blob.ciphertext) },
    },
    "blob from another session": { ...original, ratchet: foreign.ratchet },
    "private key from another session": { ...original, own: foreign.own },
    "task fifteen record": {
      v: 1,
      peer: h.idB,
      id: original.id,
      role: "initiator",
      state: "established",
      ephemeral: original.ephemeral,
      transcript: null,
      stamp: 1,
      root: original.own,
      responder: null,
      mac: original.mac,
    },
    "extra field": { ...original, plaintext: "x" },
    string: "pairs",
  };
  for (const [name, value] of Object.entries(cases)) {
    h.alice.store.data.set(key, value);
    const check = await local(h.alice.store);
    assert.equal(check.pairs.state(h.idB), "none", name);
    assert.ok(check.pairs.rejected >= 1, name);
    assert.equal(await sendText(check.pairs, h.idB, "x"), null, name);
  }
  h.alice.store.data.set(key, original);
  assert.ok(parsePair(h.idB, original));
  const restored = await local(h.alice.store);
  assert.equal(restored.pairs.state(h.idB), "established");
});

test("failed decryptions never persist state", async () => {
  const h = await established();
  const m = await sendText(h.alice.pairs, h.idB, "valid");
  assert.ok(m);
  const writes = h.bob.store.writes;
  const tampered = m.slice();
  tampered[tampered.length - 1] ^= 1;
  assert.equal(await readText(h.bob.pairs, h.idA, tampered), null);
  assert.equal(h.bob.store.writes, writes);
  assert.equal(await readText(h.bob.pairs, h.idA, m), "valid");
  assert.equal(h.bob.store.writes, writes + 1);
  const state = await h.bob.pairs.transact<RatchetState>(h.idA, async (s) => ({
    state: s,
    value: s,
  }));
  assert.equal(state?.receiving?.n, 1);
});

test("fuzzed persisted pair records never restore as usable sessions", async () => {
  const h = await established();
  const key = `pairs:${h.idB}`;
  const original = h.alice.store.data.get(key) as Record<string, unknown>;
  const names = Object.keys(original);
  const values: unknown[] = [
    null,
    0,
    1,
    -1,
    "",
    "x",
    true,
    [],
    {},
    "AAAAAAAAAAAAAAAAAAAAAA",
    original.own,
  ];
  let seed = 0x7a11;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 300);
  for (let i = 0; i < iterations; i++) {
    const mutated: Record<string, unknown> = { ...original };
    const name = names[random(names.length)];
    const choice = random(4);
    if (choice === 0) {
      delete mutated[name];
    } else if (choice === 1) {
      mutated[name] = values[random(values.length)];
    } else if (choice === 2 && typeof mutated[name] === "string") {
      const text = mutated[name] as string;
      const at = random(Math.max(1, text.length));
      mutated[name] =
        text.slice(0, at) + (text[at] === "A" ? "B" : "A") + text.slice(at + 1);
    } else {
      const blob = original.ratchet as Record<string, string>;
      mutated.ratchet = {
        ...blob,
        [random(2) ? "iv" : "ciphertext"]: flip(
          blob[random(2) ? "iv" : "ciphertext"],
        ),
      };
    }
    h.alice.store.data.set(key, mutated);
    const check = await local(h.alice.store);
    if (check.pairs.state(h.idB) !== "none") {
      assert.deepEqual(mutated, original);
    }
  }
});

test("stored records never contain the live root, chain, or message keys", async () => {
  const h = await established();
  for (let i = 0; i < 3; i++) {
    const m = await sendText(h.alice.pairs, h.idB, `probe ${i}`);
    assert.ok(m);
    await readText(h.bob.pairs, h.idA, m);
  }
  const reply = await sendText(h.bob.pairs, h.idA, "reply");
  assert.ok(reply);
  for (const [pairs, peer, store] of [
    [h.alice.pairs, h.idB, h.alice.store],
    [h.bob.pairs, h.idA, h.bob.store],
  ] as const) {
    const secrets = await pairs.transact(peer, async (state) => ({
      state,
      value: [
        state.root,
        state.sending?.key,
        state.receiving?.key,
        ...state.skipped.map((k) => k.key),
      ].filter((k): k is Uint8Array<ArrayBuffer> => !!k),
    }));
    assert.ok(secrets && secrets.length >= 2);
    const record = store.data.get(`pairs:${peer}`) as Record<string, unknown>;
    const blob = record.ratchet as Record<string, string>;
    const raw = decodeBase64Url(
      blob.ciphertext,
      Math.floor((blob.ciphertext.length * 3) / 4),
    );
    assert.ok(raw);
    assert.throws(() => JSON.parse(new TextDecoder().decode(raw)));
    const text = JSON.stringify(record);
    for (const secret of secrets) {
      assert.ok(!text.includes(encodeBase64Url(secret)));
      const hex = Buffer.from(secret).toString("hex");
      assert.ok(!Buffer.from(raw).toString("hex").includes(hex));
    }
  }
});

test("a full skipped-key state still persists, and a failed write releases nothing", async () => {
  const h = await established();
  const burst = async (count: number) => {
    const messages = await h.alice.pairs.transact(h.idB, async (state) => {
      let s = state;
      const out: Uint8Array<ArrayBuffer>[] = [];
      for (let i = 0; i < count; i++) {
        const sealed = await ratchetEncrypt(s, encoder.encode(`gap ${i}`));
        assert.ok(sealed);
        s = sealed.state;
        out.push(sealed.message);
      }
      return { state: s, value: out };
    });
    assert.ok(messages);
    return messages;
  };
  const first = await burst(100);
  assert.equal(await readText(h.bob.pairs, h.idA, first[99]), "gap 99");
  const reply = await sendText(h.bob.pairs, h.idA, "turn");
  assert.ok(reply);
  assert.equal(await readText(h.alice.pairs, h.idB, reply), "turn");
  const second = await burst(100);
  assert.equal(await readText(h.bob.pairs, h.idA, second[99]), "gap 99");
  const skipped = await h.bob.pairs.transact<number>(h.idA, async (s) => ({
    state: s,
    value: s.skipped.length,
  }));
  assert.equal(skipped, 198);
  const reopened = await local(h.bob.store);
  assert.equal(reopened.pairs.state(h.idA), "established");
  assert.equal(await readText(reopened.pairs, h.idA, first[5]), "gap 5");
  assert.equal(await readText(reopened.pairs, h.idA, second[7]), "gap 7");

  const failing = {
    ...h.alice.store,
    put: async () => {
      throw new Error("disk full");
    },
  };
  const broken = await Pairs.open(
    failing,
    h.alice.integrity,
    h.alice.storage,
    h.idA,
  );
  assert.equal(await sendText(broken, h.idB, "must not leave"), null);
});

test("a session record never loads under another device's address", async () => {
  const h = await established();
  const sibling = (await createVault(memoryStore())) as Unlocked;
  const record = h.alice.store.data.get(`pairs:${h.idB}`) as Record<
    string,
    unknown
  >;
  const elsewhere = pairAddress(h.bob.keys.identity, sibling.keys.deviceId);
  h.alice.store.data.set(`pairs:${elsewhere}`, record);
  assert.equal(parsePair(elsewhere, record), null);
  h.alice.store.data.set(`pairs:${elsewhere}`, {
    ...record,
    device: sibling.keys.deviceId,
  });
  const reopened = await local(h.alice.store);
  assert.equal(reopened.pairs.state(elsewhere), "none");
  assert.equal(reopened.pairs.state(h.idB), "established");
  assert.equal(reopened.pairs.rejected, 1);
});

test("single-device session records from the previous version are discarded", async () => {
  const h = await established();
  const record = h.alice.store.data.get(`pairs:${h.idB}`) as Record<
    string,
    unknown
  >;
  const { device: _device, ...previous } = record;
  h.alice.store.data.set(`pairs:${h.bob.keys.identity}`, { ...previous, v: 2 });
  const reopened = await local(h.alice.store);
  assert.equal(reopened.pairs.rejected, 0);
  assert.equal(h.alice.store.data.has(`pairs:${h.bob.keys.identity}`), false);
  assert.equal(reopened.pairs.state(h.idB), "established");
  assert.equal(record.v, pairsVersion);
});

test("removing a device's session deletes it durably and only for that device", async () => {
  const h = await established();
  const other = pairAddress(
    h.bob.keys.identity,
    ((await createVault(memoryStore())) as Unlocked).keys.deviceId,
  );
  assert.deepEqual(h.alice.pairs.devices(h.bob.keys.identity), [
    h.bob.keys.deviceId,
  ]);
  const changes: string[] = [];
  h.alice.pairs.onChange((address) => changes.push(address));
  assert.equal(await h.alice.pairs.remove(other), false);
  assert.equal(await h.alice.pairs.remove(h.idB), true);
  assert.equal(await h.alice.pairs.remove(h.idB), false);
  assert.deepEqual(changes, [h.idB]);
  assert.equal(h.alice.pairs.state(h.idB), "none");
  assert.deepEqual(h.alice.pairs.devices(h.bob.keys.identity), []);
  assert.equal(h.alice.store.data.has(`pairs:${h.idB}`), false);
  const reopened = await local(h.alice.store);
  assert.equal(reopened.pairs.state(h.idB), "none");
  assert.equal(h.bob.pairs.state(h.idA), "established");
});
