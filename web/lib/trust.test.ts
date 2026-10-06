import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { ExchangeKey, type KeyBundle } from "./encryption.ts";
import { fingerprint } from "./fingerprint.ts";
import { IdentityKey } from "./identity.ts";
import { memoryStore } from "./testing.ts";
import { Trust, parseTrustRecord, trustVersion } from "./trust.ts";
import { type Unlocked, loadVault } from "./vault.ts";

type Store = ReturnType<typeof memoryStore>;

async function local(): Promise<{ store: Store; integrity: CryptoKey }> {
  const store = memoryStore();
  const state = await loadVault(store);
  assert.equal(state.status, "ready");
  return { store, integrity: (state as Unlocked).integrity };
}

async function peer(identity?: IdentityKey) {
  const id = identity ?? (await IdentityKey.generate());
  const exchange = await ExchangeKey.generate();
  const bundle = await exchange.bind(id);
  assert.ok(bundle);
  const print = await fingerprint(bundle.identity, bundle.key);
  assert.ok(print);
  return { id, exchange, bundle, print };
}

function flip(text: string, index = 0): string {
  const raw = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(raw);
  raw[index] ^= 1;
  return encodeBase64Url(raw);
}

function stored(store: Store, identity: string) {
  return store.data.get(`trust:${identity}`) as
    Record<string, unknown> | undefined;
}

test("a new identity is never trusted automatically", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();

  assert.equal(trust.view(b.id.identity).state, "unavailable");
  assert.equal(trust.view(b.id.identity).current, null);
  await trust.observe(b.bundle);
  await trust.observe(b.bundle);
  assert.deepEqual(trust.view(b.id.identity), {
    identity: b.id.identity,
    state: "unverified",
    current: b.print,
    verified: null,
  });
  await trust.flush();
  assert.equal(store.data.size, 1);
});

test("explicit verification binds to the exact fingerprint and persists", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  const c = await peer();
  await trust.observe(b.bundle);

  for (const wrong of [
    c.print.value,
    b.print.digits,
    flip(b.print.value),
    flip(b.print.value, 63),
    "",
    b.id.identity,
  ]) {
    assert.equal(await trust.verify(b.id.identity, wrong), false);
  }
  assert.equal(await trust.verify(c.id.identity, c.print.value), false);
  assert.equal(trust.view(b.id.identity).state, "unverified");
  assert.equal(stored(store, b.id.identity), undefined);

  assert.equal(await trust.verify(b.id.identity, b.print.value), true);
  assert.equal(trust.view(b.id.identity).state, "verified");
  assert.deepEqual(trust.view(b.id.identity).verified, b.print);
  const record = stored(store, b.id.identity);
  assert.deepEqual(Object.keys(record ?? {}).sort(), [
    "fingerprint",
    "identity",
    "key",
    "mac",
    "status",
    "v",
  ]);
  assert.equal(record?.fingerprint, b.print.value);
  assert.equal(record?.key, b.bundle.key);
  assert.equal(record?.status, "verified");

  const reloaded = await Trust.open(store, integrity);
  assert.equal(reloaded.rejected, 0);
  assert.equal(reloaded.view(b.id.identity).state, "unavailable");
  await reloaded.observe(b.bundle);
  assert.equal(reloaded.view(b.id.identity).state, "verified");
  assert.equal(reloaded.view(c.id.identity).state, "unavailable");
});

test("a key change invalidates verification until the new key is verified", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  const rotated = await peer(b.id);
  await trust.observe(b.bundle);
  assert.equal(await trust.verify(b.id.identity, b.print.value), true);

  await trust.observe(rotated.bundle);
  assert.equal(trust.view(b.id.identity).state, "changed");
  assert.deepEqual(trust.view(b.id.identity).current, rotated.print);
  assert.deepEqual(trust.view(b.id.identity).verified, b.print);
  await trust.flush();
  assert.equal(stored(store, b.id.identity)?.status, "changed");
  assert.equal(stored(store, b.id.identity)?.fingerprint, b.print.value);

  await trust.observe(b.bundle);
  assert.equal(trust.view(b.id.identity).state, "changed");
  const reloaded = await Trust.open(store, integrity);
  assert.equal(reloaded.view(b.id.identity).state, "changed");
  await reloaded.observe(b.bundle);
  assert.equal(reloaded.view(b.id.identity).state, "changed");

  await reloaded.observe(rotated.bundle);
  assert.equal(await reloaded.verify(b.id.identity, b.print.value), false);
  assert.equal(reloaded.view(b.id.identity).state, "changed");
  assert.equal(await reloaded.verify(b.id.identity, rotated.print.value), true);
  assert.equal(reloaded.view(b.id.identity).state, "verified");
  assert.equal(stored(store, b.id.identity)?.fingerprint, rotated.print.value);
  await reloaded.observe(b.bundle);
  assert.equal(reloaded.view(b.id.identity).state, "changed");
});

test("forged or substituted key bundles are ignored", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  const c = await peer();
  await trust.observe(b.bundle);
  assert.equal(await trust.verify(b.id.identity, b.print.value), true);

  const forged: KeyBundle[] = [
    { ...b.bundle, key: c.bundle.key },
    { ...b.bundle, signature: c.bundle.signature },
    { ...c.bundle, identity: b.id.identity },
    { ...b.bundle, signature: flip(b.bundle.signature) },
    { ...b.bundle, key: flip(b.bundle.key) },
  ];
  for (const bundle of forged) {
    await trust.observe(bundle);
    assert.equal(trust.view(b.id.identity).state, "verified");
  }
  await trust.flush();
  assert.equal(stored(store, b.id.identity)?.status, "verified");
});

test("the latest observation wins regardless of completion order", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const holders = await Promise.all(Array.from({ length: 30 }, () => peer()));
  const rotations = await Promise.all(holders.map((h) => peer(h.id)));
  for (let round = 0; round < 20; round++) {
    await Promise.all(
      holders.flatMap((h, i) =>
        round % 2 === 0
          ? [trust.observe(h.bundle), trust.observe(rotations[i].bundle)]
          : [trust.observe(rotations[i].bundle), trust.observe(h.bundle)],
      ),
    );
    holders.forEach((h, i) =>
      assert.deepEqual(
        trust.view(h.id.identity).current,
        round % 2 === 0 ? rotations[i].print : h.print,
      ),
    );
  }
});

test("a queued invalidation never overwrites a decision loaded meanwhile", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const rotated = await peer(b.id);
  const tab1 = await Trust.open(store, integrity);
  let release: () => void = () => {};
  let gated = false;
  const gate = {
    ...store,
    get: async (name: "vault" | "messages" | "trust", key: string) => {
      if (gated) {
        await new Promise<void>((resolve) => (release = resolve));
      }
      return store.get(name, key);
    },
  };
  const tab2 = await Trust.open(gate, integrity);
  await tab1.observe(b.bundle);
  await tab1.verify(b.id.identity, b.print.value);
  await tab2.refresh(b.id.identity);
  await tab2.observe(b.bundle);
  assert.equal(tab2.view(b.id.identity).state, "verified");

  await tab1.observe(rotated.bundle);
  await tab1.flush();
  assert.equal(await tab1.verify(b.id.identity, rotated.print.value), true);
  const decision = stored(store, b.id.identity);

  gated = true;
  const refreshed = tab2.refresh(b.id.identity);
  const observed = tab2.observe(rotated.bundle);
  while (tab2.view(b.id.identity).current?.value !== rotated.print.value) {
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  gated = false;
  release();
  await Promise.all([refreshed, observed, tab2.flush()]);

  assert.deepEqual(stored(store, b.id.identity), decision);
  assert.equal(tab2.view(b.id.identity).state, "verified");
});

test("corrupted trust records never increase trust", async () => {
  const setup = await local();
  const trust = await Trust.open(setup.store, setup.integrity);
  const b = await peer();
  const c = await peer();
  const rotated = await peer(b.id);
  await trust.observe(b.bundle);
  await trust.verify(b.id.identity, b.print.value);
  const verified = stored(setup.store, b.id.identity) as Record<
    string,
    unknown
  >;
  await trust.observe(rotated.bundle);
  await trust.flush();
  const changed = stored(setup.store, b.id.identity) as Record<string, unknown>;
  const { fingerprint: _f, ...missingFingerprint } = verified;
  const cPrint = c.print.value;

  const cases: Record<string, unknown> = {
    "changed promoted to verified": { ...changed, status: "verified" },
    "fingerprint flipped": {
      ...verified,
      fingerprint: flip(verified.fingerprint as string),
    },
    "fingerprint of another identity": { ...verified, fingerprint: cPrint },
    "missing fingerprint": missingFingerprint,
    "key substituted": { ...verified, key: rotated.bundle.key },
    "key and fingerprint substituted": {
      ...verified,
      key: rotated.bundle.key,
      fingerprint: rotated.print.value,
    },
    "identity substituted": { ...verified, identity: c.id.identity },
    "invalid identity": { ...verified, identity: "nobody" },
    "unknown status": { ...verified, status: "trusted" },
    "boolean flag": { ...verified, verified: true },
    "future version": { ...verified, v: trustVersion + 1 },
    "mac flipped": { ...verified, mac: flip(verified.mac as string) },
    "mac missing": { ...verified, mac: undefined },
    "string record": "verified",
    "true record": true,
    null: null,
    array: [verified],
  };
  for (const [name, value] of Object.entries(cases)) {
    setup.store.data.set(`trust:${b.id.identity}`, value);
    const reopened = await Trust.open(setup.store, setup.integrity);
    assert.equal(reopened.rejected, 1, name);
    for (const bundle of [b.bundle, rotated.bundle]) {
      await reopened.observe(bundle);
      assert.equal(reopened.view(b.id.identity).state, "unverified", name);
    }
    await reopened.flush();
    assert.deepEqual(stored(setup.store, b.id.identity), value, name);
  }

  const foreign = await local();
  setup.store.data.set(`trust:${b.id.identity}`, verified);
  const wrongKey = await Trust.open(setup.store, foreign.integrity);
  await wrongKey.observe(b.bundle);
  assert.equal(wrongKey.view(b.id.identity).state, "unverified");

  setup.store.data.set(`trust:${c.id.identity}`, {
    ...verified,
    identity: c.id.identity,
  });
  const moved = await Trust.open(setup.store, setup.integrity);
  await moved.observe(c.bundle);
  assert.equal(moved.view(c.id.identity).state, "unverified");
});

test("explicit verification replaces a corrupted record", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  store.data.set(`trust:${b.id.identity}`, { v: 9 });
  const trust = await Trust.open(store, integrity);
  assert.equal(trust.rejected, 1);
  await trust.observe(b.bundle);
  assert.equal(await trust.verify(b.id.identity, b.print.value), true);
  const reopened = await Trust.open(store, integrity);
  assert.equal(reopened.rejected, 0);
  await reopened.observe(b.bundle);
  assert.equal(reopened.view(b.id.identity).state, "verified");
});

test("a key change shows as changed even if it cannot be persisted", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const rotated = await peer(b.id);
  const setup = await Trust.open(store, integrity);
  await setup.observe(b.bundle);
  await setup.verify(b.id.identity, b.print.value);
  const before = stored(store, b.id.identity);

  for (const failure of ["rejected", "thrown"] as const) {
    const broken = {
      ...store,
      swap: async () => {
        if (failure === "thrown") {
          throw new Error("write failed");
        }
        return false;
      },
    };
    const trust = await Trust.open(broken, integrity);
    await trust.observe(b.bundle);
    assert.equal(trust.view(b.id.identity).state, "verified");
    await trust.observe(rotated.bundle);
    await trust.flush();
    assert.equal(trust.view(b.id.identity).state, "changed", failure);
    assert.equal(
      await trust.verify(b.id.identity, rotated.print.value),
      false,
      failure,
    );
    assert.equal(trust.view(b.id.identity).state, "changed", failure);
    assert.deepEqual(stored(store, b.id.identity), before);
  }
});

test("an authentic record whose fingerprint does not match its key is rejected", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const c = await peer();
  const forge = async (fields: Record<string, unknown>) => {
    const input = new TextEncoder().encode(
      "ghostx/trust/v1\0" +
        JSON.stringify([
          fields.v,
          fields.identity,
          fields.status,
          fields.key,
          fields.fingerprint,
        ]),
    );
    const mac = await crypto.subtle.sign("HMAC", integrity, input);
    return { ...fields, mac: encodeBase64Url(new Uint8Array(mac)) };
  };
  const honest = await forge({
    v: trustVersion,
    identity: b.id.identity,
    status: "verified",
    key: b.bundle.key,
    fingerprint: b.print.value,
  });
  store.data.set(`trust:${b.id.identity}`, honest);
  const control = await Trust.open(store, integrity);
  await control.observe(b.bundle);
  assert.equal(control.view(b.id.identity).state, "verified");

  for (const fields of [
    { key: c.bundle.key, fingerprint: b.print.value },
    { key: b.bundle.key, fingerprint: c.print.value },
  ]) {
    store.data.set(
      `trust:${b.id.identity}`,
      await forge({
        v: trustVersion,
        identity: b.id.identity,
        status: "verified",
        ...fields,
      }),
    );
    const trust = await Trust.open(store, integrity);
    assert.equal(trust.rejected, 1);
    await trust.observe(b.bundle);
    assert.equal(trust.view(b.id.identity).state, "unverified");
  }
});

test("the record decoder enforces the schema independently of the MAC", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  await trust.observe(b.bundle);
  await trust.verify(b.id.identity, b.print.value);
  const record = stored(store, b.id.identity) as Record<string, unknown>;
  const key = b.id.identity;
  assert.deepEqual(parseTrustRecord(key, record), record);

  const without = (name: string) => {
    const copy = { ...record };
    delete copy[name];
    return copy;
  };
  const cases: [string, string, unknown][] = [
    ["stored under another identity", (await peer()).id.identity, record],
    ["version 0", key, { ...record, v: 0 }],
    ["version string", key, { ...record, v: "1" }],
    ["status", key, { ...record, status: "Verified" }],
    ["short key", key, { ...record, key: "AAAA" }],
    ["padded key", key, { ...record, key: `${record.key}=` }],
    ["short fingerprint", key, { ...record, fingerprint: "AAAA" }],
    ["hex fingerprint", key, { ...record, fingerprint: "ab".repeat(64) }],
    ["digits as fingerprint", key, { ...record, fingerprint: b.print.digits }],
    ["short mac", key, { ...record, mac: "AAAA" }],
    ["extra field", key, { ...record, verifiedAt: 1 }],
    ...Object.keys(record).map((name): [string, string, unknown] => [
      `missing ${name}`,
      key,
      without(name),
    ]),
  ];
  for (const [name, at, value] of cases) {
    assert.equal(parseTrustRecord(at, value), null, name);
  }
});

test("a stale tab cannot overwrite a newer verification decision", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const rotated = await peer(b.id);
  const tab1 = await Trust.open(store, integrity);
  const tab2 = await Trust.open(store, integrity);
  await tab1.observe(b.bundle);
  await tab2.observe(b.bundle);

  assert.equal(await tab1.verify(b.id.identity, b.print.value), true);
  assert.equal(await tab2.verify(b.id.identity, b.print.value), false);
  assert.equal(tab2.view(b.id.identity).state, "verified");

  await tab1.observe(rotated.bundle);
  await tab1.flush();
  assert.equal(await tab1.verify(b.id.identity, rotated.print.value), true);
  const latest = stored(store, b.id.identity);

  await tab2.observe(rotated.bundle);
  await tab2.flush();
  assert.deepEqual(stored(store, b.id.identity), latest);
  await tab2.refresh(b.id.identity);
  assert.equal(tab2.view(b.id.identity).state, "verified");
  assert.deepEqual(tab2.view(b.id.identity).verified, rotated.print);
});

test("refresh picks up a key change recorded by another tab", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const rotated = await peer(b.id);
  const tab1 = await Trust.open(store, integrity);
  await tab1.observe(b.bundle);
  await tab1.verify(b.id.identity, b.print.value);
  const tab2 = await Trust.open(store, integrity);
  await tab2.observe(b.bundle);
  assert.equal(tab2.view(b.id.identity).state, "verified");

  await tab1.observe(rotated.bundle);
  await tab1.flush();
  await tab2.refresh(b.id.identity);
  assert.equal(tab2.view(b.id.identity).state, "changed");
});

test("reset clears trust and closed stores refuse changes", async () => {
  const { store, integrity } = await local();
  const b = await peer();
  const trust = await Trust.open(store, integrity);
  await trust.observe(b.bundle);
  await trust.verify(b.id.identity, b.print.value);
  await store.clear();
  const state = await loadVault(store);
  assert.equal(state.status, "ready");
  const fresh = await Trust.open(store, (state as Unlocked).integrity);
  await fresh.observe(b.bundle);
  assert.equal(fresh.view(b.id.identity).state, "unverified");

  await fresh.close();
  assert.equal(await fresh.verify(b.id.identity, b.print.value), false);
  assert.equal(stored(store, b.id.identity), undefined);
});

test("fuzzed trust records never restore as verified", async () => {
  const { store, integrity } = await local();
  const trust = await Trust.open(store, integrity);
  const b = await peer();
  await trust.observe(b.bundle);
  await trust.verify(b.id.identity, b.print.value);
  const original = stored(store, b.id.identity) as Record<string, unknown>;
  const names = Object.keys(original);
  const values: unknown[] = [
    null,
    undefined,
    0,
    1,
    2,
    "",
    "verified",
    "changed",
    true,
    [],
    {},
    "A".repeat(43),
    "A".repeat(86),
    b.print.digits,
  ];
  let seed = 0x2545f491;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 1500);
  for (let i = 0; i < iterations; i++) {
    const mutated: Record<string, unknown> = { ...original };
    for (let s = 0; s <= random(3); s++) {
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
          text.slice(0, at) + chars[random(chars.length)] + text.slice(at + 1);
      } else {
        mutated[name] = original[names[random(names.length)]];
      }
    }
    store.data.set(`trust:${b.id.identity}`, mutated);
    const reopened = await Trust.open(store, integrity);
    await reopened.observe(b.bundle);
    if (reopened.view(b.id.identity).state === "verified") {
      assert.deepEqual(mutated, original);
    }
  }
});
