import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeBase64Url } from "./base64.ts";
import { Outbox, maxOutbox, outboxVersion } from "./outbox.ts";
import { createMessageId } from "./protocol.ts";
import { memoryStore } from "./testing.ts";
import { type Unlocked, createVault } from "./vault.ts";

async function setup() {
  const store = memoryStore();
  const vault = (await createVault(store)) as Unlocked;
  return {
    store,
    storage: vault.storage,
    outbox: await Outbox.open(store, vault.storage),
  };
}

const peer = encodeBase64Url(new Uint8Array(32).fill(7));
const device = (n: number) => encodeBase64Url(new Uint8Array(16).fill(n));
const records = (store: ReturnType<typeof memoryStore>) =>
  [...store.data.entries()].filter(([key]) => key.startsWith("outbox:"));

test("pending paths are sealed at rest and bound to their peer, device, id, and time", async () => {
  const { store, storage, outbox } = await setup();
  const id = createMessageId();
  assert.equal(
    await outbox.add([{ peer, device: device(1), id }], "secret body", 1000),
    true,
  );
  const [[key, value]] = records(store);
  assert.equal(key, `outbox:${peer}/${device(1)}/${id}`);
  const raw = JSON.stringify(value);
  assert.ok(!raw.includes("secret body"));
  assert.ok(!raw.includes(Buffer.from("secret body").toString("base64url")));
  assert.equal((value as { v: number }).v, outboxVersion);
  assert.deepEqual(
    (await outbox.take(peer, device(1))).map((p) => [p.id, p.body, p.created]),
    [[id, "secret body", 1000]],
  );
  for (const [name, mutate] of Object.entries({
    created: (r: Record<string, unknown>) => ({ ...r, created: 1001 }),
    ciphertext: (r: Record<string, unknown>) => ({
      ...r,
      ciphertext: `${String(r.ciphertext).slice(0, -2)}AA`,
    }),
  })) {
    const fresh = memoryStore();
    fresh.data.set(key, mutate(value as Record<string, unknown>));
    const reopened = await Outbox.open(fresh, storage);
    assert.deepEqual(await reopened.take(peer, device(1)), [], name);
    assert.equal(reopened.size, 0, name);
  }
  const moved = memoryStore();
  moved.data.set(`outbox:${peer}/${device(2)}/${id}`, value);
  moved.data.set(`outbox:${peer}/${device(1)}/${id}`, {
    ...(value as object),
    extra: 1,
  });
  const reopened = await Outbox.open(moved, storage);
  assert.equal(reopened.size, 0);
  assert.equal(records(moved).length, 0);
});

test("the outbox is bounded and never partially accepts a message", async () => {
  const { outbox } = await setup();
  const ids = Array.from({ length: maxOutbox - 1 }, () => createMessageId());
  for (const id of ids) {
    assert.equal(
      await outbox.add([{ peer, device: device(1), id }], "x", 1),
      true,
    );
  }
  assert.equal(outbox.fits(1), true);
  assert.equal(outbox.fits(2), false);
  const id = createMessageId();
  assert.equal(
    await outbox.add(
      [
        { peer, device: device(2), id },
        { peer, device: device(3), id },
      ],
      "x",
      1,
    ),
    false,
  );
  assert.equal(outbox.size, maxOutbox - 1);
  assert.equal(
    await outbox.add([{ peer, device: device(1), id: ids[0] }], "x", 2),
    true,
  );
  assert.equal(outbox.size, maxOutbox - 1);
  assert.equal(await outbox.add([{ peer, device: "bad", id }], "x", 1), false);
  assert.equal(
    await outbox.add([{ peer, device: device(2), id }], "", 1),
    false,
  );
});

test("pending paths are released in order, removed durably, and survive reopening", async () => {
  const { store, storage, outbox } = await setup();
  const [first, second, third] = [
    createMessageId(),
    createMessageId(),
    createMessageId(),
  ];
  await outbox.add([{ peer, device: device(1), id: second }], "second", 20);
  await outbox.add(
    [
      { peer, device: device(1), id: first },
      { peer, device: device(2), id: first },
    ],
    "first",
    10,
  );
  await outbox.add([{ peer, device: device(2), id: third }], "third", 30);
  assert.deepEqual(
    outbox.addresses().sort(),
    [`${peer}/${device(1)}`, `${peer}/${device(2)}`].sort(),
  );
  assert.deepEqual(
    (await outbox.take(peer, device(1))).map((p) => p.body),
    ["first", "second"],
  );
  const reopened = await Outbox.open(store, storage);
  assert.equal(reopened.size, 4);
  await reopened.remove([{ peer, device: device(1), id: first }]);
  assert.deepEqual(
    (await reopened.take(peer, device(1))).map((p) => p.body),
    ["second"],
  );
  assert.deepEqual(
    (await reopened.take(peer, device(2))).map((p) => p.body),
    ["first", "third"],
  );
  assert.equal((await Outbox.open(store, storage)).size, 3);
  const otherKey = (await createVault(memoryStore())) as Unlocked;
  const foreign = await Outbox.open(store, otherKey.storage);
  assert.deepEqual(await foreign.take(peer, device(2)), []);
});

test("fuzzed stored records never open as anything but the sealed message", async () => {
  const { store, storage, outbox } = await setup();
  const id = createMessageId();
  await outbox.add([{ peer, device: device(1), id }], "sealed body", 1000);
  const [[key, value]] = records(store);
  const original = value as Record<string, unknown>;
  const names = Object.keys(original);
  const values: unknown[] = [
    null,
    0,
    -1,
    1.5,
    "",
    "x",
    [],
    {},
    2 ** 53,
    outboxVersion + 1,
    device(2),
    createMessageId(),
  ];
  let seed = 0x0b0c5;
  const random = (n: number) => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) % n;
  };
  const iterations = Number(process.env.FUZZ_ITERATIONS ?? 600);
  for (let i = 0; i < iterations; i++) {
    const mutated: Record<string, unknown> = { ...original };
    for (let s = 0; s <= random(3); s++) {
      const name = names[random(names.length)];
      const choice = random(4);
      if (choice === 0) {
        delete mutated[name];
      } else if (choice === 1) {
        mutated[name] = values[random(values.length)];
      } else if (choice === 2) {
        mutated[name] = original[names[random(names.length)]];
      } else if (
        typeof mutated[name] === "string" &&
        (mutated[name] as string).length > 0
      ) {
        const text = mutated[name] as string;
        const at = random(text.length);
        mutated[name] =
          text.slice(0, at) +
          (text[at] === "A" ? "B" : "A") +
          text.slice(at + 1);
      }
    }
    const fresh = memoryStore();
    fresh.data.set(key, mutated);
    const reopened = await Outbox.open(fresh, storage);
    const opened = await reopened.take(peer, device(1));
    const unchanged = JSON.stringify(mutated) === JSON.stringify(original);
    if (opened.length > 0) {
      assert.deepEqual(
        opened.map((p) => [p.id, p.body, p.created]),
        [[id, "sealed body", 1000]],
      );
      assert.ok(unchanged || mutated.v === original.v, JSON.stringify(mutated));
    }
    if (!unchanged) {
      for (const other of [device(2), device(3)]) {
        assert.deepEqual(await reopened.take(peer, other), []);
      }
    }
  }
});
