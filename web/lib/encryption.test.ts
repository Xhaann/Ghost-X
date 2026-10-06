import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  ExchangeKey,
  type Parties,
  associatedData,
  keyBindingMessage,
  verifyBundle,
} from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import { exchangeKeySize, tagSize } from "./protocol.ts";
import { type LegacyParty, legacyParty, legacySeal } from "./testing.ts";

type Holder = { identity: IdentityKey; exchange: ExchangeKey };

async function holder(): Promise<Holder> {
  const [identity, exchange] = await Promise.all([
    IdentityKey.generate(),
    ExchangeKey.generate(),
  ]);
  return { identity, exchange };
}

function received(from: LegacyParty, to: Holder, id = "m1"): Parties {
  return {
    id,
    from: from.identity.identity,
    to: to.identity.identity,
    fromKey: from.publicRaw,
    toKey: to.exchange.publicRaw,
  };
}

function sent(from: Holder, to: LegacyParty, id = "m1"): Parties {
  return {
    id,
    from: from.identity.identity,
    to: to.identity.identity,
    fromKey: from.exchange.publicRaw,
    toKey: to.publicRaw,
  };
}

function flip(text: string, index = 0): string {
  const bytes = decodeBase64Url(text, Math.floor((text.length * 3) / 4));
  assert.ok(bytes);
  bytes[index] ^= 0x01;
  return encodeBase64Url(bytes);
}

test("generates distinct exchange keys with non-extractable private parts", async () => {
  const keys = await Promise.all(
    Array.from({ length: 20 }, () => ExchangeKey.generate()),
  );
  assert.equal(new Set(keys.map((k) => k.publicKey)).size, keys.length);
  for (const key of keys) {
    assert.equal(key.publicRaw.length, exchangeKeySize);
    assert.deepEqual(Object.keys(key), ["publicKey"]);
    assert.equal(
      JSON.stringify(key),
      JSON.stringify({ publicKey: key.publicKey }),
    );
  }
  const copy = keys[0].publicRaw;
  copy[0] ^= 0xff;
  assert.notDeepEqual(copy, keys[0].publicRaw);
});

test("the long-lived key has no runtime encryption path", async () => {
  const { exchange } = await holder();
  const surface = exchange as unknown as Record<string, unknown>;
  for (const name of ["seal", "open", "openOwn", "encrypt"]) {
    assert.equal(surface[name], undefined, name);
  }
  assert.equal(typeof surface.openLegacy, "function");
});

test("binds the exchange key to the identity", async () => {
  const a = await holder();
  const b = await holder();
  const bundle = await a.exchange.bind(a.identity);
  assert.ok(bundle);
  assert.deepEqual(await verifyBundle(bundle), a.exchange.publicRaw);

  const foreign = await a.exchange.bind(b.identity);
  assert.ok(foreign);
  for (const bad of [
    { ...foreign, identity: a.identity.identity },
    { ...bundle, key: b.exchange.publicKey },
    { ...bundle, identity: b.identity.identity },
    { ...bundle, key: "short" },
    { ...bundle, signature: flip(bundle.signature) },
    {
      ...bundle,
      signature:
        (await a.identity.sign(
          keyBindingMessage(b.identity.identity, a.exchange.publicRaw),
        )) ?? "",
    },
  ]) {
    assert.equal(await verifyBundle(bad), null);
  }
});

test("opens legacy envelopes in both roles for migration", async () => {
  const self = await holder();
  const peer = await legacyParty();
  const inbound = await legacySeal(
    received(peer, self),
    peer.privateKey,
    self.exchange.publicRaw,
    "legacy inbound 🌍",
  );
  const outbound = await legacySeal(
    sent(self, peer, "m2"),
    peer.privateKey,
    self.exchange.publicRaw,
    "legacy outbound",
  );
  assert.equal(
    await self.exchange.openLegacy(received(peer, self), inbound),
    "legacy inbound 🌍",
  );
  assert.equal(
    await self.exchange.openLegacy(sent(self, peer, "m2"), outbound),
    "legacy outbound",
  );
  const size = new TextEncoder().encode("legacy inbound 🌍").length + tagSize;
  assert.equal(decodeBase64Url(inbound.ciphertext, size)?.length, size);
});

test("legacy decryption rejects tampering, other holders, and rebinding", async () => {
  const self = await holder();
  const other = await holder();
  const peer = await legacyParty();
  const third = await legacyParty();
  const parties = received(peer, self);
  const sealed = await legacySeal(
    parties,
    peer.privateKey,
    self.exchange.publicRaw,
    "integrity",
  );

  for (const bad of [
    { ...sealed, ciphertext: flip(sealed.ciphertext) },
    { ...sealed, ciphertext: flip(sealed.ciphertext, 9) },
    { ...sealed, iv: flip(sealed.iv) },
    { ...sealed, salt: flip(sealed.salt) },
    { ...sealed, ciphertext: sealed.ciphertext.slice(0, -2) },
    { ...sealed, salt: "" },
    { ...sealed, iv: `${sealed.iv}=` },
    { ...sealed, ciphertext: "not base64!" },
  ]) {
    assert.equal(await self.exchange.openLegacy(parties, bad), null);
  }
  for (const rebound of [
    { ...parties, id: "m2" },
    { ...parties, from: third.identity.identity },
    { ...parties, to: other.identity.identity },
    { ...parties, fromKey: third.publicRaw },
  ]) {
    assert.equal(await self.exchange.openLegacy(rebound, sealed), null);
  }
  assert.equal(await other.exchange.openLegacy(parties, sealed), null);
  assert.equal(
    await other.exchange.openLegacy(
      { ...parties, toKey: other.exchange.publicRaw },
      sealed,
    ),
    null,
  );
  assert.equal(await self.exchange.openLegacy(parties, sealed), "integrity");
  assert.equal(associatedData({ ...parties, id: "" }), null);
});

test("released or regenerated keys cannot open legacy envelopes", async () => {
  const self = await holder();
  const peer = await legacyParty();
  const sealed = await legacySeal(
    received(peer, self),
    peer.privateKey,
    self.exchange.publicRaw,
    "before release",
  );
  const rotated: Holder = {
    identity: self.identity,
    exchange: await ExchangeKey.generate(),
  };
  assert.equal(
    await rotated.exchange.openLegacy(received(peer, rotated), sealed),
    null,
  );
  self.exchange.release();
  assert.equal(self.exchange.released, true);
  assert.equal(
    await self.exchange.openLegacy(received(peer, self), sealed),
    null,
  );
  self.identity.release();
  assert.equal(await (await ExchangeKey.generate()).bind(self.identity), null);
});
