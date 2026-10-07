import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { type DeviceEntry, deriveDeviceId } from "./device.ts";
import { ExchangeKey } from "./encryption.ts";
import {
  digitGroups,
  fingerprint,
  fingerprintOf,
  fingerprintSize,
  isCanonicalExchangeKey,
  isCanonicalIdentityKey,
} from "./fingerprint.ts";
import { IdentityKey } from "./identity.ts";

async function device(identity: string): Promise<DeviceEntry> {
  const [signing, exchange] = await Promise.all([
    IdentityKey.generate(),
    ExchangeKey.generate(),
  ]);
  const id = await deriveDeviceId(identity, signing.identity);
  assert.ok(id);
  return { id, signing: signing.identity, exchange: exchange.publicKey };
}

async function holder(count = 1) {
  const identity = (await IdentityKey.generate()).identity;
  const devices = (
    await Promise.all(Array.from({ length: count }, () => device(identity)))
  ).sort((a, b) => (a.id < b.id ? -1 : 1));
  return { identity, devices };
}

function expected(identity: string, devices: DeviceEntry[]) {
  const h = createHash("sha512")
    .update("ghostx/fingerprint/v2\0")
    .update(Buffer.from(identity, "base64url"))
    .update(Buffer.of(devices.length));
  for (const d of devices) {
    h.update(Buffer.from(d.id, "base64url"))
      .update(Buffer.from(d.signing, "base64url"))
      .update(Buffer.from(d.exchange, "base64url"));
  }
  const hash = h.digest();
  const digits = Array.from({ length: digitGroups }, (_, g) =>
    String(Number(hash.readUIntBE(g * 5, 5) % 100000)).padStart(5, "0"),
  ).join(" ");
  return { value: hash.toString("base64url"), digits };
}

function bytes(fill: (raw: Uint8Array) => void): string {
  const raw = new Uint8Array(32);
  fill(raw);
  return encodeBase64Url(raw);
}

test("matches an independent SHA-512 over the identity and its device list", async () => {
  for (let i = 1; i <= 4; i++) {
    const { identity, devices } = await holder(i);
    const print = await fingerprint(identity, devices);
    assert.deepEqual(print, expected(identity, devices));
    assert.equal(decodeBase64Url(print?.value, fingerprintSize)?.length, 64);
    assert.match(print?.digits ?? "", /^\d{5}( \d{5}){7}$/);
    assert.deepEqual(fingerprintOf(print?.value), print);
  }
  assert.equal(fingerprintOf("x"), null);
});

test("changes when any device is added, removed, or substituted", async () => {
  const { identity, devices } = await holder(2);
  const base = await fingerprint(identity, devices);
  const extra = await device(identity);
  const variants = [
    devices.slice(0, 1),
    [...devices, extra],
    [{ ...devices[0], exchange: extra.exchange }, devices[1]],
    [{ ...devices[0], signing: extra.signing }, devices[1]],
    [{ ...devices[0], id: extra.id }, devices[1]],
  ];
  for (const variant of variants) {
    const other = await fingerprint(identity, variant);
    assert.ok(other);
    assert.notEqual(other.value, base?.value);
  }
  const otherIdentity = await fingerprint((await holder()).identity, devices);
  assert.notEqual(otherIdentity?.value, base?.value);
});

test("distinguishes many identities in both the full and displayed form", async () => {
  const holders = await Promise.all(Array.from({ length: 40 }, () => holder()));
  const prints = await Promise.all(
    holders.map((h) => fingerprint(h.identity, h.devices)),
  );
  assert.equal(new Set(prints.map((p) => p?.value)).size, holders.length);
  assert.equal(new Set(prints.map((p) => p?.digits)).size, holders.length);
});

test("rejects malformed and non-canonical encodings", async () => {
  const { identity, devices } = await holder();
  const prime = BigInt(2) ** BigInt(255) - BigInt(19);
  const p = prime.toString(16).padStart(64, "0");
  const le = (hex: string) =>
    bytes((raw) => raw.set(Buffer.from(hex, "hex").reverse()));
  const plus = (n: number) => le((prime + BigInt(n)).toString(16));
  const entry = devices[0];
  for (const exchange of [
    "",
    `${entry.exchange}=`,
    entry.exchange.slice(1),
    le(p),
    plus(1),
    bytes((raw) => {
      raw[31] = 0x80;
    }),
  ]) {
    assert.equal(
      await fingerprint(identity, [{ ...entry, exchange }]),
      null,
      exchange,
    );
  }
  for (const id of ["", `${entry.id}A`, entry.id.slice(1)]) {
    assert.equal(await fingerprint(identity, [{ ...entry, id }]), null);
  }
  for (const bad of [
    "",
    `${identity}=`,
    identity.slice(1),
    le(p),
    plus(5),
    null,
  ]) {
    assert.equal(await fingerprint(bad, devices), null, String(bad));
  }
  assert.equal(await fingerprint(identity, []), null);
  const below = Buffer.from(p, "hex").reverse();
  below[0] -= 1;
  assert.equal(isCanonicalExchangeKey(below), true);
  assert.equal(isCanonicalIdentityKey(below), true);
  assert.equal(isCanonicalIdentityKey(new Uint8Array(31)), false);
});

test("exposes only public material", async () => {
  const { identity, devices } = await holder(2);
  const print = await fingerprint(identity, devices);
  assert.deepEqual(Object.keys(print ?? {}).sort(), ["digits", "value"]);
  assert.ok(!/BEGIN|PRIVATE|"d":/.test(JSON.stringify(print)));
});
