import { ExchangeKey } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import type { KeyValueStore } from "./storage.ts";

export const vaultVersion = 2;

const vaultKey = "keys";
const integrityAlgorithm = { name: "HMAC", hash: "SHA-256", length: 256 };
const storageAlgorithm = { name: "AES-GCM", length: 256 };
const legacyFields = [
  "v",
  "identity",
  "signing",
  "exchangeKey",
  "exchange",
  "integrity",
];
const recordFields = [...legacyFields, "storage"];

export type Keys = { identity: IdentityKey; exchange: ExchangeKey };

export type Unlocked = {
  keys: Keys;
  integrity: CryptoKey;
  storage: CryptoKey;
  created: boolean;
};

export type VaultState =
  ({ status: "ready" } & Unlocked) | { status: "corrupted" };

type Restored = Omit<Unlocked, "created">;

function isIntegrityKey(key: unknown): key is CryptoKey {
  if (
    !(key instanceof CryptoKey) ||
    key.type !== "secret" ||
    key.extractable ||
    key.algorithm.name !== "HMAC" ||
    !key.usages.includes("sign") ||
    !key.usages.includes("verify")
  ) {
    return false;
  }
  const algorithm = key.algorithm as HmacKeyAlgorithm;
  return algorithm.hash.name === "SHA-256" && algorithm.length === 256;
}

function isStorageKey(key: unknown): key is CryptoKey {
  return (
    key instanceof CryptoKey &&
    key.type === "secret" &&
    !key.extractable &&
    key.algorithm.name === "AES-GCM" &&
    (key.algorithm as AesKeyAlgorithm).length === 256 &&
    key.usages.includes("encrypt") &&
    key.usages.includes("decrypt")
  );
}

function fieldsOf(record: unknown): Record<string, unknown> | null {
  if (typeof record !== "object" || record === null || Array.isArray(record)) {
    return null;
  }
  const fields = record as Record<string, unknown>;
  const expected = fields.v === 1 ? legacyFields : recordFields;
  const names = Object.keys(fields);
  if (
    (fields.v !== 1 && fields.v !== vaultVersion) ||
    names.length !== expected.length ||
    !expected.every((name) => names.includes(name)) ||
    !isIntegrityKey(fields.integrity) ||
    (fields.v === vaultVersion && !isStorageKey(fields.storage))
  ) {
    return null;
  }
  return fields;
}

async function unlock(
  fields: Record<string, unknown>,
): Promise<Omit<Restored, "storage"> | null> {
  const [identity, exchange] = await Promise.all([
    IdentityKey.restore(fields.identity, fields.signing),
    ExchangeKey.restore(fields.exchangeKey, fields.exchange),
  ]);
  if (!identity || !exchange) {
    identity?.release();
    exchange?.release();
    return null;
  }
  return {
    keys: { identity, exchange },
    integrity: fields.integrity as CryptoKey,
  };
}

async function restore(
  store: KeyValueStore,
  record: unknown,
): Promise<Restored | null> {
  const fields = fieldsOf(record);
  const unlocked = fields && (await unlock(fields));
  if (!fields || !unlocked) {
    return null;
  }
  if (fields.v === vaultVersion) {
    return { ...unlocked, storage: fields.storage as CryptoKey };
  }
  const storage = await crypto.subtle.generateKey(storageAlgorithm, false, [
    "encrypt",
    "decrypt",
  ]);
  const upgraded = await store.swap(
    "vault",
    vaultKey,
    (current) => {
      const now = fieldsOf(current);
      return now?.v === 1 && now.identity === fields.identity;
    },
    { ...fields, v: vaultVersion, storage },
  );
  if (upgraded) {
    return { ...unlocked, storage };
  }
  unlocked.keys.identity.release();
  unlocked.keys.exchange.release();
  const winner = fieldsOf(await store.get("vault", vaultKey));
  if (winner?.v !== vaultVersion || winner.identity !== fields.identity) {
    return null;
  }
  return restore(store, winner);
}

export async function loadVault(store: KeyValueStore): Promise<VaultState> {
  const existing = await store.get("vault", vaultKey);
  if (existing !== undefined) {
    const restored = await restore(store, existing);
    return restored
      ? { status: "ready", ...restored, created: false }
      : { status: "corrupted" };
  }

  const [identity, exchange, integrity, storage] = await Promise.all([
    IdentityKey.create(),
    ExchangeKey.create(),
    crypto.subtle.generateKey(integrityAlgorithm, false, ["sign", "verify"]),
    crypto.subtle.generateKey(storageAlgorithm, false, ["encrypt", "decrypt"]),
  ]);
  const added = await store.add("vault", vaultKey, {
    v: vaultVersion,
    identity: identity.key.identity,
    signing: identity.privateKey,
    exchangeKey: exchange.key.publicKey,
    exchange: exchange.privateKey,
    integrity,
    storage,
  });
  if (added) {
    return {
      status: "ready",
      keys: { identity: identity.key, exchange: exchange.key },
      integrity,
      storage,
      created: true,
    };
  }
  identity.key.release();
  exchange.key.release();
  const winner = await restore(store, await store.get("vault", vaultKey));
  return winner
    ? { status: "ready", ...winner, created: false }
    : { status: "corrupted" };
}
