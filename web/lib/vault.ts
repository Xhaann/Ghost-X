import { deriveDeviceId } from "./device.ts";
import { ExchangeKey } from "./encryption.ts";
import { IdentityKey, isIdentity } from "./identity.ts";
import type { KeyValueStore } from "./storage.ts";

export const vaultVersion = 3;

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
const previousFields = [...legacyFields, "storage"];
const recordFields = [
  "v",
  "identity",
  "root",
  "device",
  "deviceKey",
  "exchangeKey",
  "exchange",
  "integrity",
  "storage",
];

export type Keys = {
  identity: string;
  root: IdentityKey | null;
  device: IdentityKey;
  deviceId: string;
  exchange: ExchangeKey;
};

export type Unlocked = {
  keys: Keys;
  integrity: CryptoKey;
  storage: CryptoKey;
  created: boolean;
};

export type VaultState =
  | ({ status: "ready" } & Unlocked)
  | { status: "empty" }
  | { status: "corrupted" };

type Fields = Record<string, unknown>;

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

function fieldsOf(record: unknown): Fields | null {
  if (typeof record !== "object" || record === null || Array.isArray(record)) {
    return null;
  }
  const fields = record as Fields;
  const expected =
    fields.v === 1
      ? legacyFields
      : fields.v === 2
        ? previousFields
        : fields.v === vaultVersion
          ? recordFields
          : null;
  const names = Object.keys(fields);
  if (
    !expected ||
    names.length !== expected.length ||
    !expected.every((name) => names.includes(name)) ||
    !isIntegrityKey(fields.integrity) ||
    (fields.v !== 1 && !isStorageKey(fields.storage)) ||
    !isIdentity(fields.identity)
  ) {
    return null;
  }
  return fields;
}

function generateSecrets(): Promise<[CryptoKey, CryptoKey]> {
  return Promise.all([
    crypto.subtle.generateKey(integrityAlgorithm, false, ["sign", "verify"]),
    crypto.subtle.generateKey(storageAlgorithm, false, ["encrypt", "decrypt"]),
  ]) as Promise<[CryptoKey, CryptoKey]>;
}

async function unlock(
  fields: Fields,
): Promise<Omit<Unlocked, "created"> | null> {
  const identity = fields.identity as string;
  const [root, device, exchange] = await Promise.all([
    fields.root === null
      ? Promise.resolve(null)
      : IdentityKey.restore(identity, fields.root),
    IdentityKey.restore(fields.deviceKey, fields.device),
    ExchangeKey.restore(fields.exchangeKey, fields.exchange),
  ]);
  const deviceId = device && (await deriveDeviceId(identity, device.identity));
  if (
    !device ||
    !exchange ||
    !deviceId ||
    (fields.root !== null && !root) ||
    device.identity === identity
  ) {
    root?.release();
    device?.release();
    exchange?.release();
    return null;
  }
  return {
    keys: { identity, root, device, deviceId, exchange },
    integrity: fields.integrity as CryptoKey,
    storage: fields.storage as CryptoKey,
  };
}

async function upgrade(
  store: KeyValueStore,
  fields: Fields,
): Promise<Omit<Unlocked, "created"> | null> {
  const [root, exchange] = await Promise.all([
    IdentityKey.restore(fields.identity, fields.signing),
    ExchangeKey.restore(fields.exchangeKey, fields.exchange),
  ]);
  root?.release();
  exchange?.release();
  if (!root || !exchange) {
    return null;
  }
  const device = await IdentityKey.create();
  const storage =
    fields.v === 1
      ? await crypto.subtle.generateKey(storageAlgorithm, false, [
          "encrypt",
          "decrypt",
        ])
      : fields.storage;
  const upgraded = await store.swap(
    "vault",
    vaultKey,
    (current) => {
      const now = fieldsOf(current);
      return now?.v === fields.v && now?.identity === fields.identity;
    },
    {
      v: vaultVersion,
      identity: fields.identity,
      root: fields.signing,
      device: device.privateKey,
      deviceKey: device.key.identity,
      exchangeKey: fields.exchangeKey,
      exchange: fields.exchange,
      integrity: fields.integrity,
      storage,
    },
  );
  device.key.release();
  const winner = fieldsOf(await store.get("vault", vaultKey));
  if (
    !winner ||
    winner.v !== vaultVersion ||
    winner.identity !== fields.identity
  ) {
    return null;
  }
  return upgraded || winner.identity === fields.identity
    ? unlock(winner)
    : null;
}

export async function loadVault(store: KeyValueStore): Promise<VaultState> {
  const existing = await store.get("vault", vaultKey);
  if (existing === undefined) {
    return { status: "empty" };
  }
  const fields = fieldsOf(existing);
  const unlocked =
    fields &&
    (fields.v === vaultVersion
      ? await unlock(fields)
      : await upgrade(store, fields));
  return unlocked
    ? { status: "ready", ...unlocked, created: false }
    : { status: "corrupted" };
}

async function install(
  store: KeyValueStore,
  identity: string,
  root: { key: IdentityKey; privateKey: CryptoKey } | null,
): Promise<VaultState> {
  const [device, exchange, [integrity, storage]] = await Promise.all([
    IdentityKey.create(),
    ExchangeKey.create(),
    generateSecrets(),
  ]);
  const deviceId = await deriveDeviceId(identity, device.key.identity);
  const added =
    deviceId !== null &&
    (await store.add("vault", vaultKey, {
      v: vaultVersion,
      identity,
      root: root?.privateKey ?? null,
      device: device.privateKey,
      deviceKey: device.key.identity,
      exchangeKey: exchange.key.publicKey,
      exchange: exchange.privateKey,
      integrity,
      storage,
    }));
  if (added && deviceId) {
    return {
      status: "ready",
      keys: {
        identity,
        root: root?.key ?? null,
        device: device.key,
        deviceId,
        exchange: exchange.key,
      },
      integrity,
      storage,
      created: true,
    };
  }
  root?.key.release();
  device.key.release();
  exchange.key.release();
  return loadVault(store);
}

export async function createVault(store: KeyValueStore): Promise<VaultState> {
  const root = await IdentityKey.create();
  return install(store, root.key.identity, root);
}

export async function linkVault(
  store: KeyValueStore,
  identity: string,
): Promise<VaultState> {
  if (!isIdentity(identity)) {
    return { status: "corrupted" };
  }
  return install(store, identity, null);
}
