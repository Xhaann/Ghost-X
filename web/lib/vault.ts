import { ExchangeKey } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";
import type { KeyValueStore } from "./storage.ts";

export const vaultVersion = 1;

const vaultKey = "keys";
const integrityAlgorithm = { name: "HMAC", hash: "SHA-256", length: 256 };
const recordFields = [
  "v",
  "identity",
  "signing",
  "exchangeKey",
  "exchange",
  "integrity",
];

export type Keys = { identity: IdentityKey; exchange: ExchangeKey };

export type Unlocked = { keys: Keys; integrity: CryptoKey; created: boolean };

export type VaultState =
  ({ status: "ready" } & Unlocked) | { status: "corrupted" };

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

async function restore(
  record: unknown,
): Promise<{ keys: Keys; integrity: CryptoKey } | null> {
  if (typeof record !== "object" || record === null || Array.isArray(record)) {
    return null;
  }
  const fields = record as Record<string, unknown>;
  const names = Object.keys(fields);
  if (
    fields.v !== vaultVersion ||
    names.length !== recordFields.length ||
    !recordFields.every((name) => names.includes(name)) ||
    !isIntegrityKey(fields.integrity)
  ) {
    return null;
  }
  const [identity, exchange] = await Promise.all([
    IdentityKey.restore(fields.identity, fields.signing),
    ExchangeKey.restore(fields.exchangeKey, fields.exchange),
  ]);
  if (!identity || !exchange) {
    identity?.release();
    exchange?.release();
    return null;
  }
  return { keys: { identity, exchange }, integrity: fields.integrity };
}

export async function loadVault(store: KeyValueStore): Promise<VaultState> {
  const existing = await store.get("vault", vaultKey);
  if (existing !== undefined) {
    const restored = await restore(existing);
    return restored
      ? { status: "ready", ...restored, created: false }
      : { status: "corrupted" };
  }

  const [identity, exchange, integrity] = await Promise.all([
    IdentityKey.create(),
    ExchangeKey.create(),
    crypto.subtle.generateKey(integrityAlgorithm, false, ["sign", "verify"]),
  ]);
  const added = await store.add("vault", vaultKey, {
    v: vaultVersion,
    identity: identity.key.identity,
    signing: identity.privateKey,
    exchangeKey: exchange.key.publicKey,
    exchange: exchange.privateKey,
    integrity,
  });
  if (added) {
    return {
      status: "ready",
      keys: { identity: identity.key, exchange: exchange.key },
      integrity,
      created: true,
    };
  }
  identity.key.release();
  exchange.key.release();
  const winner = await restore(await store.get("vault", vaultKey));
  return winner
    ? { status: "ready", ...winner, created: false }
    : { status: "corrupted" };
}
