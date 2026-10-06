import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { parseIdentity } from "./identity.ts";
import { exchangeKeySize } from "./protocol.ts";

export const fingerprintSize = 64;
export const digitGroups = 8;

const context = new TextEncoder().encode("ghostx/fingerprint/v1\0");
const groupBytes = 5;
const groupModulus = 100000;

export type Fingerprint = { value: string; digits: string };

function belowFieldPrime(raw: Uint8Array): boolean {
  if (raw[31] !== 0x7f) {
    return raw[31] < 0x7f;
  }
  for (let i = 30; i >= 1; i--) {
    if (raw[i] !== 0xff) {
      return true;
    }
  }
  return raw[0] < 0xed;
}

export function isCanonicalExchangeKey(raw: Uint8Array): boolean {
  return (
    raw.length === exchangeKeySize &&
    (raw[31] & 0x80) === 0 &&
    belowFieldPrime(raw)
  );
}

export function isCanonicalIdentityKey(raw: Uint8Array): boolean {
  if (raw.length !== 32) {
    return false;
  }
  const y = raw.slice();
  const sign = (y[31] & 0x80) !== 0;
  y[31] &= 0x7f;
  if (!belowFieldPrime(y)) {
    return false;
  }
  const one = y[0] === 1 && y.subarray(1).every((byte) => byte === 0);
  const minusOne =
    y[0] === 0xec &&
    y[31] === 0x7f &&
    y.subarray(1, 31).every((byte) => byte === 0xff);
  return !(sign && (one || minusOne));
}

function digitsOf(hash: Uint8Array): string {
  const groups: string[] = [];
  for (let g = 0; g < digitGroups; g++) {
    let value = 0;
    for (let i = 0; i < groupBytes; i++) {
      value = value * 256 + hash[g * groupBytes + i];
    }
    groups.push(String(value % groupModulus).padStart(5, "0"));
  }
  return groups.join(" ");
}

export async function fingerprint(
  identity: unknown,
  key: unknown,
): Promise<Fingerprint | null> {
  const identityRaw = parseIdentity(identity);
  const keyRaw = decodeBase64Url(key, exchangeKeySize);
  if (
    !identityRaw ||
    !keyRaw ||
    !isCanonicalIdentityKey(identityRaw) ||
    !isCanonicalExchangeKey(keyRaw)
  ) {
    return null;
  }
  const input = new Uint8Array(context.length + 64);
  input.set(context);
  input.set(identityRaw, context.length);
  input.set(keyRaw, context.length + 32);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-512", input));
  return { value: encodeBase64Url(hash), digits: digitsOf(hash) };
}

export function isFingerprintValue(value: unknown): value is string {
  return decodeBase64Url(value, fingerprintSize) !== null;
}
