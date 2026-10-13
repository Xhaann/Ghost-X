import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  type Fingerprint,
  fingerprint,
  isCanonicalExchangeKey,
  isCanonicalIdentityKey,
} from "./fingerprint.ts";
import {
  type IdentityKey,
  checkSignature,
  parseIdentity,
  verify,
} from "./identity.ts";
import {
  type WireDevice,
  type WireRoster,
  deviceIdSize,
  exchangeKeySize,
  maxDevices,
  parseWireRoster,
} from "./protocol.ts";

export const linkLifetime = 10 * 60;
export const linkSkew = 60;

const encoder = new TextEncoder();
const idContext = encoder.encode("ghostx/device/v1\0");
const rosterContext = encoder.encode("ghostx/roster/v1\0");
const linkContext = encoder.encode("ghostx/device/link/v1\0");
const linkSize = 32 + 32 + 32 + 8 + 64;

export type DeviceEntry = WireDevice;

export type Roster = WireRoster;

export type LinkRequest = {
  identity: string;
  device: DeviceEntry;
  created: number;
};

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u32(value: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

function u64(value: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

export async function deriveDeviceId(
  identity: string,
  signing: string,
): Promise<string | null> {
  const owner = parseIdentity(identity);
  const key = parseIdentity(signing);
  if (!owner || !key) {
    return null;
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    concat(idContext, owner, key),
  );
  return encodeBase64Url(new Uint8Array(digest).slice(0, deviceIdSize));
}

function entryParts(entry: DeviceEntry): Uint8Array[] | null {
  const id = decodeBase64Url(entry.id, deviceIdSize);
  const signing = parseIdentity(entry.signing);
  const exchange = decodeBase64Url(entry.exchange, exchangeKeySize);
  if (
    !id ||
    !signing ||
    !exchange ||
    !isCanonicalIdentityKey(signing) ||
    !isCanonicalExchangeKey(exchange)
  ) {
    return null;
  }
  return [id, signing, exchange];
}

export function rosterMessage(
  identity: string,
  version: number,
  devices: readonly DeviceEntry[],
): Uint8Array<ArrayBuffer> | null {
  const owner = parseIdentity(identity);
  if (
    !owner ||
    !Number.isSafeInteger(version) ||
    version < 1 ||
    version > 2 ** 31 - 1 ||
    devices.length < 1 ||
    devices.length > maxDevices
  ) {
    return null;
  }
  const parts: Uint8Array[] = [
    rosterContext,
    owner,
    u32(version),
    Uint8Array.of(devices.length),
  ];
  for (const entry of devices) {
    const encoded = entryParts(entry);
    if (!encoded) {
      return null;
    }
    parts.push(...encoded);
  }
  return concat(...parts);
}

export async function verifyRoster(
  value: unknown,
  strict = false,
): Promise<Roster | null> {
  const roster = parseWireRoster(value);
  if (!roster) {
    return null;
  }
  const message = rosterMessage(
    roster.identity,
    roster.version,
    roster.devices,
  );
  if (!message) {
    return null;
  }
  for (let i = 0; i < roster.devices.length; i++) {
    const entry = roster.devices[i];
    if (
      entry.signing === roster.identity ||
      (await deriveDeviceId(roster.identity, entry.signing)) !== entry.id ||
      (i > 0 && roster.devices[i - 1].id >= entry.id) ||
      roster.devices
        .slice(0, i)
        .some(
          (d) => d.signing === entry.signing || d.exchange === entry.exchange,
        )
    ) {
      return null;
    }
  }
  const check = strict ? checkSignature : verify;
  return (await check(roster.identity, message, roster.signature))
    ? roster
    : null;
}

export async function signRoster(
  root: IdentityKey,
  version: number,
  devices: readonly DeviceEntry[],
): Promise<Roster | null> {
  const sorted = [...devices].sort((a, b) => (a.id < b.id ? -1 : 1));
  const message = rosterMessage(root.identity, version, sorted);
  const signature = message ? await root.sign(message) : null;
  if (!signature) {
    return null;
  }
  return verifyRoster({
    identity: root.identity,
    version,
    devices: sorted,
    signature,
  });
}

export function rosterDevice(
  roster: Roster | null,
  id: string,
): DeviceEntry | null {
  return roster?.devices.find((d) => d.id === id) ?? null;
}

export function rosterFingerprint(roster: Roster): Promise<Fingerprint | null> {
  return fingerprint(roster.identity, roster.devices);
}

export function deviceFingerprint(
  identity: string,
  device: DeviceEntry,
): Promise<Fingerprint | null> {
  return fingerprint(identity, [device]);
}

function linkMessage(
  identity: Uint8Array,
  id: Uint8Array,
  signing: Uint8Array,
  exchange: Uint8Array,
  created: number,
): Uint8Array<ArrayBuffer> {
  return concat(linkContext, identity, id, signing, exchange, u64(created));
}

export async function createLinkRequest(
  identity: string,
  device: IdentityKey,
  exchange: Uint8Array<ArrayBuffer>,
  created: number,
): Promise<string | null> {
  const owner = parseIdentity(identity);
  const signing = parseIdentity(device.identity);
  const id = await deriveDeviceId(identity, device.identity);
  const idRaw = decodeBase64Url(id, deviceIdSize);
  if (!owner || !signing || !idRaw || !Number.isSafeInteger(created)) {
    return null;
  }
  const proof = await device.sign(
    linkMessage(owner, idRaw, signing, exchange, created),
  );
  const proofRaw = decodeBase64Url(proof, 64);
  if (!proofRaw) {
    return null;
  }
  return encodeBase64Url(
    concat(owner, signing, exchange, u64(created), proofRaw),
  );
}

export async function verifyLinkRequest(
  text: unknown,
  now: number,
): Promise<LinkRequest | null> {
  const raw = decodeBase64Url(
    typeof text === "string" ? text.trim() : text,
    linkSize,
  );
  if (!raw) {
    return null;
  }
  const owner = raw.slice(0, 32);
  const signing = raw.slice(32, 64);
  const exchange = raw.slice(64, 96);
  const created = Number(new DataView(raw.buffer, 96, 8).getBigUint64(0));
  const proof = raw.slice(104);
  const identity = encodeBase64Url(owner);
  const signingKey = encodeBase64Url(signing);
  if (
    !Number.isSafeInteger(created) ||
    created > now + linkSkew ||
    now - created > linkLifetime ||
    signingKey === identity ||
    !isCanonicalExchangeKey(exchange)
  ) {
    return null;
  }
  const id = await deriveDeviceId(identity, signingKey);
  const idRaw = decodeBase64Url(id, deviceIdSize);
  if (
    !id ||
    !idRaw ||
    !(await verify(
      signingKey,
      linkMessage(owner, idRaw, signing, exchange, created),
      encodeBase64Url(proof),
    ))
  ) {
    return null;
  }
  const device = {
    id,
    signing: signingKey,
    exchange: encodeBase64Url(exchange),
  };
  return entryParts(device) ? { identity, device, created } : null;
}
