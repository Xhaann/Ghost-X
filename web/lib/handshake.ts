import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import type { ExchangeKey } from "./encryption.ts";
import { isCanonicalExchangeKey } from "./fingerprint.ts";
import { type IdentityKey, parseIdentity, verify } from "./identity.ts";
import {
  confirmSize,
  deviceIdSize,
  exchangeKeySize,
  isEpoch,
} from "./protocol.ts";

export { confirmSize, deviceIdSize };

export const handshakeVersion = 1;
export const initiationIdSize = 16;

const exchange = { name: "X25519" };
const encoder = new TextEncoder();
const signedContext = encoder.encode("ghostx/prekey/signed/v1\0");
const onetimeContext = encoder.encode("ghostx/prekey/onetime/v1\0");
const transcriptContext = encoder.encode("ghostx/x3dh/v1\0");
const proofContext = encoder.encode("ghostx/x3dh/initiate/v1\0");
const curvePrefix = new Uint8Array(32).fill(0xff);
const labels = {
  root: encoder.encode("ghostx/x3dh/v1/root\0"),
  initiator: encoder.encode("ghostx/x3dh/v1/confirm/initiator\0"),
  responder: encoder.encode("ghostx/x3dh/v1/confirm/responder\0"),
};

export type Prekey = { id: number; key: string; signature: string };

export type PrekeyKind = "signed" | "onetime";

export type Transcript = {
  initiator: string;
  responder: string;
  initiatorStatic: Uint8Array<ArrayBuffer>;
  responderStatic: Uint8Array<ArrayBuffer>;
  device: string;
  signed: { id: number; key: Uint8Array<ArrayBuffer> };
  onetime: { id: number; key: Uint8Array<ArrayBuffer> } | null;
  ephemeral: Uint8Array<ArrayBuffer>;
};

export type Initiation = {
  device: string;
  signed: number;
  onetime: number | null;
  ephemeral: string;
  proof: string;
  confirm: string;
};

export type Pending = {
  id: string;
  root: CryptoKey;
  responder: CryptoKey;
  transcript: Uint8Array<ArrayBuffer>;
};

export type Established = { id: string; root: CryptoKey; accept: string };

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

function prekeyMessage(
  context: Uint8Array,
  identity: string,
  staticKey: Uint8Array,
  device: string,
  id: number,
  key: Uint8Array,
): Uint8Array<ArrayBuffer> | null {
  const owner = parseIdentity(identity);
  const deviceRaw = decodeBase64Url(device, deviceIdSize);
  if (
    !owner ||
    !deviceRaw ||
    !isEpoch(id) ||
    staticKey.length !== exchangeKeySize ||
    key.length !== exchangeKeySize
  ) {
    return null;
  }
  return concat(context, owner, staticKey, deviceRaw, u32(id), key);
}

export function prekeyBindingMessage(
  kind: PrekeyKind,
  identity: string,
  staticKey: Uint8Array,
  device: string,
  id: number,
  key: Uint8Array,
): Uint8Array<ArrayBuffer> | null {
  return prekeyMessage(
    kind === "signed" ? signedContext : onetimeContext,
    identity,
    staticKey,
    device,
    id,
    key,
  );
}

export async function signPrekey(
  kind: PrekeyKind,
  identity: IdentityKey,
  staticKey: Uint8Array,
  device: string,
  id: number,
  key: Uint8Array,
): Promise<Prekey | null> {
  const message = prekeyBindingMessage(
    kind,
    identity.identity,
    staticKey,
    device,
    id,
    key,
  );
  const signature = message ? await identity.sign(message) : null;
  return signature ? { id, key: encodeBase64Url(key), signature } : null;
}

export async function verifyPrekey(
  kind: PrekeyKind,
  identity: string,
  staticKey: Uint8Array,
  device: string,
  prekey: Prekey,
): Promise<Uint8Array<ArrayBuffer> | null> {
  const key = decodeBase64Url(prekey.key, exchangeKeySize);
  if (!key || !isCanonicalExchangeKey(key)) {
    return null;
  }
  const message = prekeyBindingMessage(
    kind,
    identity,
    staticKey,
    device,
    prekey.id,
    key,
  );
  if (!message) {
    return null;
  }
  return (await verify(identity, message, prekey.signature)) ? key : null;
}

export function transcriptBytes(t: Transcript): Uint8Array<ArrayBuffer> | null {
  const initiator = parseIdentity(t.initiator);
  const responder = parseIdentity(t.responder);
  const device = decodeBase64Url(t.device, deviceIdSize);
  const keys = [
    t.initiatorStatic,
    t.responderStatic,
    t.signed.key,
    t.ephemeral,
    ...(t.onetime ? [t.onetime.key] : []),
  ];
  if (
    !initiator ||
    !responder ||
    !device ||
    !isEpoch(t.signed.id) ||
    (t.onetime !== null && !isEpoch(t.onetime.id)) ||
    keys.some((key) => key.length !== exchangeKeySize)
  ) {
    return null;
  }
  return concat(
    transcriptContext,
    initiator,
    responder,
    t.initiatorStatic,
    t.responderStatic,
    device,
    u32(t.signed.id),
    t.signed.key,
    ...(t.onetime
      ? [Uint8Array.of(1), u32(t.onetime.id), t.onetime.key]
      : [Uint8Array.of(0)]),
    t.ephemeral,
  );
}

export function proofMessage(t: Transcript): Uint8Array<ArrayBuffer> | null {
  const bytes = transcriptBytes(t);
  return bytes ? concat(proofContext, bytes) : null;
}

async function agree(
  privateKey: CryptoKey,
  peer: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const peerKey = await crypto.subtle.importKey(
    "raw",
    peer,
    exchange,
    false,
    [],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: peerKey },
      privateKey,
      256,
    ),
  );
}

export async function derive(
  secrets: Uint8Array[],
  transcript: Uint8Array<ArrayBuffer>,
): Promise<{
  id: string;
  root: CryptoKey;
  initiator: CryptoKey;
  responder: CryptoKey;
}> {
  const material = await crypto.subtle.importKey(
    "raw",
    concat(curvePrefix, ...secrets),
    "HKDF",
    false,
    ["deriveKey"],
  );
  const salt = new Uint8Array(32);
  const key = (label: Uint8Array, usages: KeyUsage[]) =>
    crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: concat(label, transcript) },
      material,
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      usages,
    );
  const [root, initiator, responder, digest] = await Promise.all([
    key(labels.root, ["sign"]),
    key(labels.initiator, ["sign", "verify"]),
    key(labels.responder, ["sign", "verify"]),
    crypto.subtle.digest("SHA-256", transcript),
  ]);
  return {
    id: encodeBase64Url(new Uint8Array(digest).slice(0, initiationIdSize)),
    root,
    initiator,
    responder,
  };
}

export type VerifiedBundle = {
  identity: string;
  staticKey: Uint8Array<ArrayBuffer>;
  device: string;
  signed: { id: number; key: Uint8Array<ArrayBuffer> };
  onetime: { id: number; key: Uint8Array<ArrayBuffer> } | null;
};

export async function initiate(
  own: { identity: IdentityKey; exchange: ExchangeKey },
  peer: VerifiedBundle,
): Promise<{ initiation: Initiation; pending: Pending } | null> {
  try {
    const pair = (await crypto.subtle.generateKey(exchange, false, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const ephemeral = new Uint8Array(
      await crypto.subtle.exportKey("raw", pair.publicKey),
    );
    const t: Transcript = {
      initiator: own.identity.identity,
      responder: peer.identity,
      initiatorStatic: own.exchange.publicRaw,
      responderStatic: peer.staticKey,
      device: peer.device,
      signed: peer.signed,
      onetime: peer.onetime,
      ephemeral,
    };
    const transcript = transcriptBytes(t);
    const proofInput = proofMessage(t);
    const dh1 = await own.exchange.agree(peer.signed.key);
    if (!transcript || !proofInput || !dh1) {
      return null;
    }
    const secrets = [
      dh1,
      await agree(pair.privateKey, peer.staticKey),
      await agree(pair.privateKey, peer.signed.key),
      ...(peer.onetime ? [await agree(pair.privateKey, peer.onetime.key)] : []),
    ];
    const derived = await derive(secrets, transcript);
    const [confirm, proof] = await Promise.all([
      crypto.subtle.sign("HMAC", derived.initiator, transcript),
      own.identity.sign(proofInput),
    ]);
    if (!proof) {
      return null;
    }
    return {
      initiation: {
        device: peer.device,
        signed: peer.signed.id,
        onetime: peer.onetime?.id ?? null,
        ephemeral: encodeBase64Url(ephemeral),
        proof,
        confirm: encodeBase64Url(new Uint8Array(confirm)),
      },
      pending: {
        id: derived.id,
        root: derived.root,
        responder: derived.responder,
        transcript,
      },
    };
  } catch {
    return null;
  }
}

export type ResponderKeys = {
  signed: { id: number; key: Uint8Array<ArrayBuffer>; privateKey: CryptoKey };
  onetime: {
    id: number;
    key: Uint8Array<ArrayBuffer>;
    privateKey: CryptoKey;
  } | null;
};

export async function respond(
  own: { identity: IdentityKey; exchange: ExchangeKey },
  keys: ResponderKeys,
  initiation: {
    from: string;
    fromStatic: Uint8Array<ArrayBuffer>;
    device: string;
    ephemeral: string;
    proof: string;
    confirm: string;
  },
): Promise<Established | null> {
  try {
    const ephemeral = decodeBase64Url(initiation.ephemeral, exchangeKeySize);
    const confirm = decodeBase64Url(initiation.confirm, confirmSize);
    if (!ephemeral || !confirm || !isCanonicalExchangeKey(ephemeral)) {
      return null;
    }
    const t: Transcript = {
      initiator: initiation.from,
      responder: own.identity.identity,
      initiatorStatic: initiation.fromStatic,
      responderStatic: own.exchange.publicRaw,
      device: initiation.device,
      signed: { id: keys.signed.id, key: keys.signed.key },
      onetime: keys.onetime
        ? { id: keys.onetime.id, key: keys.onetime.key }
        : null,
      ephemeral,
    };
    const transcript = transcriptBytes(t);
    const proofInput = proofMessage(t);
    if (
      !transcript ||
      !proofInput ||
      !(await verify(initiation.from, proofInput, initiation.proof))
    ) {
      return null;
    }
    const dh2 = await own.exchange.agree(ephemeral);
    if (!dh2) {
      return null;
    }
    const secrets = [
      await agree(keys.signed.privateKey, initiation.fromStatic),
      dh2,
      await agree(keys.signed.privateKey, ephemeral),
      ...(keys.onetime
        ? [await agree(keys.onetime.privateKey, ephemeral)]
        : []),
    ];
    const derived = await derive(secrets, transcript);
    if (
      !(await crypto.subtle.verify(
        "HMAC",
        derived.initiator,
        confirm,
        transcript,
      ))
    ) {
      return null;
    }
    const accept = await crypto.subtle.sign(
      "HMAC",
      derived.responder,
      transcript,
    );
    return {
      id: derived.id,
      root: derived.root,
      accept: encodeBase64Url(new Uint8Array(accept)),
    };
  } catch {
    return null;
  }
}

export async function confirmAcceptance(
  pending: Pending,
  accept: string,
): Promise<boolean> {
  const tag = decodeBase64Url(accept, confirmSize);
  if (!tag) {
    return false;
  }
  try {
    return await crypto.subtle.verify(
      "HMAC",
      pending.responder,
      tag,
      pending.transcript,
    );
  } catch {
    return false;
  }
}
