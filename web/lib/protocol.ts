import {
  decodeBase64Url,
  decodeBase64UrlRange,
  encodeBase64Url,
} from "./base64.ts";
import { isIdentity } from "./identity.ts";

export type ErrorCode =
  | "invalid_message"
  | "unsupported_type"
  | "invalid_payload"
  | "authentication_required"
  | "authentication_failed"
  | "recipient_unavailable"
  | "message_too_large"
  | "key_required"
  | "duplicate_message"
  | "stale_session"
  | "session_limit"
  | "pending_limit"
  | "queue_full"
  | "internal_error";

export type ClientMessage =
  | { type: "ping"; payload: { sentAt: number } }
  | { type: "challenge"; payload: Record<string, never> }
  | { type: "authenticate"; payload: { identity: string; signature: string } }
  | { type: "whoami"; payload: Record<string, never> }
  | { type: "presence"; payload: Record<string, never> }
  | { type: "publish"; payload: { key: string; signature: string } }
  | { type: "key"; payload: { identity: string } }
  | {
      type: "send";
      payload: { to: string; id: string; ciphertext: string };
    }
  | { type: "fetch"; payload: Record<string, never> }
  | { type: "ack"; payload: { from: string; id: string } }
  | { type: "clear"; payload: { to: string; id: string } }
  | {
      type: "prekeys";
      payload: { device: string; signed: WirePrekey; onetime: WirePrekey[] };
    }
  | { type: "bundle"; payload: { identity: string } }
  | {
      type: "initiate";
      payload: {
        version: number;
        to: string;
        device: string;
        signed: number;
        onetime: number | null;
        ephemeral: string;
        ratchet: string;
        proof: string;
        confirm: string;
      };
    }
  | {
      type: "accept";
      payload: { to: string; ephemeral: string; confirm: string };
    };

export type WirePrekey = { id: number; key: string; signature: string };

export type WireDeviceBundle = {
  device: string;
  signed: WirePrekey;
  onetime: WirePrekey | null;
};

export type ReceiptStatus = "delivered" | "expired";

export type ServerMessage =
  | {
      type: "pong";
      id: string;
      payload: { sentAt: number; receivedAt: number };
    }
  | { type: "challenge"; id: string; payload: { nonce: string } }
  | { type: "authenticated"; id: string; payload: { identity: string } }
  | { type: "whoami"; id: string; payload: { identity: string } }
  | { type: "presence"; id: string; payload: Record<string, never> }
  | {
      type: "queued" | "fetched" | "acked" | "cleared" | "published";
      id: string;
      payload: Record<string, never>;
    }
  | { type: "initiated"; id: string; payload: Record<string, never> }
  | { type: "accepted"; id: string; payload: Record<string, never> }
  | { type: "prekeys"; id: string; payload: { available: number } }
  | {
      type: "bundle";
      id: string;
      payload: {
        version: number;
        identity: string;
        key: string;
        signature: string;
        bundles: WireDeviceBundle[];
      };
    }
  | {
      type: "initiation";
      id?: undefined;
      payload: {
        version: number;
        from: string;
        key: string;
        signature: string;
        device: string;
        signed: number;
        onetime: number | null;
        ephemeral: string;
        ratchet: string;
        proof: string;
        confirm: string;
      };
    }
  | {
      type: "acceptance";
      id?: undefined;
      payload: { from: string; ephemeral: string; confirm: string };
    }
  | {
      type: "key";
      id: string;
      payload: { identity: string; key: string; signature: string };
    }
  | {
      type: "message";
      id?: undefined;
      payload: {
        id: string;
        from: string;
        key: string;
        signature: string;
        ciphertext: string;
      };
    }
  | {
      type: "receipt";
      id?: undefined;
      payload: { to: string; id: string; status: ReceiptStatus };
    }
  | {
      type: "present" | "absent";
      id?: undefined;
      payload: { identity: string };
    }
  | { type: "error"; id?: string; payload: { code: ErrorCode } };

export const nonceSize = 32;

export const maxBodySize = 4096;
export const exchangeKeySize = 32;
export const signatureSize = 64;
export const saltSize = 32;
export const ivSize = 12;
export const tagSize = 16;
export const minSealedSize = 1 + tagSize;
export const maxSealedSize = maxBodySize + tagSize;
export const maxEpoch = 2 ** 31 - 1;
export const maxDevices = 4;
export const deviceIdSize = 16;
export const confirmSize = 32;
export const maxOnetimePublish = 100;
export const ratchetHeaderSize = 1 + 16 + 32 + 4 + 4;
export const messageIdSize = 16;
export const messageIdLength = 22;
export const minMessageSize = ratchetHeaderSize + messageIdLength + 1 + tagSize;
export const maxMessageSize =
  ratchetHeaderSize + messageIdLength + maxBodySize + tagSize;

const encoder = new TextEncoder();

export function bodySize(body: string): number {
  return encoder.encode(body).length;
}

export function isValidBody(body: unknown): body is string {
  return (
    typeof body === "string" &&
    body.length > 0 &&
    bodySize(body) <= maxBodySize &&
    !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(body)
  );
}

const errorCodes: readonly string[] = [
  "invalid_message",
  "unsupported_type",
  "invalid_payload",
  "authentication_required",
  "authentication_failed",
  "recipient_unavailable",
  "message_too_large",
  "key_required",
  "duplicate_message",
  "stale_session",
  "session_limit",
  "pending_limit",
  "queue_full",
  "internal_error",
];

const idPattern = /^[A-Za-z0-9_-]{1,64}$/;

type Fields = Record<string, unknown>;

function isObject(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOnly(value: Fields, required: string[], optional: string[] = []) {
  const keys = Object.keys(value);
  return (
    required.every((key) => keys.includes(key)) &&
    keys.every((key) => required.includes(key) || optional.includes(key))
  );
}

function isTimestamp(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

export function isEpoch(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 0 &&
    (value as number) <= maxEpoch
  );
}

function parsePrekey(value: unknown): WirePrekey | null {
  if (
    isObject(value) &&
    hasOnly(value, ["id", "key", "signature"]) &&
    isEpoch(value.id) &&
    isFixed(value.key, exchangeKeySize) &&
    isFixed(value.signature, signatureSize)
  ) {
    return { id: value.id, key: value.key, signature: value.signature };
  }
  return null;
}

function parseDeviceBundle(value: unknown): WireDeviceBundle | null {
  if (
    !isObject(value) ||
    !hasOnly(value, ["device", "signed", "onetime"]) ||
    !isFixed(value.device, deviceIdSize)
  ) {
    return null;
  }
  const signed = parsePrekey(value.signed);
  const onetime = value.onetime === null ? null : parsePrekey(value.onetime);
  if (!signed || (value.onetime !== null && !onetime)) {
    return null;
  }
  return { device: value.device, signed, onetime };
}

export function isFixed(value: unknown, size: number): value is string {
  return decodeBase64Url(value, size) !== null;
}

export function isValidId(value: unknown): value is string {
  return typeof value === "string" && idPattern.test(value);
}

export function isMessageId(value: unknown): value is string {
  return isFixed(value, messageIdSize);
}

export function createMessageId(): string {
  return encodeBase64Url(crypto.getRandomValues(new Uint8Array(messageIdSize)));
}

export function isMessage(value: unknown): value is string {
  const bytes = decodeBase64UrlRange(value, minMessageSize, maxMessageSize);
  return bytes !== null && bytes[0] === 1;
}

export function createId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function encode(message: ClientMessage, id: string): string {
  return JSON.stringify({ type: message.type, id, payload: message.payload });
}

export function parse(data: unknown): ServerMessage | null {
  if (typeof data !== "string") {
    return null;
  }

  let value: unknown;
  try {
    value = JSON.parse(data);
  } catch {
    return null;
  }

  if (!isObject(value) || !isObject(value.payload)) {
    return null;
  }
  const { type, id, payload } = value;

  if (type === "pong") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, ["sentAt", "receivedAt"]) &&
      isTimestamp(payload.sentAt) &&
      isTimestamp(payload.receivedAt)
    ) {
      return {
        type,
        id,
        payload: { sentAt: payload.sentAt, receivedAt: payload.receivedAt },
      };
    }
    return null;
  }

  if (type === "challenge") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, ["nonce"]) &&
      typeof payload.nonce === "string" &&
      decodeBase64Url(payload.nonce, nonceSize) !== null
    ) {
      return { type, id, payload: { nonce: payload.nonce } };
    }
    return null;
  }

  if (type === "authenticated" || type === "whoami") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, ["identity"]) &&
      isIdentity(payload.identity)
    ) {
      return { type, id, payload: { identity: payload.identity } };
    }
    return null;
  }

  if (type === "presence") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, [])
    ) {
      return { type, id, payload: {} };
    }
    return null;
  }

  if (
    type === "queued" ||
    type === "fetched" ||
    type === "acked" ||
    type === "cleared" ||
    type === "published"
  ) {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, [])
    ) {
      return { type, id, payload: {} };
    }
    return null;
  }

  if (type === "key") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, ["identity", "key", "signature"]) &&
      isIdentity(payload.identity) &&
      isFixed(payload.key, exchangeKeySize) &&
      isFixed(payload.signature, signatureSize)
    ) {
      return {
        type,
        id,
        payload: {
          identity: payload.identity,
          key: payload.key,
          signature: payload.signature,
        },
      };
    }
    return null;
  }

  if (type === "message") {
    if (
      hasOnly(value, ["type", "payload"]) &&
      hasOnly(payload, ["id", "from", "key", "signature", "ciphertext"]) &&
      isMessageId(payload.id) &&
      isIdentity(payload.from) &&
      isFixed(payload.key, exchangeKeySize) &&
      isFixed(payload.signature, signatureSize) &&
      isMessage(payload.ciphertext)
    ) {
      return {
        type,
        payload: {
          id: payload.id,
          from: payload.from,
          key: payload.key,
          signature: payload.signature,
          ciphertext: payload.ciphertext,
        },
      };
    }
    return null;
  }

  if (type === "receipt") {
    if (
      hasOnly(value, ["type", "payload"]) &&
      hasOnly(payload, ["to", "id", "status"]) &&
      isIdentity(payload.to) &&
      isMessageId(payload.id) &&
      (payload.status === "delivered" || payload.status === "expired")
    ) {
      return {
        type,
        payload: { to: payload.to, id: payload.id, status: payload.status },
      };
    }
    return null;
  }

  if (type === "initiated" || type === "accepted") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, [])
    ) {
      return { type, id, payload: {} };
    }
    return null;
  }

  if (type === "prekeys") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, ["available"]) &&
      Number.isSafeInteger(payload.available) &&
      (payload.available as number) >= 0 &&
      (payload.available as number) <= maxOnetimePublish
    ) {
      return { type, id, payload: { available: payload.available as number } };
    }
    return null;
  }

  if (type === "bundle") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, [
        "version",
        "identity",
        "key",
        "signature",
        "bundles",
      ]) &&
      payload.version === 2 &&
      isIdentity(payload.identity) &&
      isFixed(payload.key, exchangeKeySize) &&
      isFixed(payload.signature, signatureSize) &&
      Array.isArray(payload.bundles) &&
      payload.bundles.length >= 1 &&
      payload.bundles.length <= maxDevices
    ) {
      const bundles = payload.bundles.map(parseDeviceBundle);
      if (
        bundles.some((b) => b === null) ||
        new Set(bundles.map((b) => b?.device)).size !== bundles.length
      ) {
        return null;
      }
      return {
        type,
        id,
        payload: {
          version: 2,
          identity: payload.identity,
          key: payload.key,
          signature: payload.signature,
          bundles: bundles as WireDeviceBundle[],
        },
      };
    }
    return null;
  }

  if (type === "initiation") {
    if (
      hasOnly(value, ["type", "payload"]) &&
      hasOnly(payload, [
        "version",
        "from",
        "key",
        "signature",
        "device",
        "signed",
        "onetime",
        "ephemeral",
        "ratchet",
        "proof",
        "confirm",
      ]) &&
      payload.version === 2 &&
      isIdentity(payload.from) &&
      isFixed(payload.key, exchangeKeySize) &&
      isFixed(payload.signature, signatureSize) &&
      isFixed(payload.device, deviceIdSize) &&
      isEpoch(payload.signed) &&
      (payload.onetime === null || isEpoch(payload.onetime)) &&
      isFixed(payload.ephemeral, exchangeKeySize) &&
      isFixed(payload.ratchet, exchangeKeySize) &&
      isFixed(payload.proof, signatureSize) &&
      isFixed(payload.confirm, confirmSize)
    ) {
      return {
        type,
        payload: {
          version: 2,
          from: payload.from,
          key: payload.key,
          signature: payload.signature,
          device: payload.device,
          signed: payload.signed,
          onetime: payload.onetime as number | null,
          ephemeral: payload.ephemeral,
          ratchet: payload.ratchet,
          proof: payload.proof,
          confirm: payload.confirm,
        },
      };
    }
    return null;
  }

  if (type === "acceptance") {
    if (
      hasOnly(value, ["type", "payload"]) &&
      hasOnly(payload, ["from", "ephemeral", "confirm"]) &&
      isIdentity(payload.from) &&
      isFixed(payload.ephemeral, exchangeKeySize) &&
      isFixed(payload.confirm, confirmSize)
    ) {
      return {
        type,
        payload: {
          from: payload.from,
          ephemeral: payload.ephemeral,
          confirm: payload.confirm,
        },
      };
    }
    return null;
  }

  if (type === "present" || type === "absent") {
    if (
      hasOnly(value, ["type", "payload"]) &&
      hasOnly(payload, ["identity"]) &&
      isIdentity(payload.identity)
    ) {
      return { type, payload: { identity: payload.identity } };
    }
    return null;
  }

  if (type === "error") {
    if (
      hasOnly(value, ["type", "payload"], ["id"]) &&
      (id === undefined || isValidId(id)) &&
      hasOnly(payload, ["code"]) &&
      typeof payload.code === "string" &&
      errorCodes.includes(payload.code)
    ) {
      const code = payload.code as ErrorCode;
      return id === undefined
        ? { type, payload: { code } }
        : { type, id, payload: { code } };
    }
    return null;
  }

  return null;
}
