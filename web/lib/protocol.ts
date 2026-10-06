import { decodeBase64Url, decodeBase64UrlRange } from "./base64.ts";
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
      type: "session";
      payload: {
        session: string;
        epoch: number;
        key: string;
        signature: string;
      };
    }
  | {
      type: "send";
      payload: { to: string; epoch: number; envelopes: WireEnvelope[] };
    };

export type WireSession = {
  session: string;
  epoch: number;
  key: string;
  signature: string;
};

export type WireEnvelope = {
  session: string;
  epoch: number;
  salt: string;
  iv: string;
  ciphertext: string;
};

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
  | { type: "sent"; id: string; payload: Record<string, never> }
  | { type: "published"; id: string; payload: Record<string, never> }
  | { type: "established"; id: string; payload: Record<string, never> }
  | {
      type: "key";
      id: string;
      payload: {
        identity: string;
        key: string;
        signature: string;
        sessions: WireSession[];
      };
    }
  | {
      type: "message";
      id?: undefined;
      payload: {
        id: string;
        from: string;
        key: string;
        signature: string;
        sender: WireSession;
        envelope: WireEnvelope;
      };
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
export const minCiphertextSize = 1 + tagSize;
export const sessionIdSize = 16;
export const maxEpoch = 2 ** 31 - 1;
export const maxSessions = 4;
export const maxCiphertextSize = maxBodySize + tagSize;

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

function parseSession(value: unknown): WireSession | null {
  if (
    isObject(value) &&
    hasOnly(value, ["session", "epoch", "key", "signature"]) &&
    isFixed(value.session, sessionIdSize) &&
    isEpoch(value.epoch) &&
    isFixed(value.key, exchangeKeySize) &&
    isFixed(value.signature, signatureSize)
  ) {
    return {
      session: value.session,
      epoch: value.epoch,
      key: value.key,
      signature: value.signature,
    };
  }
  return null;
}

function parseEnvelope(value: unknown): WireEnvelope | null {
  if (
    isObject(value) &&
    hasOnly(value, ["session", "epoch", "salt", "iv", "ciphertext"]) &&
    isFixed(value.session, sessionIdSize) &&
    isEpoch(value.epoch) &&
    isFixed(value.salt, saltSize) &&
    isFixed(value.iv, ivSize) &&
    typeof value.ciphertext === "string" &&
    decodeBase64UrlRange(
      value.ciphertext,
      minCiphertextSize,
      maxCiphertextSize,
    ) !== null
  ) {
    return {
      session: value.session,
      epoch: value.epoch,
      salt: value.salt,
      iv: value.iv,
      ciphertext: value.ciphertext,
    };
  }
  return null;
}

export function isFixed(value: unknown, size: number): value is string {
  return decodeBase64Url(value, size) !== null;
}

export function isValidId(value: unknown): value is string {
  return typeof value === "string" && idPattern.test(value);
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

  if (type === "sent") {
    if (
      hasOnly(value, ["type", "id", "payload"]) &&
      isValidId(id) &&
      hasOnly(payload, [])
    ) {
      return { type, id, payload: {} };
    }
    return null;
  }

  if (type === "published" || type === "established") {
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
      hasOnly(payload, ["identity", "key", "signature", "sessions"]) &&
      isIdentity(payload.identity) &&
      isFixed(payload.key, exchangeKeySize) &&
      isFixed(payload.signature, signatureSize) &&
      Array.isArray(payload.sessions) &&
      payload.sessions.length <= maxSessions
    ) {
      const sessions = payload.sessions.map(parseSession);
      if (
        sessions.some((s) => s === null) ||
        new Set(sessions.map((s) => s?.session)).size !== sessions.length
      ) {
        return null;
      }
      return {
        type,
        id,
        payload: {
          identity: payload.identity,
          key: payload.key,
          signature: payload.signature,
          sessions: sessions as WireSession[],
        },
      };
    }
    return null;
  }

  if (type === "message") {
    if (
      hasOnly(value, ["type", "payload"]) &&
      hasOnly(payload, [
        "id",
        "from",
        "key",
        "signature",
        "sender",
        "envelope",
      ]) &&
      isValidId(payload.id) &&
      isIdentity(payload.from) &&
      isFixed(payload.key, exchangeKeySize) &&
      isFixed(payload.signature, signatureSize)
    ) {
      const sender = parseSession(payload.sender);
      const envelope = parseEnvelope(payload.envelope);
      if (!sender || !envelope) {
        return null;
      }
      return {
        type,
        payload: {
          id: payload.id,
          from: payload.from,
          key: payload.key,
          signature: payload.signature,
          sender,
          envelope,
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
