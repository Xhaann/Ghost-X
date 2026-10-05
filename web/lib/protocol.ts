import { decodeBase64Url } from "./base64.ts";
import { isIdentity } from "./identity.ts";

export type ErrorCode =
  | "invalid_message"
  | "unsupported_type"
  | "invalid_payload"
  | "authentication_required"
  | "authentication_failed"
  | "internal_error";

export type ClientMessage =
  | { type: "ping"; payload: { sentAt: number } }
  | { type: "challenge"; payload: Record<string, never> }
  | { type: "authenticate"; payload: { identity: string; signature: string } }
  | { type: "whoami"; payload: Record<string, never> };

export type ServerMessage =
  | {
      type: "pong";
      id: string;
      payload: { sentAt: number; receivedAt: number };
    }
  | { type: "challenge"; id: string; payload: { nonce: string } }
  | { type: "authenticated"; id: string; payload: { identity: string } }
  | { type: "whoami"; id: string; payload: { identity: string } }
  | { type: "error"; id?: string; payload: { code: ErrorCode } };

export const nonceSize = 32;

const errorCodes: readonly string[] = [
  "invalid_message",
  "unsupported_type",
  "invalid_payload",
  "authentication_required",
  "authentication_failed",
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

function isValidId(value: unknown): value is string {
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
