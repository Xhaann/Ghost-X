import type { AuthState } from "./auth.ts";
import type {
  TransportError,
  TransportKind,
  TransportState,
} from "./transport.ts";

export type Connection =
  | { status: "unavailable" }
  | { status: "connecting" }
  | { status: "reconnecting" }
  | { status: "disconnected"; reason: TransportError | null }
  | { status: "authenticating" }
  | { status: "authenticated" }
  | { status: "rejected" }
  | { status: "pending" }
  | { status: "revoked" };

export type Availability = "available" | "unavailable";

export type Capabilities = {
  url: string | undefined;
  websocket: boolean;
  link: boolean;
};

export type LocalStatus =
  "loading" | "unavailable" | "corrupted" | "empty" | "ready";

export type Phase =
  | { phase: "initializing" }
  | { phase: "fatal"; reason: "storage_unavailable" | "corrupted" }
  | { phase: "no_identity" }
  | { phase: "ready" };

export function connectionOf(
  transport: TransportState,
  error: TransportError | null,
  auth: AuthState,
): Connection {
  if (auth === "revoked") {
    return { status: "revoked" };
  }
  if (auth === "pending") {
    return { status: "pending" };
  }
  if (auth === "failed") {
    return { status: "rejected" };
  }
  switch (transport) {
    case "connected":
      return auth === "authenticated"
        ? { status: "authenticated" }
        : { status: "authenticating" };
    case "connecting":
      return { status: "connecting" };
    case "reconnecting":
      return { status: "reconnecting" };
    default:
      return error === "unavailable"
        ? { status: "unavailable" }
        : { status: "disconnected", reason: error };
  }
}

export function availability(
  kind: TransportKind,
  capabilities: Capabilities,
): Availability {
  if (kind === "websocket") {
    return capabilities.websocket && !!capabilities.url
      ? "available"
      : "unavailable";
  }
  return capabilities.link ? "available" : "unavailable";
}

export function phaseOf(status: LocalStatus): Phase {
  switch (status) {
    case "loading":
      return { phase: "initializing" };
    case "unavailable":
      return { phase: "fatal", reason: "storage_unavailable" };
    case "corrupted":
      return { phase: "fatal", reason: "corrupted" };
    case "empty":
      return { phase: "no_identity" };
    default:
      return { phase: "ready" };
  }
}
