import type { Availability, Connection, Phase } from "./application.ts";
import type {
  ConversationMessage,
  DeliveryState,
  SendAttempt,
} from "./conversations.ts";
import { isIdentity } from "./identity.ts";
import type { PeerAuthorization } from "./peer.ts";
import type { PresenceState } from "./presence.ts";
import { bodySize, maxBodySize } from "./protocol.ts";
import type { PairingState } from "./session.ts";
import type { TransportError, TransportKind } from "./transport.ts";
import type { TrustState } from "./trust.ts";

export type Tone = "neutral" | "progress" | "success" | "warning" | "danger";

export type View = {
  label: string;
  detail: string;
  tone: Tone;
  symbol: string;
};

export type Section = "messages" | "devices" | "connection";

export const sections: { id: Section; label: string }[] = [
  { id: "messages", label: "Messages" },
  { id: "devices", label: "Devices" },
  { id: "connection", label: "Connection" },
];

export function phaseView(phase: Phase): View | null {
  switch (phase.phase) {
    case "initializing":
      return {
        label: "Opening your identity",
        detail: "Loading keys and history stored on this device.",
        tone: "progress",
        symbol: "…",
      };
    case "waiting":
      return {
        label: "Ghost X is open in another tab",
        detail:
          "Only one tab at a time can use this device's keys. This tab has not loaded them and will take over automatically when the other tab closes.",
        tone: "warning",
        symbol: "○",
      };
    case "fatal":
      if (phase.reason === "unsupported") {
        return {
          label: "This browser is not supported",
          detail:
            "Ghost X needs the Web Locks API to make sure only one tab uses your keys at a time. Use a current version of Chrome, Edge, Firefox or Safari.",
          tone: "danger",
          symbol: "!",
        };
      }
      return phase.reason === "storage_unavailable"
        ? {
            label: "Secure storage is unavailable",
            detail:
              "This browser is blocking the storage Ghost X needs for your keys, for example in a private window. Open Ghost X in a regular window to continue.",
            tone: "danger",
            symbol: "!",
          }
        : {
            label: "Your stored identity could not be restored",
            detail:
              "The data on this device failed its integrity checks. Resetting deletes this identity and its history from this browser.",
            tone: "danger",
            symbol: "!",
          };
    case "no_identity":
      return null;
    default:
      return null;
  }
}

const connectionViews: Record<Connection["status"], View> = {
  unavailable: {
    label: "Unavailable",
    detail: "The selected transport cannot run on this device.",
    tone: "warning",
    symbol: "○",
  },
  connecting: {
    label: "Connecting",
    detail: "Opening a connection over the selected transport.",
    tone: "progress",
    symbol: "…",
  },
  reconnecting: {
    label: "Reconnecting",
    detail: "The connection dropped. Trying again over the same transport.",
    tone: "progress",
    symbol: "…",
  },
  disconnected: {
    label: "Not connected",
    detail: "There is no connection over the selected transport.",
    tone: "warning",
    symbol: "○",
  },
  authenticating: {
    label: "Authenticating",
    detail: "Connected. Proving this device's identity.",
    tone: "progress",
    symbol: "…",
  },
  authenticated: {
    label: "Connected",
    detail: "Connected and authenticated as this device.",
    tone: "success",
    symbol: "●",
  },
  rejected: {
    label: "Authentication failed",
    detail: "The other side did not accept this device's proof of identity.",
    tone: "danger",
    symbol: "!",
  },
  pending: {
    label: "Awaiting authorization",
    detail:
      "This device is linked to an identity but has not been authorized yet.",
    tone: "warning",
    symbol: "○",
  },
  revoked: {
    label: "Device revoked",
    detail: "This device has been removed from its identity.",
    tone: "danger",
    symbol: "!",
  },
};

export function connectionView(connection: Connection): View {
  return connectionViews[connection.status];
}

const waiting = "Your history is available, but sending waits for a connection.";

const connectionImpacts: Record<
  Exclude<Connection["status"], "authenticated">,
  string
> = {
  unavailable:
    "Your history is available, but messages cannot be sent until you select a transport that works on this device.",
  connecting: waiting,
  reconnecting: waiting,
  disconnected: waiting,
  authenticating: waiting,
  rejected:
    "Your history is available, but messages cannot be sent until this device is accepted.",
  pending:
    "Your history is available, but this device cannot send messages until it is authorized.",
  revoked: "This device can no longer send or receive messages.",
};

export function connectionImpact(connection: Connection): string | null {
  return connection.status === "authenticated"
    ? null
    : connectionImpacts[connection.status];
}

const transportErrors: Record<TransportError, string> = {
  unavailable: "This transport is not available on this device.",
  failed: "The connection could not be opened.",
  lost: "The connection was lost.",
  timeout: "The connection timed out.",
  oversized: "An oversized frame was dropped.",
  malformed: "A malformed frame was dropped.",
};

export function transportError(error: TransportError): string {
  return transportErrors[error];
}

export function transportView(
  kind: TransportKind,
  availability: Availability,
): View & { name: string } {
  if (kind === "websocket") {
    return availability === "available"
      ? {
          name: "Internet",
          label: "Available",
          detail:
            "Relays end-to-end encrypted messages through the Ghost X server, which also queues them while recipients are offline.",
          tone: "neutral",
          symbol: "●",
        }
      : {
          name: "Internet",
          label: "Not configured",
          detail: "No server address is configured for this build.",
          tone: "warning",
          symbol: "○",
        };
  }
  return availability === "available"
    ? {
        name: "Local link",
        label: "Available",
        detail:
          "Talks directly to one nearby device without the server. Nothing is queued while that device is away.",
        tone: "neutral",
        symbol: "●",
      }
    : {
        name: "Local link",
        label: "Not available on this device",
        detail:
          "Direct device-to-device links need a platform carrier, and this browser does not provide one. Selecting it will not fall back to the Internet.",
        tone: "warning",
        symbol: "○",
      };
}

export type Reachability = "online" | "offline" | "unknown";

export function presenceOf(
  presence: PresenceState,
  identity: string,
): Reachability {
  if (presence.status !== "active") {
    return "unknown";
  }
  return presence.identities.includes(identity) ? "online" : "offline";
}

const reachabilityViews: Record<Reachability, View> = {
  online: {
    label: "Online",
    detail: "Connected to the server right now.",
    tone: "success",
    symbol: "●",
  },
  offline: {
    label: "Offline",
    detail:
      "Not connected to the server. Messages wait in the server's encrypted queue.",
    tone: "neutral",
    symbol: "○",
  },
  unknown: {
    label: "Presence unknown",
    detail: "Presence is only available while connected over the Internet.",
    tone: "neutral",
    symbol: "?",
  },
};

export function reachabilityView(reachability: Reachability): View {
  return reachabilityViews[reachability];
}

const trustViews: Record<TrustState, View> = {
  verified: {
    label: "Verified",
    detail: "You compared and confirmed this identity's fingerprint.",
    tone: "success",
    symbol: "✓",
  },
  unverified: {
    label: "Not verified",
    detail:
      "Messages are end-to-end encrypted, but you have not confirmed who holds this identity. Compare fingerprints over a channel you trust.",
    tone: "neutral",
    symbol: "○",
  },
  changed: {
    label: "Identity changed",
    detail:
      "This identity's devices or keys changed since you verified it. Compare the new fingerprint before trusting this conversation.",
    tone: "danger",
    symbol: "!",
  },
  unavailable: {
    label: "Cannot check",
    detail:
      "This identity's current device list is not available, so its fingerprint cannot be shown.",
    tone: "warning",
    symbol: "?",
  },
};

export function trustView(state: TrustState): View {
  return trustViews[state];
}

export function conversationTrust(state: TrustState): View | null {
  return state === "verified" || state === "changed" ? trustViews[state] : null;
}

export function conversationPreview(
  message: ConversationMessage | undefined,
): string {
  if (!message) {
    return "No messages yet";
  }
  if (message.body === null) {
    return "Could not be decrypted";
  }
  const text = message.body.slice(0, 60);
  return message.direction === "sent" ? `You: ${text}` : text;
}

const deliveryViews: Record<DeliveryState, View> = {
  sending: {
    label: "Sending",
    detail: "Encrypting and handing the message to the selected transport.",
    tone: "progress",
    symbol: "…",
  },
  pending: {
    label: "Held on this device",
    detail:
      "Encrypted and stored here until a secure session with the recipient exists.",
    tone: "progress",
    symbol: "◔",
  },
  queued: {
    label: "Accepted for delivery",
    detail:
      "Encrypted and accepted by the relay. The recipient's device has not confirmed it yet.",
    tone: "neutral",
    symbol: "✓",
  },
  delivered: {
    label: "Delivered",
    detail: "The recipient's device confirmed it received the message.",
    tone: "success",
    symbol: "✓✓",
  },
  expired: {
    label: "Not delivered",
    detail: "It expired before the recipient's device came online.",
    tone: "danger",
    symbol: "!",
  },
  unavailable: {
    label: "Not delivered",
    detail: "The recipient is not available to receive messages.",
    tone: "danger",
    symbol: "!",
  },
  failed: {
    label: "Not sent",
    detail:
      "The message could not be sent. Check the connection and try again.",
    tone: "danger",
    symbol: "!",
  },
};

export function deliveryView(state: DeliveryState): View {
  return deliveryViews[state];
}

export const undecryptable: View = {
  label: "Could not be decrypted",
  detail:
    "A message arrived but failed authentication, so its contents are not shown.",
  tone: "danger",
  symbol: "!",
};

const pairingViews: Record<Exclude<PairingState, "none">, View> = {
  pending: {
    label: "Securing session",
    detail:
      "A secure session starts once this identity's device responds. Messages are held until then.",
    tone: "progress",
    symbol: "◔",
  },
  established: {
    label: "Secure session",
    detail: "An end-to-end encrypted session with this identity is ready.",
    tone: "success",
    symbol: "●",
  },
  unavailable: {
    label: "No keys published",
    detail:
      "This identity has not published keys yet, so a secure session cannot start.",
    tone: "warning",
    symbol: "○",
  },
  invalid_bundle: {
    label: "Keys failed verification",
    detail:
      "The keys offered for this identity did not verify, so no session was started.",
    tone: "danger",
    symbol: "!",
  },
  failed: {
    label: "Session not started",
    detail: "A secure session could not be started. Try again later.",
    tone: "warning",
    symbol: "!",
  },
};

export function pairingView(state: PairingState | null): View | null {
  return state && state !== "none" ? pairingViews[state] : null;
}

export function authorizationView(authorization: PeerAuthorization): View {
  return authorization.basis === "confirmed"
    ? {
        label: "Device list confirmed by the server",
        detail:
          "The device list this peer presented matches the one last confirmed through the server. Revocations made since then are not known here.",
        tone: "neutral",
        symbol: "✓",
      }
    : {
        label: "Device list not confirmed",
        detail:
          "The server has not confirmed this peer's device list, so a revocation this device has not received cannot be detected.",
        tone: "warning",
        symbol: "!",
      };
}

export function recipientError(value: string, self: string): string | null {
  const identity = value.trim();
  if (!identity) {
    return "Enter the identity you want to message.";
  }
  if (!isIdentity(identity)) {
    return "That is not a valid Ghost X identity. Identities are 43 characters long.";
  }
  if (identity === self) {
    return "That is your own identity.";
  }
  return null;
}

export function linkError(value: string): string | null {
  const identity = value.trim();
  if (!identity) {
    return "Enter the identity this device should join.";
  }
  return isIdentity(identity)
    ? null
    : "That is not a valid Ghost X identity. Identities are 43 characters long.";
}

const rejections: Record<
  Extract<SendAttempt, { accepted: false }>["reason"],
  string
> = {
  no_conversation: "Choose a conversation first.",
  authentication_required:
    "Not connected. Messages can be sent once connected.",
  invalid_payload: "This message contains characters that cannot be sent.",
  message_too_large: "This message is too long to send.",
};

export function rejectionMessage(
  reason: Extract<SendAttempt, { accepted: false }>["reason"],
): string {
  return rejections[reason];
}

export function composerState(body: string): {
  bytes: number;
  max: number;
  tooLarge: boolean;
  nearLimit: boolean;
} {
  const bytes = bodySize(body);
  return {
    bytes,
    max: maxBodySize,
    tooLarge: bytes > maxBodySize,
    nearLimit: bytes > maxBodySize * 0.8,
  };
}

export function shortIdentifier(value: string): string {
  return value.length > 16 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

export function groupDigits(digits: string): string[] {
  return digits.split(/\s+/).filter(Boolean);
}
