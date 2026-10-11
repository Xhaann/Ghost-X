"use client";

import { useEffect, useState } from "react";
import type { Availability, Connection } from "@/lib/application.ts";
import type { PingResult, Session, SessionState } from "@/lib/session.ts";
import type { TransportError, TransportKind } from "@/lib/transport.ts";

const connectionLabels: Record<Connection["status"], string> = {
  unavailable: "Not available on this device",
  connecting: "Connecting",
  reconnecting: "Reconnecting",
  disconnected: "Not connected",
  authenticating: "Connected, authenticating",
  authenticated: "Connected and authenticated",
  rejected: "Connected, but authentication failed",
  pending: "Connected, waiting for this device to be authorized",
  revoked: "This device is no longer authorized",
};

const errors: Record<TransportError, string> = {
  unavailable: "This transport is not available on this device",
  failed: "Connection failed",
  lost: "Connection lost",
  timeout: "Connection timed out",
  oversized: "An oversized frame was dropped",
  malformed: "A malformed frame was dropped",
};

const transports: { kind: TransportKind; label: string }[] = [
  { kind: "websocket", label: "Internet" },
  { kind: "local", label: "Local link" },
];

export default function Status({
  kind,
  availability,
  session,
  state,
  select,
}: {
  kind: TransportKind;
  availability: Record<TransportKind, Availability>;
  session: Session | null;
  state: SessionState | null;
  select: (kind: TransportKind) => void;
}) {
  const [result, setResult] = useState<PingResult | null>(null);

  useEffect(() => {
    setResult(null);
  }, [session]);

  const ping = () => {
    if (!session) {
      return;
    }
    void session.ping().then((value) => {
      if (!session.disposed) {
        setResult(value);
      }
    });
  };

  return (
    <section>
      <div role="group" aria-label="Transport" data-transport={kind}>
        {transports.map((t) => (
          <button
            key={t.kind}
            type="button"
            aria-pressed={kind === t.kind}
            data-availability={availability[t.kind]}
            disabled={!session}
            onClick={() => select(t.kind)}
          >
            {t.label}
            {availability[t.kind] === "unavailable" &&
              " (not available on this device)"}
          </button>
        ))}
      </div>
      {state && (
        <>
          <p
            role="status"
            data-transport-state={state.transport}
            data-connection={state.connection.status}
          >
            {connectionLabels[state.connection.status]}
          </p>
          {state.error && (
            <p data-transport-error={state.error}>{errors[state.error]}</p>
          )}
          {kind === "websocket" && (
            <button
              type="button"
              onClick={ping}
              disabled={state.transport !== "connected"}
            >
              Ping
            </button>
          )}
          {result && (
            <output>
              {result.ok ? `Round trip ${result.roundTrip} ms` : "Ping failed"}
            </output>
          )}
        </>
      )}
    </section>
  );
}
