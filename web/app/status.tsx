"use client";

import type {
  TransportError,
  TransportKind,
  TransportState,
} from "@/lib/transport.ts";
import { useClient } from "@/lib/useClient.ts";
import { usePing } from "@/lib/usePing.ts";
import Identity from "./identity";

const labels: Record<TransportState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  reconnecting: "Reconnecting",
  error: "Not connected",
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

export default function Status({ url }: { url: string | undefined }) {
  const { state, error, kind, client, select } = useClient(url);
  const { ping, result } = usePing(client);

  return (
    <>
      <section>
        <div role="group" aria-label="Transport" data-transport={kind}>
          {transports.map((t) => (
            <button
              key={t.kind}
              type="button"
              aria-pressed={kind === t.kind}
              disabled={!client}
              onClick={() => select(t.kind)}
            >
              {t.label}
            </button>
          ))}
        </div>
        <p role="status" data-transport-state={state}>
          {labels[state]}
        </p>
        {error && <p data-transport-error={error}>{errors[error]}</p>}
        <button type="button" onClick={ping} disabled={state !== "connected"}>
          Ping
        </button>
        {result && (
          <output>
            {result.ok ? `Round trip ${result.roundTrip} ms` : "Ping failed"}
          </output>
        )}
      </section>
      <Identity client={client} />
    </>
  );
}
