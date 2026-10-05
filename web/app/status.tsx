"use client";

import type { TransportError, TransportState } from "@/lib/transport.ts";
import { useClient } from "@/lib/useClient.ts";
import { usePing } from "@/lib/usePing.ts";
import Identity from "./identity";

const labels: Record<TransportState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  reconnecting: "Reconnecting",
};

const errors: Record<TransportError, string> = {
  unavailable: "Unavailable",
  lost: "Connection lost",
};

export default function Status({ url }: { url: string | undefined }) {
  const { state, error, client } = useClient(url);
  const { ping, result } = usePing(client);

  return (
    <>
      <section>
        <p role="status">{labels[state]}</p>
        {error && <p>{errors[error]}</p>}
        <button type="button" onClick={ping} disabled={state !== "connected"}>
          Ping
        </button>
        {result && (
          <output>
            {result.ok ? `Round trip ${result.roundTrip} ms` : "Ping failed"}
          </output>
        )}
      </section>
      <Identity client={client} connected={state === "connected"} />
    </>
  );
}
