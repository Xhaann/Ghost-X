"use client";

import type { SocketState } from "@/lib/socket.ts";
import { usePing } from "@/lib/usePing.ts";
import { useSocket } from "@/lib/useSocket.ts";

const labels: Record<SocketState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  reconnecting: "Reconnecting",
};

export default function Status({ url }: { url: string | undefined }) {
  const { state, socket } = useSocket(url);
  const { ping, result } = usePing(socket);

  return (
    <section>
      <p role="status">{labels[state]}</p>
      <button type="button" onClick={ping} disabled={state !== "connected"}>
        Ping
      </button>
      {result && (
        <output>
          {result.ok ? `Round trip ${result.roundTrip} ms` : "Ping failed"}
        </output>
      )}
    </section>
  );
}
