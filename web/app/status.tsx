"use client";

import type { SocketState } from "@/lib/socket.ts";
import { useSocket } from "@/lib/useSocket.ts";

const labels: Record<SocketState, string> = {
  disconnected: "Disconnected",
  connecting: "Connecting",
  connected: "Connected",
  reconnecting: "Reconnecting",
};

export default function Status({ url }: { url: string | undefined }) {
  const state = useSocket(url);
  return <p role="status">{labels[state]}</p>;
}
