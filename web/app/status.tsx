"use client";

import { useEffect, useState } from "react";

type State = "connecting" | "connected" | "disconnected" | "unavailable";

const labels: Record<State, string> = {
  connecting: "Connecting",
  connected: "Connected",
  disconnected: "Disconnected",
  unavailable: "Unavailable",
};

const minDelay = 1000;
const maxDelay = 30000;

export default function Status({ url }: { url: string | undefined }) {
  const [state, setState] = useState<State>(url ? "connecting" : "unavailable");

  useEffect(() => {
    if (!url) {
      return;
    }

    let socket: WebSocket | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let delay = minDelay;
    let active = true;

    const connect = () => {
      try {
        socket = new WebSocket(url);
      } catch {
        setState("unavailable");
        return;
      }
      setState("connecting");
      socket.onopen = () => {
        delay = minDelay;
        setState("connected");
      };
      socket.onclose = () => {
        if (!active) {
          return;
        }
        setState("disconnected");
        timer = setTimeout(connect, delay);
        delay = Math.min(delay * 2, maxDelay);
      };
    };

    connect();

    return () => {
      active = false;
      clearTimeout(timer);
      socket?.close();
    };
  }, [url]);

  return <p role="status">{labels[state]}</p>;
}
