import { useCallback, useEffect, useRef, useState } from "react";
import type { Client } from "./client.ts";
import type { ErrorCode } from "./protocol.ts";

export type PingResult =
  { ok: true; roundTrip: number } | { ok: false; code: ErrorCode };

export function usePing(client: Client | null): {
  ping: () => void;
  result: PingResult | null;
} {
  const [result, setResult] = useState<PingResult | null>(null);
  const pending = useRef<string | null>(null);

  useEffect(() => {
    if (!client) {
      return;
    }

    const unsubscribe = client.onMessage((message) => {
      if (message.id === undefined || message.id !== pending.current) {
        return;
      }
      pending.current = null;
      if (message.type === "pong") {
        setResult({
          ok: true,
          roundTrip: Math.max(0, Date.now() - message.payload.sentAt),
        });
      } else if (message.type === "error") {
        setResult({ ok: false, code: message.payload.code });
      }
    });

    return () => {
      unsubscribe();
      pending.current = null;
    };
  }, [client]);

  const ping = useCallback(() => {
    pending.current =
      client?.send({ type: "ping", payload: { sentAt: Date.now() } }) ?? null;
  }, [client]);

  return { ping, result };
}
