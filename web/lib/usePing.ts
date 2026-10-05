import { useCallback, useEffect, useRef, useState } from "react";
import type { ErrorCode } from "./protocol.ts";
import type { Socket } from "./socket.ts";

export type PingResult =
  { ok: true; roundTrip: number } | { ok: false; code: ErrorCode };

export function usePing(socket: Socket | null): {
  ping: () => void;
  result: PingResult | null;
} {
  const [result, setResult] = useState<PingResult | null>(null);
  const pending = useRef<string | null>(null);

  useEffect(() => {
    if (!socket) {
      return;
    }

    const unsubscribe = socket.onMessage((message) => {
      if (message.id === undefined || message.id !== pending.current) {
        return;
      }
      pending.current = null;
      setResult(
        message.type === "pong"
          ? {
              ok: true,
              roundTrip: Math.max(0, Date.now() - message.payload.sentAt),
            }
          : { ok: false, code: message.payload.code },
      );
    });

    return () => {
      unsubscribe();
      pending.current = null;
    };
  }, [socket]);

  const ping = useCallback(() => {
    pending.current =
      socket?.send({ type: "ping", payload: { sentAt: Date.now() } }) ?? null;
  }, [socket]);

  return { ping, result };
}
