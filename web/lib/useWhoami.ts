import { useCallback, useEffect, useRef, useState } from "react";
import type { AuthState } from "./auth.ts";
import type { Client } from "./client.ts";

export type WhoamiResult =
  { ok: true; identity: string } | { ok: false; required: boolean };

export function useWhoami(
  client: Client | null,
  auth: AuthState,
): { query: () => void; result: WhoamiResult | null } {
  const [result, setResult] = useState<WhoamiResult | null>(null);
  const attempt = useRef(0);

  useEffect(() => {
    attempt.current += 1;
    setResult(null);
  }, [client, auth]);

  const query = useCallback(() => {
    if (!client) {
      return;
    }
    const current = ++attempt.current;
    client.request({ type: "whoami", payload: {} }).then((reply) => {
      if (attempt.current !== current) {
        return;
      }
      if (reply?.type === "whoami") {
        setResult({ ok: true, identity: reply.payload.identity });
      } else {
        setResult({
          ok: false,
          required:
            reply?.type === "error" &&
            reply.payload.code === "authentication_required",
        });
      }
    });
  }, [client]);

  return { query, result };
}
