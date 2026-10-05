import { useCallback, useEffect, useRef, useState } from "react";
import type { Client } from "./client.ts";
import type { IdentityKey } from "./identity.ts";
import { proveIdentity } from "./proof.ts";

export function useProof(
  client: Client | null,
  key: IdentityKey | null,
): { prove: () => void; proven: boolean | null; pending: boolean } {
  const [proven, setProven] = useState<boolean | null>(null);
  const [pending, setPending] = useState(false);
  const attempt = useRef(0);

  useEffect(() => {
    const reset = () => {
      attempt.current += 1;
      setProven(null);
      setPending(false);
    };
    reset();
    return client?.onState((state) => {
      if (state !== "connected") {
        reset();
      }
    });
  }, [client, key]);

  const prove = useCallback(() => {
    if (!client || !key) {
      return;
    }
    const current = ++attempt.current;
    setPending(true);
    proveIdentity(client, key).then(
      (result) => {
        if (attempt.current === current) {
          setProven(result);
          setPending(false);
        }
      },
      () => {
        if (attempt.current === current) {
          setProven(false);
          setPending(false);
        }
      },
    );
  }, [client, key]);

  return { prove, proven, pending };
}
