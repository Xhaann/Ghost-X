import { useEffect, useState } from "react";
import { type AuthState, Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import type { IdentityKey } from "./identity.ts";

export function useAuth(
  client: Client | null,
  key: IdentityKey | null,
): AuthState {
  const [state, setState] = useState<AuthState>("unauthenticated");

  useEffect(() => {
    if (!client || !key) {
      return;
    }
    const authenticator = new Authenticator(client, key);
    const unsubscribe = authenticator.onState(setState);
    authenticator.start();

    return () => {
      unsubscribe();
      authenticator.stop();
      setState("unauthenticated");
    };
  }, [client, key]);

  return state;
}
