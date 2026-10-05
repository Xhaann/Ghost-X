import { useEffect, useState } from "react";
import { type AuthState, Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import type { IdentityKey } from "./identity.ts";

export function useAuth(
  client: Client | null,
  key: IdentityKey | null,
): { state: AuthState; authenticator: Authenticator | null } {
  const [state, setState] = useState<AuthState>("unauthenticated");
  const [authenticator, setAuthenticator] = useState<Authenticator | null>(
    null,
  );

  useEffect(() => {
    if (!client || !key) {
      return;
    }
    const authenticator = new Authenticator(client, key);
    const unsubscribe = authenticator.onState(setState);
    setAuthenticator(authenticator);
    authenticator.start();

    return () => {
      unsubscribe();
      authenticator.stop();
      setState("unauthenticated");
      setAuthenticator(null);
    };
  }, [client, key]);

  return { state, authenticator };
}
