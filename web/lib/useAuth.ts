import { useEffect, useState } from "react";
import { type AuthState, Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import type { LocalSession } from "./useIdentity.ts";

export function useAuth(
  client: Client | null,
  session: LocalSession | null,
): { state: AuthState; authenticator: Authenticator | null } {
  const [state, setState] = useState<AuthState>("unauthenticated");
  const [authenticator, setAuthenticator] = useState<Authenticator | null>(
    null,
  );

  useEffect(() => {
    if (!client || !session) {
      return;
    }
    const authenticator = new Authenticator(
      client,
      session.keys,
      session.devices,
    );
    const unsubscribe = authenticator.onState(setState);
    setAuthenticator(authenticator);
    authenticator.start();

    return () => {
      unsubscribe();
      authenticator.stop();
      setState("unauthenticated");
      setAuthenticator(null);
    };
  }, [client, session]);

  return { state, authenticator };
}
