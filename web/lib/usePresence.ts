import { useEffect, useState } from "react";
import type { Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import { Presence, type PresenceState } from "./presence.ts";

const inactive: PresenceState = { status: "inactive", identities: [] };

export function usePresence(
  client: Client | null,
  authenticator: Authenticator | null,
): PresenceState {
  const [state, setState] = useState<PresenceState>(inactive);

  useEffect(() => {
    if (!client || !authenticator) {
      return;
    }
    const presence = new Presence(client, authenticator);
    const unsubscribe = presence.onState(setState);
    presence.start();

    return () => {
      unsubscribe();
      presence.stop();
      setState(inactive);
    };
  }, [client, authenticator]);

  return state;
}
