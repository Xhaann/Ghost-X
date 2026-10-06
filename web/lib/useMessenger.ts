import { useCallback, useEffect, useRef, useState } from "react";
import type { Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import {
  Messenger,
  type MessengerState,
  type SendResult,
} from "./messenger.ts";

const inactive: MessengerState = { active: false, received: [] };

export function useMessenger(
  client: Client | null,
  authenticator: Authenticator | null,
): {
  state: MessengerState;
  send: (to: string, body: string) => Promise<SendResult>;
} {
  const [state, setState] = useState<MessengerState>(inactive);
  const messenger = useRef<Messenger | null>(null);

  useEffect(() => {
    if (!client || !authenticator) {
      return;
    }
    const instance = new Messenger(client, authenticator);
    messenger.current = instance;
    const unsubscribe = instance.onState(setState);
    instance.start();

    return () => {
      unsubscribe();
      instance.stop();
      if (messenger.current === instance) {
        messenger.current = null;
      }
      setState(inactive);
    };
  }, [client, authenticator]);

  const send = useCallback(
    (to: string, body: string): Promise<SendResult> =>
      messenger.current
        ? messenger.current.send(to, body)
        : Promise.resolve({ ok: false, reason: "authentication_required" }),
    [],
  );

  return { state, send };
}
