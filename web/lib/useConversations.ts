import { useCallback, useEffect, useRef, useState } from "react";
import type { Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import {
  Conversations,
  type ConversationsState,
  type SendAttempt,
} from "./conversations.ts";
import { Messenger } from "./messenger.ts";
import type { LocalSession } from "./useIdentity.ts";

const empty: ConversationsState = {
  connected: false,
  active: null,
  conversations: [],
};

export function useConversations(
  client: Client | null,
  authenticator: Authenticator | null,
  session: LocalSession | null,
): {
  state: ConversationsState;
  rejected: number;
  open: (identity: string) => boolean;
  close: () => void;
  send: (body: string) => SendAttempt;
} {
  const [state, setState] = useState<ConversationsState>(empty);
  const [rejected, setRejected] = useState(0);
  const store = useRef<Conversations | null>(null);

  useEffect(() => {
    if (!client || !authenticator || !session) {
      return;
    }
    let active = true;
    let teardown: (() => void) | null = null;
    const { keys, history } = session;

    history.restore().then(({ restored, rejected }) => {
      if (!active) {
        return;
      }
      setRejected(rejected);
      const messenger = new Messenger(
        client,
        authenticator,
        keys.identity,
        keys.exchange,
      );
      const conversations = new Conversations(
        messenger,
        keys.identity.identity,
        { history, restored },
      );
      store.current = conversations;
      const unsubscribe = conversations.onState(setState);
      messenger.start();
      conversations.start();
      teardown = () => {
        unsubscribe();
        conversations.stop();
        messenger.stop();
        if (store.current === conversations) {
          store.current = null;
        }
      };
    });

    return () => {
      active = false;
      teardown?.();
      setState(empty);
      setRejected(0);
    };
  }, [client, authenticator, session]);

  const open = useCallback(
    (identity: string) => store.current?.open(identity) ?? false,
    [],
  );
  const close = useCallback(() => store.current?.close(), []);
  const send = useCallback(
    (body: string): SendAttempt =>
      store.current?.send(body) ?? {
        accepted: false,
        reason: "authentication_required",
      },
    [],
  );

  return { state, rejected, open, close, send };
}
