import { useCallback, useEffect, useRef, useState } from "react";
import type { Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import {
  Conversations,
  type ConversationsState,
  type SendAttempt,
} from "./conversations.ts";
import { Messenger } from "./messenger.ts";

const empty: ConversationsState = {
  connected: false,
  active: null,
  conversations: [],
};

export function useConversations(
  client: Client | null,
  authenticator: Authenticator | null,
  self: string | null,
): {
  state: ConversationsState;
  open: (identity: string) => boolean;
  close: () => void;
  send: (body: string) => SendAttempt;
} {
  const [state, setState] = useState<ConversationsState>(empty);
  const store = useRef<Conversations | null>(null);

  useEffect(() => {
    if (!client || !authenticator || !self) {
      return;
    }
    const messenger = new Messenger(client, authenticator);
    const conversations = new Conversations(messenger, self);
    store.current = conversations;
    const unsubscribe = conversations.onState(setState);
    messenger.start();
    conversations.start();

    return () => {
      unsubscribe();
      conversations.stop();
      messenger.stop();
      if (store.current === conversations) {
        store.current = null;
      }
      setState(empty);
    };
  }, [client, authenticator, self]);

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

  return { state, open, close, send };
}
