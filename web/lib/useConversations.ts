import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import {
  Conversations,
  type ConversationsState,
  type SendAttempt,
} from "./conversations.ts";
import { Messenger } from "./messenger.ts";
import type { TrustState, TrustView } from "./trust.ts";
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
  verification: TrustView | null;
  trustOf: (identity: string) => TrustState;
  verify: (value: string) => Promise<boolean>;
} {
  const [state, setState] = useState<ConversationsState>(empty);
  const [rejected, setRejected] = useState(0);
  const [trustVersion, setTrustVersion] = useState(0);
  const store = useRef<Conversations | null>(null);
  const messengerRef = useRef<Messenger | null>(null);

  useEffect(() => {
    if (!client || !authenticator || !session) {
      return;
    }
    let active = true;
    let teardown: (() => void) | null = null;
    const { keys, history, trust } = session;
    const untrust = trust.onChange(() => setTrustVersion((v) => v + 1));

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
      messengerRef.current = messenger;
      const unkey = messenger.onKey((bundle) => void trust.observe(bundle));
      const unsubscribe = conversations.onState(setState);
      messenger.start();
      conversations.start();
      teardown = () => {
        unsubscribe();
        unkey();
        conversations.stop();
        messenger.stop();
        if (store.current === conversations) {
          store.current = null;
        }
        if (messengerRef.current === messenger) {
          messengerRef.current = null;
        }
      };
    });

    return () => {
      active = false;
      untrust();
      teardown?.();
      setState(empty);
      setRejected(0);
    };
  }, [client, authenticator, session]);

  useEffect(() => {
    if (!session || !state.active || !state.connected) {
      return;
    }
    void session.trust.refresh(state.active);
    void messengerRef.current?.lookup(state.active);
  }, [session, state.active, state.connected]);

  const verification = useMemo(
    () =>
      session && state.active && trustVersion >= 0
        ? session.trust.view(state.active)
        : null,
    [session, state.active, trustVersion],
  );
  const trustOf = useCallback(
    (identity: string): TrustState =>
      session && trustVersion >= 0
        ? session.trust.view(identity).state
        : "unavailable",
    [session, trustVersion],
  );
  const verify = useCallback(
    async (value: string) =>
      session && state.active
        ? session.trust.verify(state.active, value)
        : false,
    [session, state.active],
  );

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

  return {
    state,
    rejected,
    open,
    close,
    send,
    verification,
    trustOf,
    verify,
  };
}
