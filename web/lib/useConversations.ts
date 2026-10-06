import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Authenticator } from "./auth.ts";
import type { Client } from "./client.ts";
import {
  Conversations,
  type ConversationsState,
  type SendAttempt,
} from "./conversations.ts";
import { requestDeviceLock } from "./lock.ts";
import { Messenger } from "./messenger.ts";
import type { PairState } from "./pairs.ts";
import { type InitiateResult, Pairing } from "./pairing.ts";
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
  pairing: PairState | InitiateResult | null;
  locked: boolean;
} {
  const [state, setState] = useState<ConversationsState>(empty);
  const [rejected, setRejected] = useState(0);
  const [trustVersion, setTrustVersion] = useState(0);
  const store = useRef<Conversations | null>(null);
  const messengerRef = useRef<Messenger | null>(null);
  const pairingRef = useRef<Pairing | null>(null);
  const [pairVersion, setPairVersion] = useState(0);
  const [locked, setLocked] = useState(false);
  const [attempt, setAttempt] = useState<{
    peer: string;
    result: InitiateResult;
  } | null>(null);

  useEffect(() => {
    if (!client || !authenticator || !session) {
      return;
    }
    let active = true;
    let teardown: (() => void) | null = null;
    const { keys, history, trust } = session;
    const untrust = trust.onChange(() => setTrustVersion((v) => v + 1));
    const unpair = session.pairs.onChange(() => setPairVersion((v) => v + 1));

    const controller = new AbortController();
    let release: (() => void) | null = null;
    const waiting = setTimeout(() => {
      if (active) {
        setLocked(true);
      }
    }, 500);
    const prekeys = session.prekeys;

    requestDeviceLock(controller.signal)
      .then(async (unlock) => {
        release = unlock;
        clearTimeout(waiting);
        if (!active || !prekeys) {
          if (active) {
            setLocked(true);
          }
          return;
        }
        setLocked(false);
        const { restored, rejected } = await history.restore();
        if (!active) {
          return;
        }
        setRejected(rejected);
        const pairing = new Pairing(
          client,
          keys.identity,
          keys.exchange,
          prekeys,
          session.pairs,
        );
        const messenger = new Messenger(
          client,
          authenticator,
          keys.identity,
          keys.exchange,
          pairing,
        );
        const conversations = new Conversations(
          messenger,
          keys.identity.identity,
          { history, restored },
        );
        store.current = conversations;
        messengerRef.current = messenger;
        pairingRef.current = pairing;
        const unkey = messenger.onKey((bundle) => void trust.observe(bundle));
        const unpairKey = pairing.onKey((bundle) => void trust.observe(bundle));
        const unsubscribe = conversations.onState(setState);
        messenger.start();
        pairing.start(messenger);
        conversations.start();
        teardown = () => {
          unsubscribe();
          unkey();
          unpairKey();
          pairing.stop();
          conversations.stop();
          messenger.stop();
          if (pairingRef.current === pairing) {
            pairingRef.current = null;
          }
          if (store.current === conversations) {
            store.current = null;
          }
          if (messengerRef.current === messenger) {
            messengerRef.current = null;
          }
        };
      })
      .catch(() => {
        clearTimeout(waiting);
        if (active) {
          setLocked(true);
        }
      });

    return () => {
      active = false;
      clearTimeout(waiting);
      controller.abort();
      untrust();
      unpair();
      teardown?.();
      release?.();
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
    const peer = state.active;
    const pairing = pairingRef.current;
    if (pairing && session.pairs.state(peer) === "none") {
      void pairing.initiate(peer).then((result) => {
        if (pairingRef.current === pairing) {
          setAttempt({ peer, result });
        }
      });
    }
  }, [session, state.active, state.connected]);

  const pairing = useMemo(() => {
    if (!session || !state.active || pairVersion < 0) {
      return null;
    }
    const current = session.pairs.state(state.active);
    if (current !== "none") {
      return current;
    }
    return attempt?.peer === state.active ? attempt.result : null;
  }, [session, state.active, pairVersion, attempt]);

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
    pairing,
    locked,
  };
}
