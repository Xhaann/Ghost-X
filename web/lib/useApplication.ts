import { useCallback, useEffect, useState } from "react";
import {
  type Availability,
  type Phase,
  availability,
  phaseOf,
} from "./application.ts";
import type { Devices } from "./devices.ts";
import { Session, type SessionState } from "./session.ts";
import type { TransportKind } from "./transport.ts";
import { useIdentity } from "./useIdentity.ts";

export type IdentityInfo = {
  identity: string;
  deviceId: string;
  created: boolean;
  linked: boolean;
  devices: Devices;
};

export type Application = {
  phase: Phase;
  identity: IdentityInfo | null;
  kind: TransportKind;
  availability: Record<TransportKind, Availability>;
  session: Session | null;
  state: SessionState | null;
  select: (kind: TransportKind) => void;
  create: () => void;
  link: (identity: string) => void;
  reset: () => void;
};

export function useApplication(url: string | undefined): Application {
  const { local, reset, create, link } = useIdentity();
  const ready = local.status === "ready" ? local : null;
  const [kind, setKind] = useState<TransportKind>("websocket");
  const [session, setSession] = useState<Session | null>(null);
  const [state, setState] = useState<SessionState | null>(null);
  const [websocket, setWebsocket] = useState(false);

  useEffect(() => {
    setWebsocket(typeof WebSocket !== "undefined");
  }, []);

  useEffect(() => {
    if (!ready) {
      return;
    }
    const current = new Session({ kind, local: ready, url, link: null });
    const release = current.onState(setState);
    const retry = () => {
      if (document.visibilityState === "visible") {
        current.retry();
      }
    };
    const suspend = () => current.suspend();
    const resume = (event: PageTransitionEvent) => {
      if (event.persisted) {
        current.resume();
      }
    };
    window.addEventListener("online", retry);
    document.addEventListener("visibilitychange", retry);
    window.addEventListener("pagehide", suspend);
    window.addEventListener("pageshow", resume);
    setSession(current);
    setState(current.state);
    current.start();

    return () => {
      window.removeEventListener("online", retry);
      document.removeEventListener("visibilitychange", retry);
      window.removeEventListener("pagehide", suspend);
      window.removeEventListener("pageshow", resume);
      release();
      current.dispose();
      setSession(null);
      setState(null);
    };
  }, [ready, kind, url]);

  const select = useCallback((next: TransportKind) => setKind(next), []);

  const capabilities = {
    url,
    websocket,
    link: false,
  };

  return {
    phase: phaseOf(local.status),
    identity: ready
      ? {
          identity: ready.keys.identity,
          deviceId: ready.keys.deviceId,
          created: ready.created,
          linked: ready.keys.root === null,
          devices: ready.devices,
        }
      : null,
    kind,
    availability: {
      websocket: availability("websocket", capabilities),
      local: availability("local", capabilities),
    },
    session,
    state,
    select,
    create,
    link,
    reset,
  };
}
