import { useCallback, useEffect, useState } from "react";
import { Client } from "./client.ts";
import { LocalTransport } from "./local.ts";
import { WebSocketTransport } from "./socket.ts";
import type {
  Transport,
  TransportError,
  TransportKind,
  TransportState,
} from "./transport.ts";

function transport(kind: TransportKind, url: string): Transport {
  return kind === "websocket"
    ? new WebSocketTransport(url)
    : new LocalTransport(null);
}

export function useClient(url: string | undefined): {
  state: TransportState;
  error: TransportError | null;
  kind: TransportKind;
  client: Client | null;
  select: (kind: TransportKind) => void;
} {
  const [state, setState] = useState<TransportState>("disconnected");
  const [error, setError] = useState<TransportError | null>(null);
  const [kind, setKind] = useState<TransportKind>("websocket");
  const [client, setClient] = useState<Client | null>(null);

  const select = useCallback(
    (next: TransportKind) => {
      if (!client || !url || client.kind === next) {
        return;
      }
      setError(null);
      setKind(next);
      client.select(transport(next, url));
    },
    [client, url],
  );

  useEffect(() => {
    if (!url) {
      return;
    }

    const client = new Client(transport("websocket", url));
    const unsubscribe = [
      client.onState((state) => {
        setState(state);
        if (state === "connected" || state === "disconnected") {
          setError(null);
        }
      }),
      client.onError(setError),
    ];
    setClient(client);
    const retry = () => {
      if (document.visibilityState === "visible") {
        client.retry();
      }
    };
    const suspend = () => client.close();
    const resume = (event: PageTransitionEvent) => {
      if (event.persisted) {
        client.open();
      }
    };

    window.addEventListener("online", retry);
    document.addEventListener("visibilitychange", retry);
    window.addEventListener("pagehide", suspend);
    window.addEventListener("pageshow", resume);
    client.open();

    return () => {
      window.removeEventListener("online", retry);
      document.removeEventListener("visibilitychange", retry);
      window.removeEventListener("pagehide", suspend);
      window.removeEventListener("pageshow", resume);
      unsubscribe.forEach((release) => release());
      client.close();
      setState("disconnected");
      setError(null);
      setKind("websocket");
      setClient(null);
    };
  }, [url]);

  return { state, error, kind, client, select };
}
