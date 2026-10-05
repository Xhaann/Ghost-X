import { useEffect, useState } from "react";
import { Client } from "./client.ts";
import { WebSocketTransport } from "./socket.ts";
import type { TransportError, TransportState } from "./transport.ts";

export function useClient(url: string | undefined): {
  state: TransportState;
  error: TransportError | null;
  client: Client | null;
} {
  const [state, setState] = useState<TransportState>("disconnected");
  const [error, setError] = useState<TransportError | null>(null);
  const [client, setClient] = useState<Client | null>(null);

  useEffect(() => {
    if (!url) {
      return;
    }

    const client = new Client(new WebSocketTransport(url));
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
      setClient(null);
    };
  }, [url]);

  return { state, error, client };
}
