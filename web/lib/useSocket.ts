import { useEffect, useState } from "react";
import { Socket, type SocketState } from "./socket.ts";

export function useSocket(url: string | undefined): {
  state: SocketState;
  socket: Socket | null;
} {
  const [state, setState] = useState<SocketState>("disconnected");
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (!url) {
      return;
    }

    const socket = new Socket(url);
    const unsubscribe = socket.subscribe(setState);
    setSocket(socket);
    const retry = () => {
      if (document.visibilityState === "visible") {
        socket.retry();
      }
    };
    const suspend = () => socket.close();
    const resume = (event: PageTransitionEvent) => {
      if (event.persisted) {
        socket.open();
      }
    };

    window.addEventListener("online", retry);
    document.addEventListener("visibilitychange", retry);
    window.addEventListener("pagehide", suspend);
    window.addEventListener("pageshow", resume);
    socket.open();

    return () => {
      window.removeEventListener("online", retry);
      document.removeEventListener("visibilitychange", retry);
      window.removeEventListener("pagehide", suspend);
      window.removeEventListener("pageshow", resume);
      unsubscribe();
      socket.close();
      setState("disconnected");
      setSocket(null);
    };
  }, [url]);

  return { state, socket };
}
