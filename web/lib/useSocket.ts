import { useEffect, useState } from "react";
import { Socket, type SocketState } from "./socket.ts";

export function useSocket(url: string | undefined): SocketState {
  const [state, setState] = useState<SocketState>("disconnected");

  useEffect(() => {
    if (!url) {
      return;
    }

    const socket = new Socket(url);
    const unsubscribe = socket.subscribe(setState);
    socket.open();

    return () => {
      unsubscribe();
      socket.close();
      setState("disconnected");
    };
  }, [url]);

  return state;
}
