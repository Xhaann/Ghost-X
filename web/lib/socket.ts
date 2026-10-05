export type SocketState =
  "disconnected" | "connecting" | "connected" | "reconnecting";

type Listener = (state: SocketState) => void;

export class Socket {
  readonly #url: string;
  readonly #listeners = new Set<Listener>();
  #socket: WebSocket | null = null;
  #state: SocketState = "disconnected";
  #active = false;

  constructor(url: string) {
    this.#url = url;
  }

  get state(): SocketState {
    return this.#state;
  }

  subscribe(listener: Listener): () => void {
    this.#listeners.add(listener);
    return () => {
      this.#listeners.delete(listener);
    };
  }

  open(): void {
    if (this.#active) {
      return;
    }
    this.#active = true;
    this.#connect();
  }

  close(): void {
    this.#active = false;
    this.#release();
    this.#setState("disconnected");
  }

  #connect(): void {
    let socket: WebSocket;
    try {
      socket = new WebSocket(this.#url);
    } catch {
      this.close();
      return;
    }

    this.#socket = socket;
    socket.onopen = () => this.#setState("connected");
    socket.onclose = () => {
      if (this.#socket !== socket) {
        return;
      }
      this.#socket = null;
      this.#active = false;
      this.#setState("disconnected");
    };
    this.#setState("connecting");
  }

  #release(): void {
    const socket = this.#socket;
    if (!socket) {
      return;
    }
    this.#socket = null;
    socket.onopen = null;
    socket.onclose = null;
    socket.close(1000);
  }

  #setState(state: SocketState): void {
    if (this.#state === state) {
      return;
    }
    this.#state = state;
    for (const listener of this.#listeners) {
      listener(state);
    }
  }
}
