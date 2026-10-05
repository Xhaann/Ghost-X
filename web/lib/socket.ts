export type SocketState =
  "disconnected" | "connecting" | "connected" | "reconnecting";

export type SocketOptions = {
  minDelay?: number;
  maxDelay?: number;
};

type Listener = (state: SocketState) => void;

export class Socket {
  readonly #url: string;
  readonly #minDelay: number;
  readonly #maxDelay: number;
  readonly #listeners = new Set<Listener>();
  #socket: WebSocket | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #attempt = 0;
  #state: SocketState = "disconnected";
  #active = false;

  constructor(url: string, options: SocketOptions = {}) {
    this.#url = url;
    this.#minDelay = options.minDelay ?? 1000;
    this.#maxDelay = options.maxDelay ?? 30000;
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
    this.#attempt = 0;
    this.#cancelRetry();
    this.#release();
    this.#setState("disconnected");
  }

  retry(): void {
    if (!this.#active || this.#timer === null) {
      return;
    }
    this.#cancelRetry();
    this.#connect();
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
    socket.onopen = () => {
      this.#attempt = 0;
      this.#setState("connected");
    };
    socket.onclose = () => {
      this.#socket = null;
      this.#scheduleRetry();
    };
    this.#setState(this.#attempt === 0 ? "connecting" : "reconnecting");
  }

  #scheduleRetry(): void {
    const ceiling = Math.min(
      this.#maxDelay,
      this.#minDelay * 2 ** this.#attempt,
    );
    const delay = ceiling / 2 + Math.random() * (ceiling / 2);
    this.#attempt += 1;
    this.#setState("reconnecting");
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.#connect();
    }, delay);
  }

  #cancelRetry(): void {
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
  }

  #release(): void {
    const socket = this.#socket;
    if (!socket) {
      return;
    }
    this.#socket = null;
    socket.onclose = null;
    if (socket.readyState === WebSocket.CONNECTING) {
      socket.onopen = () => socket.close(1000);
    } else {
      socket.onopen = null;
      socket.close(1000);
    }
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
