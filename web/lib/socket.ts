import { Listeners } from "./listeners.ts";
import {
  type SendResult,
  type Transport,
  type TransportError,
  type TransportState,
  isFrameSize,
  maxBufferedBytes,
} from "./transport.ts";

export type WebSocketOptions = {
  minDelay?: number;
  maxDelay?: number;
};

export class WebSocketTransport implements Transport {
  readonly kind = "websocket";
  readonly #url: string;
  readonly #minDelay: number;
  readonly #maxDelay: number;
  readonly #states = new Listeners<TransportState>();
  readonly #data = new Listeners<string>();
  readonly #errors = new Listeners<TransportError>();
  #socket: WebSocket | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #attempt = 0;
  #state: TransportState = "disconnected";
  #active = false;

  constructor(url: string, options: WebSocketOptions = {}) {
    this.#url = url;
    this.#minDelay = options.minDelay ?? 1000;
    this.#maxDelay = options.maxDelay ?? 30000;
  }

  get state(): TransportState {
    return this.#state;
  }

  onState(listener: (state: TransportState) => void): () => void {
    return this.#states.add(listener);
  }

  onData(listener: (data: string) => void): () => void {
    return this.#data.add(listener);
  }

  onError(listener: (error: TransportError) => void): () => void {
    return this.#errors.add(listener);
  }

  send(frame: string): SendResult {
    const socket = this.#socket;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return "not_connected";
    }
    if (!isFrameSize(frame)) {
      return "oversized";
    }
    if (socket.bufferedAmount > maxBufferedBytes) {
      return "busy";
    }
    try {
      socket.send(frame);
      return "sent";
    } catch {
      return "failed";
    }
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
      this.#active = false;
      this.#attempt = 0;
      this.#cancelRetry();
      this.#release();
      this.#setState("error");
      this.#errors.emit("unavailable");
      return;
    }

    let opened = false;
    this.#socket = socket;
    socket.onopen = () => {
      opened = true;
      this.#attempt = 0;
      this.#setState("connected");
    };
    socket.onmessage = (event: MessageEvent) => {
      if (typeof event.data !== "string" || event.data === "") {
        this.#errors.emit("malformed");
      } else if (!isFrameSize(event.data)) {
        this.#errors.emit("oversized");
      } else {
        this.#data.emit(event.data);
      }
    };
    socket.onclose = () => {
      this.#socket = null;
      this.#errors.emit(opened ? "lost" : "failed");
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
    socket.onmessage = null;
    if (socket.readyState === WebSocket.CONNECTING) {
      socket.onopen = () => socket.close(1000);
    } else {
      socket.onopen = null;
      socket.close(1000);
    }
  }

  #setState(state: TransportState): void {
    if (this.#state === state) {
      return;
    }
    this.#state = state;
    this.#states.emit(state);
  }
}
