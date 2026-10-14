import { Listeners } from "./listeners.ts";
import {
  type SendResult,
  type Transport,
  type TransportError,
  type TransportState,
  isFrameSize,
} from "./transport.ts";

export type LinkHandlers = {
  frame(frame: string): void;
  closed(): void;
};

export interface LinkConnection {
  /**
   * True means the frame was accepted, in order, into this connection's
   * outbound buffer; it says nothing about whether the peer received it.
   * Backpressure below the connection's buffer cap is absorbed, not refused.
   * False means the frame was not accepted and will not be written later:
   * the connection is closed or its buffer is over the cap. Frames still
   * buffered when the connection closes are discarded, and the close is
   * reported through `LinkHandlers.closed`.
   */
  send(frame: string): boolean;
  close(): void;
}

export interface Link {
  connect(handlers: LinkHandlers): Promise<LinkConnection>;
}

export const connectTimeout = 10_000;

export class LocalTransport implements Transport {
  readonly kind = "local";
  readonly #link: Link | null;
  readonly #timeout: number;
  readonly #states = new Listeners<TransportState>();
  readonly #data = new Listeners<string>();
  readonly #errors = new Listeners<TransportError>();
  #connection: LinkConnection | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #generation = 0;
  #state: TransportState = "disconnected";

  constructor(link: Link | null, options: { timeout?: number } = {}) {
    this.#link = link;
    this.#timeout = options.timeout ?? connectTimeout;
  }

  get state(): TransportState {
    return this.#state;
  }

  onState(listener: (state: TransportState) => void): () => void {
    return this.#states.add(listener);
  }

  onData(listener: (frame: string) => void): () => void {
    return this.#data.add(listener);
  }

  onError(listener: (error: TransportError) => void): () => void {
    return this.#errors.add(listener);
  }

  open(): void {
    if (this.#state === "connecting" || this.#state === "connected") {
      return;
    }
    const link = this.#link;
    const generation = ++this.#generation;
    if (!link) {
      this.#setState("error");
      this.#errors.emit("unavailable");
      return;
    }
    this.#setState("connecting");
    this.#timer = setTimeout(() => {
      if (generation === this.#generation) {
        this.#fail("timeout");
      }
    }, this.#timeout);
    void this.#connect(link, generation);
  }

  close(): void {
    this.#generation += 1;
    this.#release();
    this.#setState("disconnected");
  }

  send(frame: string): SendResult {
    const connection = this.#connection;
    if (!connection || this.#state !== "connected") {
      return "not_connected";
    }
    if (!isFrameSize(frame)) {
      return "oversized";
    }
    try {
      return connection.send(frame) ? "sent" : "busy";
    } catch {
      return "failed";
    }
  }

  async #connect(link: Link, generation: number): Promise<void> {
    let connection: LinkConnection;
    try {
      connection = await link.connect({
        frame: (frame) => this.#receive(generation, frame),
        closed: () => {
          if (generation === this.#generation) {
            this.#fail(this.#state === "connected" ? "lost" : "failed");
          }
        },
      });
    } catch {
      if (generation === this.#generation) {
        this.#fail("failed");
      }
      return;
    }
    if (generation !== this.#generation) {
      connection.close();
      return;
    }
    this.#clearTimer();
    this.#connection = connection;
    this.#setState("connected");
  }

  #receive(generation: number, frame: unknown): void {
    if (generation !== this.#generation || this.#state !== "connected") {
      return;
    }
    if (typeof frame !== "string" || frame === "") {
      this.#errors.emit("malformed");
    } else if (!isFrameSize(frame)) {
      this.#errors.emit("oversized");
    } else {
      this.#data.emit(frame);
    }
  }

  #fail(error: TransportError): void {
    this.#generation += 1;
    this.#release();
    this.#setState("error");
    this.#errors.emit(error);
  }

  #release(): void {
    this.#clearTimer();
    const connection = this.#connection;
    this.#connection = null;
    try {
      connection?.close();
    } catch {}
  }

  #clearTimer(): void {
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
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
