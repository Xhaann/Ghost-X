import { Listeners } from "./listeners.ts";
import {
  type ClientMessage,
  type ServerMessage,
  createId,
  encode,
  parse,
} from "./protocol.ts";
import type { Transport, TransportError, TransportState } from "./transport.ts";

export class Client {
  readonly #states = new Listeners<TransportState>();
  readonly #errors = new Listeners<TransportError>();
  readonly #messages = new Listeners<ServerMessage>();
  #transport: Transport;
  #detach: () => void;
  #open = false;

  constructor(transport: Transport) {
    this.#transport = transport;
    this.#detach = this.#attach(transport);
  }

  get state(): TransportState {
    return this.#transport.state;
  }

  select(transport: Transport): void {
    if (transport === this.#transport) {
      return;
    }
    this.#detach();
    this.#transport.close();
    this.#transport = transport;
    this.#detach = this.#attach(transport);
    this.#states.emit(transport.state);
    if (this.#open) {
      transport.open();
    }
  }

  open(): void {
    this.#open = true;
    this.#transport.open();
  }

  close(): void {
    this.#open = false;
    this.#transport.close();
  }

  retry(): void {
    this.#transport.retry?.();
  }

  send(message: ClientMessage, id: string = createId()): string | null {
    return this.#transport.send(encode(message, id)) ? id : null;
  }

  request(
    message: ClientMessage,
    timeout = 5000,
    id?: string,
  ): Promise<ServerMessage | null> {
    return new Promise((resolve) => {
      const sent = this.send(message, id);
      if (!sent) {
        resolve(null);
        return;
      }
      const finish = (result: ServerMessage | null) => {
        clearTimeout(timer);
        releaseMessages();
        releaseStates();
        resolve(result);
      };
      const releaseMessages = this.onMessage((reply) => {
        if (reply.id === sent) {
          finish(reply);
        }
      });
      const releaseStates = this.onState((state) => {
        if (state !== "connected") {
          finish(null);
        }
      });
      const timer = setTimeout(() => finish(null), timeout);
    });
  }

  onState(listener: (state: TransportState) => void): () => void {
    return this.#states.add(listener);
  }

  onError(listener: (error: TransportError) => void): () => void {
    return this.#errors.add(listener);
  }

  onMessage(listener: (message: ServerMessage) => void): () => void {
    return this.#messages.add(listener);
  }

  #attach(transport: Transport): () => void {
    const detach = [
      transport.onState((state) => this.#states.emit(state)),
      transport.onError((error) => this.#errors.emit(error)),
      transport.onData((data) => {
        const message = parse(data);
        if (message) {
          this.#messages.emit(message);
        }
      }),
    ];
    return () => detach.forEach((release) => release());
  }
}
