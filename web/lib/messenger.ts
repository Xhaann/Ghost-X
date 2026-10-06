import type { Client } from "./client.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { AuthSource } from "./presence.ts";
import {
  type ErrorCode,
  bodySize,
  isValidBody,
  maxBodySize,
} from "./protocol.ts";

export type SendResult =
  { ok: true } | { ok: false; reason: ErrorCode | "not_sent" };

export type Received = { from: string; body: string; sequence: number };

export type MessengerState = {
  active: boolean;
  received: readonly Received[];
};

export const maxReceived = 100;

const inactive: MessengerState = { active: false, received: [] };

export class Messenger {
  readonly #client: Client;
  readonly #auth: AuthSource;
  readonly #states = new Listeners<MessengerState>();
  #state: MessengerState = inactive;
  #sequence = 0;
  #detach: (() => void) | null = null;

  constructor(client: Client, auth: AuthSource) {
    this.#client = client;
    this.#auth = auth;
  }

  get state(): MessengerState {
    return this.#state;
  }

  onState(listener: (state: MessengerState) => void): () => void {
    return this.#states.add(listener);
  }

  start(): void {
    if (this.#detach) {
      return;
    }
    const detach = [
      this.#client.onMessage((message) => {
        if (message.type === "message" && this.#state.active) {
          this.#receive(message.payload.from, message.payload.body);
        }
      }),
      this.#auth.onState((state) => this.#activate(state === "authenticated")),
    ];
    this.#detach = () => detach.forEach((release) => release());
    this.#activate(this.#auth.state === "authenticated");
  }

  stop(): void {
    this.#detach?.();
    this.#detach = null;
    this.#activate(false);
  }

  async send(to: string, body: string): Promise<SendResult> {
    if (!this.#state.active) {
      return { ok: false, reason: "authentication_required" };
    }
    if (!isIdentity(to)) {
      return { ok: false, reason: "invalid_payload" };
    }
    if (bodySize(body) > maxBodySize) {
      return { ok: false, reason: "message_too_large" };
    }
    if (!isValidBody(body)) {
      return { ok: false, reason: "invalid_payload" };
    }
    const reply = await this.#client.request({
      type: "send",
      payload: { to, body },
    });
    if (reply?.type === "sent") {
      return { ok: true };
    }
    if (reply?.type === "error") {
      return { ok: false, reason: reply.payload.code };
    }
    return { ok: false, reason: "not_sent" };
  }

  #activate(active: boolean): void {
    if (this.#state.active === active && this.#state.received.length === 0) {
      return;
    }
    this.#state = { active, received: [] };
    this.#states.emit(this.#state);
  }

  #receive(from: string, body: string): void {
    this.#sequence += 1;
    const received = [
      ...this.#state.received,
      { from, body, sequence: this.#sequence },
    ].slice(-maxReceived);
    this.#state = { active: true, received };
    this.#states.emit(this.#state);
  }
}
