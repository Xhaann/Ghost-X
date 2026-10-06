import type { Client } from "./client.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { AuthSource } from "./presence.ts";
import {
  type ErrorCode,
  bodySize,
  createId,
  isValidBody,
  isValidId,
  maxBodySize,
} from "./protocol.ts";

export type SendResult =
  { ok: true } | { ok: false; reason: ErrorCode | "not_sent" };

export type Incoming = { id: string; from: string; body: string };

export type MessengerState = { active: boolean };

export class Messenger {
  readonly #client: Client;
  readonly #auth: AuthSource;
  readonly #states = new Listeners<MessengerState>();
  readonly #messages = new Listeners<Incoming>();
  #state: MessengerState = { active: false };
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

  onMessage(listener: (message: Incoming) => void): () => void {
    return this.#messages.add(listener);
  }

  start(): void {
    if (this.#detach) {
      return;
    }
    const detach = [
      this.#client.onMessage((message) => {
        if (message.type === "message" && this.#state.active) {
          this.#messages.emit({ ...message.payload });
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

  async send(
    to: string,
    body: string,
    id: string = createId(),
  ): Promise<SendResult> {
    if (!this.#state.active) {
      return { ok: false, reason: "authentication_required" };
    }
    if (!isIdentity(to) || !isValidId(id)) {
      return { ok: false, reason: "invalid_payload" };
    }
    if (bodySize(body) > maxBodySize) {
      return { ok: false, reason: "message_too_large" };
    }
    if (!isValidBody(body)) {
      return { ok: false, reason: "invalid_payload" };
    }
    const reply = await this.#client.request(
      { type: "send", payload: { to, body } },
      5000,
      id,
    );
    if (reply?.type === "sent") {
      return { ok: true };
    }
    if (reply?.type === "error") {
      return { ok: false, reason: reply.payload.code };
    }
    return { ok: false, reason: "not_sent" };
  }

  #activate(active: boolean): void {
    if (this.#state.active === active) {
      return;
    }
    this.#state = { active };
    this.#states.emit(this.#state);
  }
}
