import type { Client } from "./client.ts";
import {
  type ExchangeKey,
  type KeyBundle,
  type Sealed,
  verifyBundle,
} from "./encryption.ts";
import { type IdentityKey, isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { AuthSource } from "./presence.ts";
import {
  type ErrorCode,
  type ServerMessage,
  bodySize,
  createId,
  isValidBody,
  isValidId,
  maxBodySize,
} from "./protocol.ts";

export type SealedRecord = { sealed: Sealed; peer: KeyBundle };

export type SendResult =
  | { ok: true; record?: SealedRecord }
  | {
      ok: false;
      reason: ErrorCode | "not_sent" | "encryption_failed";
      record?: SealedRecord;
    };

export type Incoming = {
  id: string;
  from: string;
  body: string | null;
  record?: SealedRecord;
};

export type MessengerState = { active: boolean };

export const maxPendingDecryptions = 128;

type Delivery = Extract<ServerMessage, { type: "message" }>["payload"];

export class Messenger {
  readonly #client: Client;
  readonly #auth: AuthSource;
  readonly #identity: IdentityKey;
  readonly #exchange: ExchangeKey;
  readonly #states = new Listeners<MessengerState>();
  readonly #messages = new Listeners<Incoming>();
  #state: MessengerState = { active: false };
  #generation = 0;
  #pending = 0;
  #queue: Promise<void> = Promise.resolve();
  #detach: (() => void) | null = null;

  constructor(
    client: Client,
    auth: AuthSource,
    identity: IdentityKey,
    exchange: ExchangeKey,
  ) {
    this.#client = client;
    this.#auth = auth;
    this.#identity = identity;
    this.#exchange = exchange;
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
        if (message.type === "message") {
          this.#receive(message.payload);
        }
      }),
      this.#auth.onState((state) => {
        if (state === "authenticated") {
          this.#publish();
        } else {
          this.#deactivate();
        }
      }),
    ];
    this.#detach = () => detach.forEach((release) => release());
    if (this.#auth.state === "authenticated") {
      this.#publish();
    }
  }

  stop(): void {
    this.#detach?.();
    this.#detach = null;
    this.#deactivate();
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
    const generation = this.#generation;

    const bundle = await this.#client.request({
      type: "key",
      payload: { identity: to },
    });
    if (bundle?.type === "error") {
      return { ok: false, reason: bundle.payload.code };
    }
    if (bundle?.type !== "key" || bundle.payload.identity !== to) {
      return { ok: false, reason: "not_sent" };
    }
    const toKey = await verifyBundle(bundle.payload);
    if (!toKey) {
      return { ok: false, reason: "encryption_failed" };
    }
    const sealed = await this.#exchange.seal(
      {
        id,
        from: this.#identity.identity,
        to,
        fromKey: this.#exchange.publicRaw,
        toKey,
      },
      body,
    );
    if (!sealed) {
      return { ok: false, reason: "encryption_failed" };
    }
    const record: SealedRecord = { sealed, peer: bundle.payload };
    if (generation !== this.#generation) {
      return { ok: false, reason: "not_sent", record };
    }

    const reply = await this.#client.request(
      { type: "send", payload: { to, ...sealed } },
      5000,
      id,
    );
    if (reply?.type === "sent") {
      return { ok: true, record };
    }
    if (reply?.type === "error") {
      return { ok: false, reason: reply.payload.code, record };
    }
    return { ok: false, reason: "not_sent", record };
  }

  #publish(): void {
    const generation = ++this.#generation;
    this.#setActive(false);
    this.#exchange
      .bind(this.#identity)
      .then(async (bundle) => {
        if (!bundle || generation !== this.#generation) {
          return;
        }
        const reply = await this.#client.request({
          type: "publish",
          payload: { key: bundle.key, signature: bundle.signature },
        });
        if (generation === this.#generation && reply?.type === "published") {
          this.#setActive(true);
        }
      })
      .catch(() => {});
  }

  #deactivate(): void {
    this.#generation += 1;
    this.#setActive(false);
  }

  #receive(delivery: Delivery): void {
    if (!this.#state.active) {
      return;
    }
    const generation = this.#generation;
    if (this.#pending >= maxPendingDecryptions) {
      this.#messages.emit({ id: delivery.id, from: delivery.from, body: null });
      return;
    }
    this.#pending += 1;
    this.#queue = this.#queue.then(async () => {
      const opened = await this.#open(delivery);
      this.#pending -= 1;
      if (generation === this.#generation) {
        this.#messages.emit({
          id: delivery.id,
          from: delivery.from,
          body: opened?.body ?? null,
          record: opened?.record,
        });
      }
    });
  }

  async #open(
    delivery: Delivery,
  ): Promise<{ body: string; record: SealedRecord } | null> {
    try {
      const peer: KeyBundle = {
        identity: delivery.from,
        key: delivery.key,
        signature: delivery.signature,
      };
      const fromKey = await verifyBundle(peer);
      if (!fromKey) {
        return null;
      }
      const sealed: Sealed = {
        salt: delivery.salt,
        iv: delivery.iv,
        ciphertext: delivery.ciphertext,
      };
      const body = await this.#exchange.open(
        {
          id: delivery.id,
          from: delivery.from,
          to: this.#identity.identity,
          fromKey,
          toKey: this.#exchange.publicRaw,
        },
        sealed,
      );
      return body === null ? null : { body, record: { sealed, peer } };
    } catch {
      return null;
    }
  }

  #setActive(active: boolean): void {
    if (this.#state.active === active) {
      return;
    }
    this.#state = { active };
    this.#states.emit(this.#state);
  }
}
