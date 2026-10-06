import { decodeBase64UrlRange, encodeBase64Url } from "./base64.ts";
import type { Client } from "./client.ts";
import {
  type ExchangeKey,
  type KeyBundle,
  verifyBundle,
} from "./encryption.ts";
import { type IdentityKey, isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { Channel } from "./pairing.ts";
import type { AuthSource } from "./presence.ts";
import {
  type ErrorCode,
  type ReceiptStatus,
  type ServerMessage,
  bodySize,
  createMessageId,
  isMessageId,
  isValidBody,
  maxBodySize,
  maxMessageSize,
  minMessageSize,
} from "./protocol.ts";

export type SendResult =
  | { ok: true }
  | {
      ok: false;
      reason: ErrorCode | "not_sent" | "encryption_failed" | "session_pending";
    };

export type MessengerState = { active: boolean };

export type Receipt = { to: string; id: string; status: ReceiptStatus };

export interface Receiver {
  has(from: string, id: string): boolean;
  accept(message: { from: string; id: string; body: string }): Promise<boolean>;
  reject(message: { from: string; id: string }): void;
  settle(receipt: Receipt): Promise<boolean>;
}

export const maxDeferred = 64;

type Delivery = Extract<ServerMessage, { type: "message" }>["payload"];

export class Messenger {
  readonly #client: Client;
  readonly #auth: AuthSource;
  readonly #identity: IdentityKey;
  readonly #exchange: ExchangeKey;
  readonly #channel: Channel;
  readonly #states = new Listeners<MessengerState>();
  readonly #bundles = new Listeners<KeyBundle>();
  readonly #deferred = new Map<string, Delivery[]>();
  #receiver: Receiver | null = null;
  #state: MessengerState = { active: false };
  #generation = 0;
  #queue: Promise<void> = Promise.resolve();
  #detach: (() => void) | null = null;

  constructor(
    client: Client,
    auth: AuthSource,
    identity: IdentityKey,
    exchange: ExchangeKey,
    channel: Channel,
  ) {
    this.#client = client;
    this.#auth = auth;
    this.#identity = identity;
    this.#exchange = exchange;
    this.#channel = channel;
  }

  get state(): MessengerState {
    return this.#state;
  }

  onState(listener: (state: MessengerState) => void): () => void {
    return this.#states.add(listener);
  }

  onKey(listener: (bundle: KeyBundle) => void): () => void {
    return this.#bundles.add(listener);
  }

  receive(receiver: Receiver): () => void {
    this.#receiver = receiver;
    if (this.#state.active) {
      void this.#fetch(this.#generation);
    }
    return () => {
      if (this.#receiver === receiver) {
        this.#receiver = null;
      }
    };
  }

  start(): void {
    if (this.#detach) {
      return;
    }
    const detach = [
      this.#client.onMessage((message) => {
        const generation = this.#generation;
        if (message.type === "message") {
          this.#enqueue(() => this.#deliver(message.payload, generation));
        } else if (message.type === "receipt") {
          this.#enqueue(() => this.#settle(message.payload, generation));
        }
      }),
      this.#auth.onState((state) => {
        if (state === "authenticated") {
          this.#establish();
        } else {
          this.#deactivate();
        }
      }),
      this.#channel.onChange((peer) => this.#resume(peer)),
    ];
    this.#detach = () => detach.forEach((release) => release());
    if (this.#auth.state === "authenticated") {
      this.#establish();
    }
  }

  stop(): void {
    this.#detach?.();
    this.#detach = null;
    this.#deactivate();
  }

  async lookup(identity: string): Promise<boolean> {
    if (!this.#state.active || !isIdentity(identity)) {
      return false;
    }
    const generation = this.#generation;
    const reply = await this.#client.request({
      type: "key",
      payload: { identity },
    });
    if (reply?.type !== "key" || reply.payload.identity !== identity) {
      return false;
    }
    const bundle: KeyBundle = {
      identity,
      key: reply.payload.key,
      signature: reply.payload.signature,
    };
    if (!(await verifyBundle(bundle)) || generation !== this.#generation) {
      return false;
    }
    this.#bundles.emit(bundle);
    return true;
  }

  async send(
    to: string,
    body: string,
    id: string = createMessageId(),
  ): Promise<SendResult> {
    if (!this.#state.active) {
      return { ok: false, reason: "authentication_required" };
    }
    if (!isIdentity(to) || !isMessageId(id) || to === this.#identity.identity) {
      return { ok: false, reason: "invalid_payload" };
    }
    if (bodySize(body) > maxBodySize) {
      return { ok: false, reason: "message_too_large" };
    }
    if (!isValidBody(body)) {
      return { ok: false, reason: "invalid_payload" };
    }
    const generation = this.#generation;
    const session = await this.#channel.establish(to);
    if (session === "unavailable") {
      return { ok: false, reason: "recipient_unavailable" };
    }
    if (session !== "established") {
      return { ok: false, reason: "session_pending" };
    }
    if (generation !== this.#generation) {
      return { ok: false, reason: "not_sent" };
    }
    const sealed = await this.#channel.seal(to, id, body);
    if (!sealed) {
      return { ok: false, reason: "encryption_failed" };
    }
    if (generation !== this.#generation) {
      return { ok: false, reason: "not_sent" };
    }
    const reply = await this.#client.request({
      type: "send",
      payload: { to, id, ciphertext: encodeBase64Url(sealed) },
    });
    if (reply?.type === "queued") {
      return { ok: true };
    }
    if (reply?.type === "error") {
      return { ok: false, reason: reply.payload.code };
    }
    return { ok: false, reason: "not_sent" };
  }

  #establish(): void {
    const generation = ++this.#generation;
    this.#setActive(false);
    this.#deferred.clear();
    (async () => {
      const bundle = await this.#exchange.bind(this.#identity);
      if (!bundle || generation !== this.#generation) {
        return;
      }
      const published = await this.#client.request({
        type: "publish",
        payload: { key: bundle.key, signature: bundle.signature },
      });
      if (generation === this.#generation && published?.type === "published") {
        this.#setActive(true);
        if (this.#receiver) {
          await this.#fetch(generation);
        }
      }
    })().catch(() => {});
  }

  async #fetch(generation: number): Promise<void> {
    if (generation === this.#generation) {
      await this.#client.request({ type: "fetch", payload: {} });
    }
  }

  #deactivate(): void {
    this.#generation += 1;
    this.#deferred.clear();
    this.#setActive(false);
  }

  #enqueue(task: () => Promise<void>): void {
    this.#queue = this.#queue.then(task).catch(() => {});
  }

  async #deliver(delivery: Delivery, generation: number): Promise<void> {
    const receiver = this.#receiver;
    if (!receiver || generation !== this.#generation) {
      return;
    }
    const { from, id } = delivery;
    const peer: KeyBundle = {
      identity: from,
      key: delivery.key,
      signature: delivery.signature,
    };
    const data = decodeBase64UrlRange(
      delivery.ciphertext,
      minMessageSize,
      maxMessageSize,
    );
    const valid = data !== null && (await verifyBundle(peer)) !== null;
    if (generation !== this.#generation) {
      return;
    }
    if (valid) {
      this.#bundles.emit(peer);
    }
    const known = receiver.has(from, id);
    const result = valid
      ? await this.#channel.open(from, id, data, (body) =>
          known ? Promise.resolve(true) : receiver.accept({ from, id, body }),
        )
      : "rejected";
    if (generation !== this.#generation) {
      return;
    }
    if (result === "accepted") {
      this.#acknowledge(from, id);
      return;
    }
    if (result === "failed") {
      return;
    }
    if (known) {
      this.#acknowledge(from, id);
      return;
    }
    if (result === "deferred") {
      this.#defer(delivery);
      return;
    }
    if (result === "missing") {
      void this.#channel.initiate(from);
    }
    receiver.reject({ from, id });
    this.#acknowledge(from, id);
  }

  #acknowledge(from: string, id: string): void {
    this.#client.send({ type: "ack", payload: { from, id } });
  }

  #defer(delivery: Delivery): void {
    let total = 0;
    for (const list of this.#deferred.values()) {
      total += list.length;
    }
    if (total >= maxDeferred) {
      return;
    }
    const list = this.#deferred.get(delivery.from) ?? [];
    if (!list.some((d) => d.id === delivery.id)) {
      list.push(delivery);
    }
    this.#deferred.set(delivery.from, list);
  }

  #resume(peer: string): void {
    const list = this.#deferred.get(peer);
    if (!list) {
      return;
    }
    this.#deferred.delete(peer);
    const generation = this.#generation;
    for (const delivery of list) {
      this.#enqueue(() => this.#deliver(delivery, generation));
    }
  }

  async #settle(receipt: Receipt, generation: number): Promise<void> {
    const receiver = this.#receiver;
    if (!receiver || generation !== this.#generation) {
      return;
    }
    if (await receiver.settle(receipt)) {
      this.#client.send({
        type: "clear",
        payload: { to: receipt.to, id: receipt.id },
      });
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
