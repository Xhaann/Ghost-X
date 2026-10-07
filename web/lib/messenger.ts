import { decodeBase64UrlRange, encodeBase64Url } from "./base64.ts";
import type { Client } from "./client.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { Channel } from "./pairing.ts";
import type { AuthSource } from "./presence.ts";
import {
  type ErrorCode,
  type ReceiptStatus,
  type ServerMessage,
  type WireEnvelope,
  bodySize,
  createMessageId,
  isMessageId,
  isValidBody,
  maxBodySize,
  maxMessageSize,
  minMessageSize,
} from "./protocol.ts";
import type { Rosters } from "./rosters.ts";

export type SendResult =
  | { ok: true; devices: number }
  | {
      ok: false;
      reason: ErrorCode | "not_sent" | "encryption_failed" | "session_pending";
    };

export type MessengerState = { active: boolean };

export type Receipt = {
  to: string;
  device: string;
  id: string;
  status: ReceiptStatus;
};

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
  readonly #self: string;
  readonly #channel: Channel;
  readonly #rosters: Rosters;
  readonly #states = new Listeners<MessengerState>();
  readonly #deferred = new Map<string, Delivery[]>();
  #receiver: Receiver | null = null;
  #state: MessengerState = { active: false };
  #generation = 0;
  #queue: Promise<void> = Promise.resolve();
  #detach: (() => void) | null = null;

  constructor(
    client: Client,
    auth: AuthSource,
    self: string,
    channel: Channel,
    rosters: Rosters,
  ) {
    this.#client = client;
    this.#auth = auth;
    this.#self = self;
    this.#channel = channel;
    this.#rosters = rosters;
  }

  get state(): MessengerState {
    return this.#state;
  }

  onState(listener: (state: MessengerState) => void): () => void {
    return this.#states.add(listener);
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
          this.#activate();
        } else {
          this.#deactivate();
        }
      }),
      this.#channel.onChange((address) => this.#resume(address)),
    ];
    this.#detach = () => detach.forEach((release) => release());
    if (this.#auth.state === "authenticated") {
      this.#activate();
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
    return (await this.#rosters.fetch(identity)) !== null;
  }

  async send(
    to: string,
    body: string,
    id: string = createMessageId(),
  ): Promise<SendResult> {
    if (!this.#state.active) {
      return { ok: false, reason: "authentication_required" };
    }
    if (!isIdentity(to) || !isMessageId(id) || to === this.#self) {
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
    if (session.result === "unavailable") {
      return { ok: false, reason: "recipient_unavailable" };
    }
    if (session.devices.length === 0) {
      return { ok: false, reason: "session_pending" };
    }
    if (generation !== this.#generation) {
      return { ok: false, reason: "not_sent" };
    }
    const envelopes: WireEnvelope[] = [];
    for (const device of session.devices) {
      const sealed = await this.#channel.seal(to, device, id, body);
      if (sealed) {
        envelopes.push({ device, ciphertext: encodeBase64Url(sealed) });
      }
    }
    if (envelopes.length === 0) {
      return { ok: false, reason: "encryption_failed" };
    }
    if (generation !== this.#generation) {
      return { ok: false, reason: "not_sent" };
    }
    let delivered = envelopes;
    let reply = await this.#client.request({
      type: "send",
      payload: { to, id, envelopes },
    });
    if (reply?.type === "error" && reply.payload.code === "stale_devices") {
      const roster = await this.#rosters.fetch(to);
      delivered = envelopes.filter((e) =>
        roster?.devices.some((d) => d.id === e.device),
      );
      if (delivered.length === 0 || delivered.length === envelopes.length) {
        return { ok: false, reason: "stale_devices" };
      }
      reply = await this.#client.request({
        type: "send",
        payload: { to, id, envelopes: delivered },
      });
    }
    if (reply?.type === "queued") {
      return { ok: true, devices: delivered.length };
    }
    if (reply?.type === "error") {
      return { ok: false, reason: reply.payload.code };
    }
    return { ok: false, reason: "not_sent" };
  }

  #activate(): void {
    const generation = ++this.#generation;
    this.#deferred.clear();
    this.#setActive(true);
    if (this.#receiver) {
      void this.#fetch(generation);
    }
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
    const { from, device, id } = delivery;
    const data = decodeBase64UrlRange(
      delivery.ciphertext,
      minMessageSize,
      maxMessageSize,
    );
    const known = receiver.has(from, id);
    const result = data
      ? await this.#channel.open(from, device, id, data, (body) =>
          known ? Promise.resolve(true) : receiver.accept({ from, id, body }),
        )
      : "rejected";
    if (generation !== this.#generation) {
      return;
    }
    if (result === "accepted") {
      this.#acknowledge(delivery);
      return;
    }
    if (result === "failed") {
      return;
    }
    if (known) {
      this.#acknowledge(delivery);
      return;
    }
    if (result === "deferred") {
      this.#defer(delivery);
      return;
    }
    if (result === "missing") {
      void this.#channel.initiate(from, device);
    }
    receiver.reject({ from, id });
    this.#acknowledge(delivery);
  }

  #acknowledge(delivery: Delivery): void {
    this.#client.send({
      type: "ack",
      payload: {
        from: delivery.from,
        device: delivery.device,
        id: delivery.id,
      },
    });
  }

  #defer(delivery: Delivery): void {
    let total = 0;
    for (const list of this.#deferred.values()) {
      total += list.length;
    }
    if (total >= maxDeferred) {
      return;
    }
    const address = `${delivery.from}/${delivery.device}`;
    const list = this.#deferred.get(address) ?? [];
    if (!list.some((d) => d.id === delivery.id)) {
      list.push(delivery);
    }
    this.#deferred.set(address, list);
  }

  #resume(address: string): void {
    const list = this.#deferred.get(address);
    if (!list) {
      return;
    }
    this.#deferred.delete(address);
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
        payload: { to: receipt.to, device: receipt.device, id: receipt.id },
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
