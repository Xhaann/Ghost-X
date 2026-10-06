import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type {
  MessengerState,
  Receipt,
  Receiver,
  SendResult,
} from "./messenger.ts";
import {
  bodySize,
  createMessageId,
  isValidBody,
  maxBodySize,
} from "./protocol.ts";

export type DeliveryState =
  "sending" | "queued" | "delivered" | "expired" | "unavailable" | "failed";

type MessageBase = {
  id: string;
  from: string;
  to: string;
  sequence: number;
};

export type ConversationMessage =
  | (MessageBase & {
      direction: "sent";
      body: string;
      delivery: DeliveryState;
    })
  | (MessageBase & { direction: "received"; body: string | null });

export type Conversation = {
  identity: string;
  messages: readonly ConversationMessage[];
  unread: number;
  updated: number;
};

export type ConversationsState = {
  connected: boolean;
  active: string | null;
  conversations: readonly Conversation[];
};

export type SendAttempt =
  | { accepted: true; id: string; delivery: Promise<DeliveryState> }
  | {
      accepted: false;
      reason:
        | "no_conversation"
        | "authentication_required"
        | "invalid_payload"
        | "message_too_large";
    };

export interface MessageSource {
  readonly state: MessengerState;
  onState(listener: (state: MessengerState) => void): () => void;
  receive(receiver: Receiver): () => void;
  send(to: string, body: string, id: string): Promise<SendResult>;
}

export type SettledDelivery = Exclude<DeliveryState, "sending">;

const ranks: Record<DeliveryState, number> = {
  sending: 0,
  failed: 1,
  unavailable: 1,
  queued: 2,
  delivered: 3,
  expired: 3,
};

export function advances(from: DeliveryState, to: DeliveryState): boolean {
  return ranks[to] > ranks[from];
}

export type Restored = ConversationMessage & { read?: boolean };

export interface HistoryPort {
  has(peer: string, id: string): boolean;
  received(entry: {
    id: string;
    peer: string;
    sequence: number;
    read: boolean;
    body: string;
  }): Promise<boolean>;
  sent(entry: {
    id: string;
    peer: string;
    sequence: number;
    delivery: SettledDelivery;
    body: string;
  }): Promise<boolean>;
  settle(peer: string, id: string, delivery: SettledDelivery): Promise<boolean>;
  read(identity: string): void;
}

export type ConversationOptions = {
  history?: HistoryPort;
  restored?: readonly Restored[];
};

export const maxConversations = 100;
export const maxMessages = 200;

const empty: ConversationsState = {
  connected: false,
  active: null,
  conversations: [],
};

function deliveryOf(result: SendResult): SettledDelivery {
  if (result.ok) {
    return "queued";
  }
  return result.reason === "recipient_unavailable" ? "unavailable" : "failed";
}

export class Conversations implements Receiver {
  readonly #source: MessageSource;
  readonly #self: string;
  readonly #history: HistoryPort | null;
  readonly #states = new Listeners<ConversationsState>();
  readonly #conversations = new Map<string, Conversation>();
  #active: string | null = null;
  #sequence = 0;
  #generation = 0;
  #state: ConversationsState = empty;
  #detach: (() => void) | null = null;

  constructor(
    source: MessageSource,
    self: string,
    options: ConversationOptions = {},
  ) {
    this.#source = source;
    this.#self = self;
    this.#history = options.history ?? null;
    this.#restore(options.restored ?? []);
  }

  get state(): ConversationsState {
    return this.#state;
  }

  onState(listener: (state: ConversationsState) => void): () => void {
    return this.#states.add(listener);
  }

  start(): void {
    if (this.#detach) {
      return;
    }
    const detach = [
      this.#source.receive(this),
      this.#source.onState(() => this.#publish()),
    ];
    this.#detach = () => detach.forEach((release) => release());
    this.#publish();
  }

  stop(): void {
    this.#detach?.();
    this.#detach = null;
    this.#generation += 1;
    this.#conversations.clear();
    this.#active = null;
    this.#state = empty;
    this.#states.emit(this.#state);
  }

  open(identity: string): boolean {
    if (!this.#detach || !isIdentity(identity)) {
      return false;
    }
    const conversation = this.#ensure(identity);
    this.#active = identity;
    if (conversation.unread > 0) {
      this.#conversations.set(identity, { ...conversation, unread: 0 });
      this.#history?.read(identity);
    }
    this.#publish();
    return true;
  }

  close(): void {
    if (this.#active === null) {
      return;
    }
    this.#active = null;
    this.#publish();
  }

  send(body: string): SendAttempt {
    const to = this.#active;
    if (!this.#detach || to === null) {
      return { accepted: false, reason: "no_conversation" };
    }
    if (!this.#source.state.active) {
      return { accepted: false, reason: "authentication_required" };
    }
    if (bodySize(body) > maxBodySize) {
      return { accepted: false, reason: "message_too_large" };
    }
    if (!isValidBody(body)) {
      return { accepted: false, reason: "invalid_payload" };
    }

    const id = createMessageId();
    const generation = this.#generation;
    const target = this.#ensure(to);
    const sequence = ++this.#sequence;
    this.#append(target, {
      id,
      from: this.#self,
      to,
      body,
      sequence,
      direction: "sent",
      delivery: "sending",
    });
    this.#publish();

    const delivery = this.#source.send(to, body, id).then(
      (result) => this.#record(generation, to, id, sequence, body, result),
      () => this.#settle(generation, to, id, "failed"),
    );
    return { accepted: true, id, delivery };
  }

  has(from: string, id: string): boolean {
    return (
      this.#conversations
        .get(from)
        ?.messages.some(
          (m) => m.id === id && m.direction === "received" && m.body !== null,
        ) === true || this.#history?.has(from, id) === true
    );
  }

  async accept(message: {
    from: string;
    id: string;
    body: string;
  }): Promise<boolean> {
    if (!this.#detach || !isValidBody(message.body)) {
      return false;
    }
    const generation = this.#generation;
    const sequence = ++this.#sequence;
    const read = this.#active === message.from;
    if (this.#history) {
      const stored = await this.#history.received({
        id: message.id,
        peer: message.from,
        sequence,
        read,
        body: message.body,
      });
      if (!stored) {
        return false;
      }
    }
    if (generation === this.#generation) {
      this.#receive({ ...message, sequence });
    }
    return true;
  }

  reject(message: { from: string; id: string }): void {
    if (this.#detach) {
      this.#receive({ ...message, body: null, sequence: ++this.#sequence });
    }
  }

  async settle(receipt: Receipt): Promise<boolean> {
    const delivery: SettledDelivery = receipt.status;
    this.#settle(this.#generation, receipt.to, receipt.id, delivery);
    return this.#history
      ? this.#history.settle(receipt.to, receipt.id, delivery)
      : true;
  }

  async #record(
    generation: number,
    to: string,
    id: string,
    sequence: number,
    body: string,
    result: SendResult,
  ): Promise<DeliveryState> {
    const settled = this.#settle(generation, to, id, deliveryOf(result));
    if (generation === this.#generation && settled !== "sending") {
      await this.#history?.sent({
        id,
        peer: to,
        sequence,
        delivery: settled,
        body,
      });
    }
    return settled;
  }

  #settle(
    generation: number,
    identity: string,
    id: string,
    delivery: DeliveryState,
  ): DeliveryState {
    const conversation = this.#conversations.get(identity);
    const current = conversation?.messages.find(
      (message) => message.id === id && message.direction === "sent",
    );
    if (
      generation !== this.#generation ||
      !conversation ||
      current?.direction !== "sent"
    ) {
      return delivery;
    }
    if (!advances(current.delivery, delivery)) {
      return current.delivery;
    }
    const messages = conversation.messages.map((message) =>
      message === current ? { ...current, delivery } : message,
    );
    this.#conversations.set(identity, { ...conversation, messages });
    this.#publish();
    return delivery;
  }

  #receive(message: {
    from: string;
    id: string;
    body: string | null;
    sequence: number;
  }): void {
    const existing = this.#conversations.get(message.from);
    const duplicate = existing?.messages.find((m) => m.id === message.id);
    if (duplicate && (duplicate.body !== null || message.body === null)) {
      return;
    }
    const target = duplicate
      ? {
          ...existing!,
          messages: existing!.messages.filter((m) => m !== duplicate),
        }
      : this.#ensure(message.from);
    const conversation = this.#append(target, {
      id: message.id,
      from: message.from,
      to: this.#self,
      body: message.body,
      sequence: message.sequence,
      direction: "received",
    });
    if (this.#active !== message.from) {
      this.#conversations.set(message.from, {
        ...conversation,
        unread: conversation.unread + 1,
      });
    }
    this.#publish();
  }

  #restore(restored: readonly Restored[]): void {
    const ordered = [...restored].sort((a, b) => a.sequence - b.sequence);
    for (const entry of ordered) {
      const peer = entry.direction === "sent" ? entry.to : entry.from;
      if (
        this.#conversations.get(peer)?.messages.some((m) => m.id === entry.id)
      ) {
        continue;
      }
      const { read, ...message } = entry;
      this.#sequence = Math.max(this.#sequence, message.sequence);
      const conversation = this.#append(this.#ensure(peer), message);
      if (message.direction === "received" && read === false) {
        this.#conversations.set(peer, {
          ...conversation,
          unread: conversation.unread + 1,
        });
      }
    }
  }

  #ensure(identity: string): Conversation {
    const existing = this.#conversations.get(identity);
    if (existing) {
      return existing;
    }
    if (this.#conversations.size >= maxConversations) {
      this.#evict();
    }
    const conversation: Conversation = {
      identity,
      messages: [],
      unread: 0,
      updated: ++this.#sequence,
    };
    this.#conversations.set(identity, conversation);
    return conversation;
  }

  #evict(): void {
    let oldest: Conversation | null = null;
    for (const conversation of this.#conversations.values()) {
      if (
        conversation.identity !== this.#active &&
        (!oldest || conversation.updated < oldest.updated)
      ) {
        oldest = conversation;
      }
    }
    if (oldest) {
      this.#conversations.delete(oldest.identity);
    }
  }

  #append(
    conversation: Conversation,
    message: ConversationMessage,
  ): Conversation {
    const next: Conversation = {
      ...conversation,
      messages: [...conversation.messages, message].slice(-maxMessages),
      updated: message.sequence,
    };
    this.#conversations.set(conversation.identity, next);
    return next;
  }

  #publish(): void {
    this.#state = {
      connected: this.#source.state.active,
      active: this.#active,
      conversations: [...this.#conversations.values()].sort(
        (a, b) => b.updated - a.updated,
      ),
    };
    this.#states.emit(this.#state);
  }
}
