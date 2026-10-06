import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { Incoming, MessengerState, SendResult } from "./messenger.ts";
import { bodySize, createId, isValidBody, maxBodySize } from "./protocol.ts";

export type DeliveryState = "sending" | "delivered" | "unavailable" | "failed";

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
  onMessage(listener: (message: Incoming) => void): () => void;
  send(to: string, body: string, id: string): Promise<SendResult>;
}

export type SettledDelivery = Exclude<DeliveryState, "sending">;

export type Restored = ConversationMessage & { read?: boolean };

export interface HistoryPort {
  received(entry: {
    id: string;
    peer: string;
    sequence: number;
    read: boolean;
    body: string;
  }): void;
  sent(entry: {
    id: string;
    peer: string;
    sequence: number;
    delivery: SettledDelivery;
    body: string;
  }): void;
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
    return "delivered";
  }
  return result.reason === "recipient_unavailable" ? "unavailable" : "failed";
}

export class Conversations {
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
      this.#source.onMessage((message) => this.#receive(message)),
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

    const id = createId();
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
      (result) => {
        const settled = deliveryOf(result);
        if (generation === this.#generation) {
          this.#history?.sent({
            id,
            peer: to,
            sequence,
            delivery: settled,
            body,
          });
        }
        return this.#settle(generation, to, id, settled);
      },
      () => this.#settle(generation, to, id, "failed"),
    );
    return { accepted: true, id, delivery };
  }

  #settle(
    generation: number,
    identity: string,
    id: string,
    delivery: DeliveryState,
  ): DeliveryState {
    const conversation = this.#conversations.get(identity);
    if (generation !== this.#generation || !conversation) {
      return delivery;
    }
    const messages = conversation.messages.map((message) =>
      message.id === id && message.direction === "sent"
        ? { ...message, delivery }
        : message,
    );
    this.#conversations.set(identity, { ...conversation, messages });
    this.#publish();
    return delivery;
  }

  #receive(message: Incoming): void {
    if (!this.#detach) {
      return;
    }
    const existing = this.#conversations.get(message.from);
    if (existing?.messages.some((m) => m.id === message.id)) {
      return;
    }
    const target = this.#ensure(message.from);
    const sequence = ++this.#sequence;
    const conversation = this.#append(target, {
      id: message.id,
      from: message.from,
      to: this.#self,
      body: message.body,
      sequence,
      direction: "received",
    });
    if (message.body !== null) {
      this.#history?.received({
        id: message.id,
        peer: message.from,
        sequence,
        read: this.#active === message.from,
        body: message.body,
      });
    }
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
