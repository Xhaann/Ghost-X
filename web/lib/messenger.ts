import type { Client } from "./client.ts";
import {
  type ExchangeKey,
  type KeyBundle,
  verifyBundle,
} from "./encryption.ts";
import { type IdentityKey, isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { AuthSource } from "./presence.ts";
import {
  type ErrorCode,
  type ServerMessage,
  type WireEnvelope,
  bodySize,
  createId,
  isValidBody,
  isValidId,
  maxBodySize,
} from "./protocol.ts";
import type { Channel } from "./pairing.ts";
import { SessionKeys, type Transcript, verifySession } from "./session.ts";

export type SendResult =
  | { ok: true }
  | {
      ok: false;
      reason: ErrorCode | "not_sent" | "encryption_failed" | "session_pending";
    };

export type Incoming = { id: string; from: string; body: string | null };

export type MessengerState = { active: boolean };

export type SessionInfo = { session: string; epochs: number[] };

export type MessengerOptions = {
  rotationLimit?: number;
  previousLimit?: number;
};

export const maxPendingDecryptions = 128;
export const rotationLimit = 32;
export const previousLimit = 8;
export const replayLimit = 4096;

type Delivery = Extract<ServerMessage, { type: "message" }>["payload"];

export class Messenger {
  readonly #client: Client;
  readonly #auth: AuthSource;
  readonly #identity: IdentityKey;
  readonly #exchange: ExchangeKey;
  readonly #channel: Channel;
  readonly #rotationLimit: number;
  readonly #previousLimit: number;
  readonly #states = new Listeners<MessengerState>();
  readonly #messages = new Listeners<Incoming>();
  readonly #bundles = new Listeners<KeyBundle>();
  readonly #seen = new Set<string>();
  #state: MessengerState = { active: false };
  #session: SessionKeys | null = null;
  #uses = 0;
  #sincePrevious = 0;
  #rotating = false;
  #generation = 0;
  #pending = 0;
  #queue: Promise<void> = Promise.resolve();
  #detach: (() => void) | null = null;

  constructor(
    client: Client,
    auth: AuthSource,
    identity: IdentityKey,
    exchange: ExchangeKey,
    channel: Channel,
    options: MessengerOptions = {},
  ) {
    this.#client = client;
    this.#auth = auth;
    this.#identity = identity;
    this.#exchange = exchange;
    this.#channel = channel;
    this.#rotationLimit = options.rotationLimit ?? rotationLimit;
    this.#previousLimit = options.previousLimit ?? previousLimit;
  }

  get state(): MessengerState {
    return this.#state;
  }

  get session(): SessionInfo | null {
    const session = this.#session;
    return session && !session.destroyed
      ? { session: session.session, epochs: session.epochs }
      : null;
  }

  onState(listener: (state: MessengerState) => void): () => void {
    return this.#states.add(listener);
  }

  onMessage(listener: (message: Incoming) => void): () => void {
    return this.#messages.add(listener);
  }

  onKey(listener: (bundle: KeyBundle) => void): () => void {
    return this.#bundles.add(listener);
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
          this.#establish();
        } else {
          this.#deactivate();
        }
      }),
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

  async rotate(): Promise<boolean> {
    const session = this.#session;
    const generation = this.#generation;
    if (!session || this.#rotating || !this.#state.active) {
      return false;
    }
    this.#rotating = true;
    try {
      const epoch = await session.prepare();
      const bundle =
        epoch === null
          ? null
          : await session.bind(this.#identity, this.#exchange, "pending");
      if (generation !== this.#generation || this.#session !== session) {
        return false;
      }
      const reply = bundle
        ? await this.#client.request({ type: "session", payload: bundle })
        : null;
      if (generation !== this.#generation || this.#session !== session) {
        return false;
      }
      if (
        epoch !== null &&
        reply?.type === "established" &&
        session.activate(epoch)
      ) {
        this.#uses = 0;
        this.#sincePrevious = 0;
        return true;
      }
      this.#deactivate();
      return false;
    } finally {
      if (this.#session === session) {
        this.#rotating = false;
      }
    }
  }

  async send(
    to: string,
    body: string,
    id: string = createId(),
  ): Promise<SendResult> {
    const session = this.#session;
    if (!this.#state.active || !session || session.destroyed) {
      return { ok: false, reason: "authentication_required" };
    }
    if (!isIdentity(to) || !isValidId(id) || to === this.#identity.identity) {
      return { ok: false, reason: "invalid_payload" };
    }
    if (bodySize(body) > maxBodySize) {
      return { ok: false, reason: "message_too_large" };
    }
    if (!isValidBody(body)) {
      return { ok: false, reason: "invalid_payload" };
    }
    const generation = this.#generation;

    const reply = await this.#client.request({
      type: "key",
      payload: { identity: to },
    });
    if (reply?.type === "error") {
      return { ok: false, reason: reply.payload.code };
    }
    if (reply?.type !== "key" || reply.payload.identity !== to) {
      return { ok: false, reason: "not_sent" };
    }
    const bundle: KeyBundle = {
      identity: to,
      key: reply.payload.key,
      signature: reply.payload.signature,
    };
    const toStatic = await verifyBundle(bundle);
    if (!toStatic) {
      return { ok: false, reason: "encryption_failed" };
    }
    if (generation === this.#generation) {
      this.#bundles.emit(bundle);
    }
    if (reply.payload.sessions.length === 0) {
      return { ok: false, reason: "recipient_unavailable" };
    }

    const targets: {
      target: (typeof reply.payload.sessions)[number];
      ephemeral: Uint8Array<ArrayBuffer>;
    }[] = [];
    for (const target of reply.payload.sessions) {
      const ephemeral = await verifySession(to, toStatic, target);
      if (!ephemeral) {
        return { ok: false, reason: "encryption_failed" };
      }
      targets.push({ target, ephemeral });
    }
    if (!(await this.#channel.establish(to))) {
      return { ok: false, reason: "session_pending" };
    }
    if (generation !== this.#generation || this.#session !== session) {
      return { ok: false, reason: "not_sent" };
    }
    const inner = await this.#channel.seal(to, body);
    if (!inner) {
      return { ok: false, reason: "encryption_failed" };
    }
    const current = session.current;
    if (!current) {
      return { ok: false, reason: "not_sent" };
    }
    const envelopes: WireEnvelope[] = [];
    for (const { target, ephemeral } of targets) {
      const transcript: Transcript = {
        id,
        from: {
          identity: this.#identity.identity,
          staticKey: this.#exchange.publicRaw,
          session: session.session,
          epoch: current.epoch,
          ephemeral: current.key,
        },
        to: {
          identity: to,
          staticKey: toStatic,
          session: target.session,
          epoch: target.epoch,
          ephemeral,
        },
      };
      const sealed = await session.seal(transcript, inner);
      if (!sealed) {
        return { ok: false, reason: "encryption_failed" };
      }
      envelopes.push({
        session: target.session,
        epoch: target.epoch,
        ...sealed,
      });
    }
    if (generation !== this.#generation || this.#session !== session) {
      return { ok: false, reason: "not_sent" };
    }
    this.#used();

    const result = await this.#client.request(
      { type: "send", payload: { to, epoch: current.epoch, envelopes } },
      5000,
      id,
    );
    if (result?.type === "sent") {
      return { ok: true };
    }
    if (result?.type === "error") {
      return { ok: false, reason: result.payload.code };
    }
    return { ok: false, reason: "not_sent" };
  }

  #establish(): void {
    const generation = ++this.#generation;
    this.#setActive(false);
    this.#discard();
    (async () => {
      const bundle = await this.#exchange.bind(this.#identity);
      if (!bundle || generation !== this.#generation) {
        return;
      }
      const published = await this.#client.request({
        type: "publish",
        payload: { key: bundle.key, signature: bundle.signature },
      });
      if (generation !== this.#generation || published?.type !== "published") {
        return;
      }
      const session = await SessionKeys.create();
      const offer = await session.bind(
        this.#identity,
        this.#exchange,
        "current",
      );
      const reply =
        offer && generation === this.#generation
          ? await this.#client.request({ type: "session", payload: offer })
          : null;
      if (generation === this.#generation && reply?.type === "established") {
        this.#session = session;
        this.#uses = 0;
        this.#sincePrevious = 0;
        this.#rotating = false;
        this.#setActive(true);
      } else {
        session.destroy();
      }
    })().catch(() => {});
  }

  #deactivate(): void {
    this.#generation += 1;
    this.#discard();
    this.#setActive(false);
  }

  #discard(): void {
    this.#session?.destroy();
    this.#session = null;
    this.#rotating = false;
  }

  #used(): void {
    const session = this.#session;
    if (!session) {
      return;
    }
    this.#uses += 1;
    if (session.epochs.length > 1) {
      this.#sincePrevious += 1;
      if (this.#sincePrevious >= this.#previousLimit) {
        session.discardPrevious();
        this.#sincePrevious = 0;
      }
    }
    if (this.#uses >= this.#rotationLimit) {
      void this.rotate();
    }
  }

  #remember(key: string): void {
    this.#seen.add(key);
    if (this.#seen.size > replayLimit) {
      const oldest = this.#seen.values().next().value;
      if (oldest !== undefined) {
        this.#seen.delete(oldest);
      }
    }
  }

  #receive(delivery: Delivery): void {
    const session = this.#session;
    if (
      !this.#state.active ||
      !session ||
      delivery.envelope.session !== session.session
    ) {
      return;
    }
    const replay = `${delivery.from}/${delivery.id}`;
    if (this.#seen.has(replay)) {
      return;
    }
    const generation = this.#generation;
    if (this.#pending >= maxPendingDecryptions) {
      this.#messages.emit({ id: delivery.id, from: delivery.from, body: null });
      return;
    }
    this.#pending += 1;
    this.#queue = this.#queue.then(async () => {
      const body = await this.#open(delivery, session);
      this.#pending -= 1;
      if (generation !== this.#generation || this.#session !== session) {
        return;
      }
      if (this.#seen.has(replay)) {
        return;
      }
      if (body !== null) {
        this.#remember(replay);
        this.#used();
      }
      this.#messages.emit({ id: delivery.id, from: delivery.from, body });
    });
  }

  async #open(
    delivery: Delivery,
    session: SessionKeys,
  ): Promise<string | null> {
    try {
      const peer: KeyBundle = {
        identity: delivery.from,
        key: delivery.key,
        signature: delivery.signature,
      };
      const fromStatic = await verifyBundle(peer);
      if (!fromStatic) {
        return null;
      }
      this.#bundles.emit(peer);
      const fromEphemeral = await verifySession(
        delivery.from,
        fromStatic,
        delivery.sender,
      );
      const toEphemeral = session.publicKeyOf(delivery.envelope.epoch);
      if (!fromEphemeral || !toEphemeral) {
        return null;
      }
      const inner = await session.open(
        {
          id: delivery.id,
          from: {
            identity: delivery.from,
            staticKey: fromStatic,
            session: delivery.sender.session,
            epoch: delivery.sender.epoch,
            ephemeral: fromEphemeral,
          },
          to: {
            identity: this.#identity.identity,
            staticKey: this.#exchange.publicRaw,
            session: session.session,
            epoch: delivery.envelope.epoch,
            ephemeral: toEphemeral,
          },
        },
        {
          salt: delivery.envelope.salt,
          iv: delivery.envelope.iv,
          ciphertext: delivery.envelope.ciphertext,
        },
      );
      return inner ? await this.#channel.open(delivery.from, inner) : null;
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
