import { type Connection, connectionOf } from "./application.ts";
import { type AuthState, Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import {
  Conversations,
  type ConversationsState,
  type SendAttempt,
} from "./conversations.ts";
import type { AuthorizeResult } from "./devices.ts";
import { Listeners } from "./listeners.ts";
import { type Link, LocalTransport } from "./local.ts";
import { Messenger } from "./messenger.ts";
import type { PairState } from "./pairs.ts";
import { type InitiateResult, Pairing } from "./pairing.ts";
import {
  type PeerAuthorization,
  PeerEndpoint,
  type PeerIdentity,
} from "./peer.ts";
import { Presence, type PresenceState } from "./presence.ts";
import { type Relay, ServerRelay } from "./relay.ts";
import { Rosters } from "./rosters.ts";
import { WebSocketTransport } from "./socket.ts";
import type {
  Transport,
  TransportError,
  TransportKind,
  TransportState,
} from "./transport.ts";
import type { TrustState, TrustView } from "./trust.ts";
import type { LocalSession } from "./owner.ts";

export type Messaging = "starting" | "ready" | "unavailable";

export type PairingState = PairState | InitiateResult;

export type WhoamiResult =
  { ok: true; identity: string } | { ok: false; required: boolean };

export type PingResult = { ok: true; roundTrip: number } | { ok: false };

export interface DeviceAdmin {
  authorize(code: string): Promise<AuthorizeResult>;
  revoke(id: string): Promise<AuthorizeResult>;
}

export type SessionState = {
  kind: TransportKind;
  transport: TransportState;
  error: TransportError | null;
  auth: AuthState;
  connection: Connection;
  presence: PresenceState;
  messaging: Messaging;
  conversations: ConversationsState;
  rejected: number;
  pairing: PairingState | null;
  verification: TrustView | null;
  changed: readonly string[];
  peer: PeerIdentity | null;
  authorization: PeerAuthorization | null;
};

export type SessionOptions = {
  kind: TransportKind;
  local: LocalSession;
  url?: string;
  link?: Link | null;
};

type AuthSource = {
  readonly state: AuthState;
  onState(listener: (state: AuthState) => void): () => void;
};

const inactive: PresenceState = { status: "inactive", identities: [] };

const noConversations: ConversationsState = {
  connected: false,
  active: null,
  conversations: [],
};

export class Session {
  readonly kind: TransportKind;
  readonly #local: LocalSession;
  readonly #transport: Transport;
  readonly #client: Client | null;
  readonly #authenticator: Authenticator | null;
  readonly #endpoint: PeerEndpoint | null;
  readonly #source: AuthSource;
  readonly #presence: Presence | null;
  readonly #pairing: Pairing | null;
  readonly #messenger: Messenger | null;
  readonly #states = new Listeners<SessionState>();
  readonly #releases: (() => void)[] = [];
  #conversations: Conversations | null = null;
  #error: TransportError | null = null;
  #presenceState: PresenceState = inactive;
  #messaging: Messaging = "starting";
  #rejected = 0;
  #attempt: { peer: string; result: InitiateResult } | null = null;
  #focused: { peer: string | null; connected: boolean } = {
    peer: null,
    connected: false,
  };
  #focus = 0;
  #state: SessionState;
  #started = false;
  #disposed = false;

  constructor(options: SessionOptions) {
    const { local } = options;
    const { keys, devices, trust, prekeys, pairs, outbox } = local;
    this.kind = options.kind;
    this.#local = local;
    let relay: Relay;
    if (options.kind === "websocket") {
      this.#transport = new WebSocketTransport(options.url ?? "");
      this.#client = new Client(this.#transport);
      this.#authenticator = new Authenticator(this.#client, keys, devices);
      this.#endpoint = null;
      this.#source = this.#authenticator;
      this.#presence = new Presence(this.#client, this.#authenticator);
      relay = new ServerRelay(this.#client);
    } else {
      this.#transport = new LocalTransport(options.link ?? null);
      this.#client = null;
      this.#authenticator = null;
      this.#endpoint = new PeerEndpoint(this.#transport, {
        keys,
        devices,
        trust,
        prekeys: prekeys ?? { reserve: () => Promise.resolve(null) },
      });
      this.#source = this.#endpoint;
      this.#presence = null;
      relay = this.#endpoint;
    }
    const rosters = new Rosters(relay, trust);
    this.#pairing = prekeys
      ? new Pairing(relay, keys, rosters, prekeys, pairs)
      : null;
    this.#messenger = this.#pairing
      ? new Messenger(
          relay,
          this.#source,
          keys.identity,
          this.#pairing,
          rosters,
          outbox,
        )
      : null;
    this.#state = this.#snapshot();
  }

  get state(): SessionState {
    return this.#state;
  }

  get disposed(): boolean {
    return this.#disposed;
  }

  get admin(): DeviceAdmin | null {
    const client = this.#client;
    const devices = this.#local.devices;
    if (!client || !devices.canManage) {
      return null;
    }
    return {
      authorize: (code) => devices.authorize(client, code),
      revoke: (id) => devices.revoke(client, id),
    };
  }

  onState(listener: (state: SessionState) => void): () => void {
    return this.#states.add(listener);
  }

  start(): void {
    if (this.#started || this.#disposed) {
      return;
    }
    this.#started = true;
    const { trust, pairs } = this.#local;
    const target = this.#client ?? this.#transport;
    this.#releases.push(
      target.onState((state) => {
        if (state === "connected" || state === "disconnected") {
          this.#error = null;
        }
        this.#publish();
      }),
      target.onError((error) => {
        this.#error = error;
        this.#publish();
      }),
      this.#source.onState(() => this.#publish()),
      trust.onChange(() => this.#publish()),
      pairs.onChange(() => this.#publish()),
    );
    if (this.#presence) {
      const presence = this.#presence;
      this.#releases.push(
        presence.onState((state) => {
          this.#presenceState = state;
          this.#publish();
        }),
      );
      presence.start();
    }
    this.#authenticator?.start();
    if (this.#client) {
      this.#client.open();
    } else {
      this.#endpoint?.open();
    }
    this.#startMessaging();
    this.#publish();
  }

  dispose(): void {
    if (this.#disposed) {
      return;
    }
    this.#disposed = true;
    this.#focus += 1;
    this.#conversations?.stop();
    this.#pairing?.stop();
    this.#messenger?.stop();
    this.#presence?.stop();
    this.#authenticator?.stop();
    this.#endpoint?.close();
    this.#client?.close();
    this.#releases.splice(0).forEach((release) => release());
  }

  open(identity: string): boolean {
    return this.#conversations?.open(identity) ?? false;
  }

  close(): void {
    this.#conversations?.close();
  }

  send(body: string): SendAttempt {
    if (!this.#conversations) {
      return { accepted: false, reason: "authentication_required" };
    }
    return this.#conversations.send(body);
  }

  async verify(value: string): Promise<boolean> {
    const peer = this.#conversations?.state.active;
    return peer && !this.#disposed
      ? this.#local.trust.verify(peer, value)
      : false;
  }

  trustOf(identity: string): TrustState {
    return this.#local.trust.view(identity).state;
  }

  async whoami(): Promise<WhoamiResult> {
    const reply = await this.#client?.request({ type: "whoami", payload: {} });
    if (reply?.type === "whoami") {
      return { ok: true, identity: reply.payload.identity };
    }
    return {
      ok: false,
      required:
        reply?.type === "error" &&
        reply.payload.code === "authentication_required",
    };
  }

  async ping(): Promise<PingResult> {
    const sentAt = Date.now();
    const reply = await this.#client?.request({
      type: "ping",
      payload: { sentAt },
    });
    return reply?.type === "pong"
      ? { ok: true, roundTrip: Math.max(0, Date.now() - sentAt) }
      : { ok: false };
  }

  retry(): void {
    if (!this.#disposed) {
      this.#client?.retry();
    }
  }

  suspend(): void {
    if (!this.#disposed) {
      this.#client?.close();
    }
  }

  resume(): void {
    if (!this.#disposed) {
      this.#client?.open();
    }
  }

  #startMessaging(): void {
    const messenger = this.#messenger;
    const pairing = this.#pairing;
    if (!messenger || !pairing) {
      this.#messaging = "unavailable";
      return;
    }
    const { keys, history } = this.#local;
    history.restore().then(
      ({ restored, rejected }) => {
        if (this.#disposed) {
          return;
        }
        const conversations = new Conversations(messenger, keys.identity, {
          history,
          restored,
        });
        this.#conversations = conversations;
        this.#rejected = rejected;
        this.#releases.push(conversations.onState(() => this.#publish()));
        messenger.start();
        pairing.start(messenger);
        conversations.start();
        this.#messaging = "ready";
        this.#publish();
      },
      () => {
        if (!this.#disposed) {
          this.#messaging = "unavailable";
          this.#publish();
        }
      },
    );
  }

  #observeFocus(state: ConversationsState): void {
    const peer = state.active;
    const previous = this.#focused;
    this.#focused = { peer, connected: state.connected };
    if (
      !peer ||
      !state.connected ||
      (previous.peer === peer && previous.connected)
    ) {
      return;
    }
    const generation = ++this.#focus;
    const pairing = this.#pairing;
    void this.#local.trust.refresh(peer);
    void this.#messenger?.lookup(peer);
    if (pairing && pairing.summary(peer) === "none") {
      void pairing.initiate(peer).then((result) => {
        if (!this.#disposed && generation === this.#focus) {
          this.#attempt = { peer, result };
          this.#publish();
        }
      });
    }
  }

  #pairingState(active: string | null): PairingState | null {
    if (!active || !this.#pairing) {
      return null;
    }
    const current = this.#pairing.summary(active);
    if (current !== "none") {
      return current;
    }
    return this.#attempt?.peer === active ? this.#attempt.result : null;
  }

  #snapshot(): SessionState {
    const target = this.#client ?? this.#transport;
    const conversations = this.#conversations?.state ?? noConversations;
    const active = conversations.active;
    const trust = this.#local.trust;
    return {
      kind: this.kind,
      transport: target.state,
      error: this.#error,
      auth: this.#source.state,
      connection: connectionOf(target.state, this.#error, this.#source.state),
      presence: this.#presenceState,
      messaging: this.#messaging,
      conversations,
      rejected: this.#rejected,
      pairing: this.#pairingState(active),
      verification: active ? trust.view(active) : null,
      changed: conversations.conversations
        .map((c) => c.identity)
        .filter((identity) => trust.view(identity).state === "changed"),
      peer: this.#endpoint?.peer ?? null,
      authorization: this.#endpoint?.authorization ?? null,
    };
  }

  #publish(): void {
    if (this.#disposed) {
      return;
    }
    this.#state = this.#snapshot();
    this.#observeFocus(this.#state.conversations);
    this.#states.emit(this.#state);
  }
}
