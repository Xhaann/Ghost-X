import type { AuthState } from "./auth.ts";
import {
  decodeBase64Url,
  decodeBase64UrlRange,
  encodeBase64Url,
} from "./base64.ts";
import {
  type DeviceEntry,
  type Roster,
  rosterDevice,
  verifyRoster,
} from "./device.ts";
import type { DeviceStatus } from "./devices.ts";
import { isCanonicalExchangeKey } from "./fingerprint.ts";
import { isIdentity, parseIdentity, verify } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { Publication } from "./prekeys.ts";
import {
  type WireDeviceBundle,
  type WireEnvelope,
  type WireRoster,
  confirmSize,
  createId,
  deviceIdSize,
  exchangeKeySize,
  handshakeWireVersion,
  hasOnly,
  isEpoch,
  isFixed,
  isMessage,
  isMessageId,
  isObject,
  isValidId,
  nonceSize,
  parseDeviceBundle,
  parseWireRoster,
  signatureSize,
} from "./protocol.ts";
import { generateRatchetKey } from "./ratchet.ts";
import type {
  Acceptance,
  BundleResult,
  Delivery,
  InitiateOutcome,
  Initiation,
  Relay,
  RelayEvent,
  SendOutcome,
} from "./relay.ts";
import type { Transport, TransportKind } from "./transport.ts";
import type { Confirmation } from "./trust.ts";
import type { Keys } from "./vault.ts";

export const peerVersion = 1;
export const peerTimeout = 10_000;
export const peerRequestTimeout = 5000;
export const maxPeerPending = 64;
export const maxPeerUnacknowledged = 64;
export const maxPeerSetup = 8;
export const maxPeerBacklog = 128;
export const maxSessionFrame = 16 * 1024;

const tagSize = 16;

export type PeerFailure =
  | "malformed"
  | "oversized"
  | "version"
  | "self"
  | "unauthorized"
  | "signature"
  | "stale"
  | "protocol"
  | "integrity"
  | "timeout"
  | "limit"
  | "revoked"
  | "lost";

export type PeerHello = {
  version: number;
  nonce: string;
  share: string;
  identity: string;
  device: string;
  roster: WireRoster;
};

export type PeerIdentity = { identity: string; device: string };

export type PeerAuthorization = {
  roster: number;
  basis: "confirmed" | "unconfirmed";
  confirmed: { version: number; at: number } | null;
};

export type HandshakeFrame =
  | { type: "hello"; payload: PeerHello }
  | { type: "proof"; payload: { signature: string; confirm: string } }
  | { type: "sealed"; payload: { data: string } };

export type SessionFrame =
  | { type: "bundle"; id: string; payload: Record<string, never> }
  | { type: "bundled"; id: string; payload: { bundle: WireDeviceBundle } }
  | { type: "initiate"; id: string; payload: Omit<Initiation, "to"> }
  | { type: "initiated"; id: string; payload: Record<string, never> }
  | { type: "accept"; id: string; payload: Omit<Acceptance, "to"> }
  | { type: "accepted"; id: string; payload: Record<string, never> }
  | { type: "refused"; id: string; payload: Record<string, never> }
  | { type: "message"; payload: { id: string; ciphertext: string } }
  | { type: "ack"; payload: { id: string } };

type Reply = Extract<
  SessionFrame,
  { type: "bundled" | "initiated" | "accepted" | "refused" }
>;

export interface OwnDevices {
  readonly roster: Roster | null;
  readonly status: DeviceStatus;
  onChange(listener: (roster: Roster | null) => void): () => void;
}

export interface PeerTrust {
  observe(value: unknown): Promise<Roster | null>;
  roster(identity: string): Roster | null;
  confirmation(identity: string): Confirmation | null;
  onChange(listener: (identity: string) => void): () => void;
}

export interface BundleSource {
  reserve(): Promise<WireDeviceBundle | null>;
}

export type PeerOptions = {
  keys: Keys;
  devices: OwnDevices;
  trust: PeerTrust;
  prekeys: BundleSource;
  timeout?: number;
  requestTimeout?: number;
  frames?: number;
};

const encoder = new TextEncoder();
const transcriptContext = encoder.encode("ghostx/peer/v1\0");
const proofContext = encoder.encode("ghostx/peer/proof/v1\0");
const keyContext = encoder.encode("ghostx/peer/keys/v1\0");
const frameContext = encoder.encode("ghostx/peer/frame/v1\0");
const carriers: Record<TransportKind, number> = { websocket: 1, local: 2 };
const maxCounter = 2 ** 32 - 1;

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u32(value: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) {
      return a[i] - b[i];
    }
  }
  return a.length - b.length;
}

function isVersion(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 1 &&
    (value as number) <= 255
  );
}

function sealedSize(text: string): Uint8Array<ArrayBuffer> | null {
  return decodeBase64UrlRange(text, tagSize + 1, maxSessionFrame + tagSize);
}

export function parseHandshakeFrame(data: unknown): HandshakeFrame | null {
  if (typeof data !== "string") {
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(data);
  } catch {
    return null;
  }
  if (
    !isObject(value) ||
    !hasOnly(value, ["type", "payload"]) ||
    !isObject(value.payload)
  ) {
    return null;
  }
  const payload = value.payload;
  if (value.type === "hello") {
    const roster = parseWireRoster(payload.roster);
    if (
      hasOnly(payload, [
        "version",
        "nonce",
        "share",
        "identity",
        "device",
        "roster",
      ]) &&
      isVersion(payload.version) &&
      isFixed(payload.nonce, nonceSize) &&
      isFixed(payload.share, exchangeKeySize) &&
      isIdentity(payload.identity) &&
      isFixed(payload.device, deviceIdSize) &&
      roster
    ) {
      return {
        type: "hello",
        payload: {
          version: payload.version,
          nonce: payload.nonce,
          share: payload.share,
          identity: payload.identity,
          device: payload.device,
          roster,
        },
      };
    }
    return null;
  }
  if (value.type === "proof") {
    return hasOnly(payload, ["signature", "confirm"]) &&
      isFixed(payload.signature, signatureSize) &&
      isFixed(payload.confirm, confirmSize)
      ? {
          type: "proof",
          payload: { signature: payload.signature, confirm: payload.confirm },
        }
      : null;
  }
  if (value.type === "sealed") {
    return hasOnly(payload, ["data"]) &&
      typeof payload.data === "string" &&
      sealedSize(payload.data)
      ? { type: "sealed", payload: { data: payload.data } }
      : null;
  }
  return null;
}

export function parseSessionFrame(data: unknown): SessionFrame | null {
  if (typeof data !== "string") {
    return null;
  }
  let value: unknown;
  try {
    value = JSON.parse(data);
  } catch {
    return null;
  }
  if (!isObject(value) || !isObject(value.payload)) {
    return null;
  }
  const { type, id, payload } = value;
  const request = hasOnly(value, ["type", "id", "payload"]) && isValidId(id);
  const notice = hasOnly(value, ["type", "payload"]);
  if (
    (type === "bundle" ||
      type === "initiated" ||
      type === "accepted" ||
      type === "refused") &&
    request &&
    hasOnly(payload, [])
  ) {
    return { type, id: id as string, payload: {} };
  }
  if (type === "bundled" && request && hasOnly(payload, ["bundle"])) {
    const bundle = parseDeviceBundle(payload.bundle);
    return bundle ? { type, id: id as string, payload: { bundle } } : null;
  }
  if (
    type === "initiate" &&
    request &&
    hasOnly(payload, [
      "version",
      "device",
      "signed",
      "onetime",
      "ephemeral",
      "ratchet",
      "proof",
      "confirm",
    ]) &&
    payload.version === handshakeWireVersion &&
    isFixed(payload.device, deviceIdSize) &&
    isEpoch(payload.signed) &&
    (payload.onetime === null || isEpoch(payload.onetime)) &&
    isFixed(payload.ephemeral, exchangeKeySize) &&
    isFixed(payload.ratchet, exchangeKeySize) &&
    isFixed(payload.proof, signatureSize) &&
    isFixed(payload.confirm, confirmSize)
  ) {
    return {
      type,
      id: id as string,
      payload: {
        version: handshakeWireVersion,
        device: payload.device,
        signed: payload.signed,
        onetime: payload.onetime as number | null,
        ephemeral: payload.ephemeral,
        ratchet: payload.ratchet,
        proof: payload.proof,
        confirm: payload.confirm,
      },
    };
  }
  if (
    type === "accept" &&
    request &&
    hasOnly(payload, ["device", "ephemeral", "confirm"]) &&
    isFixed(payload.device, deviceIdSize) &&
    isFixed(payload.ephemeral, exchangeKeySize) &&
    isFixed(payload.confirm, confirmSize)
  ) {
    return {
      type,
      id: id as string,
      payload: {
        device: payload.device,
        ephemeral: payload.ephemeral,
        confirm: payload.confirm,
      },
    };
  }
  if (
    type === "message" &&
    notice &&
    hasOnly(payload, ["id", "ciphertext"]) &&
    isMessageId(payload.id) &&
    isMessage(payload.ciphertext)
  ) {
    return {
      type,
      payload: { id: payload.id, ciphertext: payload.ciphertext },
    };
  }
  if (
    type === "ack" &&
    notice &&
    hasOnly(payload, ["id"]) &&
    isMessageId(payload.id)
  ) {
    return { type, payload: { id: payload.id } };
  }
  return null;
}

function helloBytes(hello: PeerHello): Uint8Array<ArrayBuffer> | null {
  const nonce = decodeBase64Url(hello.nonce, nonceSize);
  const share = decodeBase64Url(hello.share, exchangeKeySize);
  const identity = parseIdentity(hello.identity);
  const device = decodeBase64Url(hello.device, deviceIdSize);
  const signature = decodeBase64Url(hello.roster.signature, signatureSize);
  if (
    !nonce ||
    !share ||
    !identity ||
    !device ||
    !signature ||
    !isVersion(hello.version) ||
    !Number.isSafeInteger(hello.roster.version) ||
    hello.roster.version < 1 ||
    hello.roster.version > maxCounter
  ) {
    return null;
  }
  return concat(
    Uint8Array.of(hello.version),
    nonce,
    share,
    identity,
    device,
    u32(hello.roster.version),
    signature,
  );
}

function position(own: PeerHello, other: PeerHello): 0 | 1 | null {
  const a = decodeBase64Url(own.nonce, nonceSize);
  const b = decodeBase64Url(other.nonce, nonceSize);
  if (!a || !b) {
    return null;
  }
  const order = compare(a, b);
  return order === 0 ? null : order < 0 ? 0 : 1;
}

export function peerTranscript(
  kind: TransportKind,
  own: PeerHello,
  other: PeerHello,
): Uint8Array<ArrayBuffer> | null {
  const place = position(own, other);
  const a = helloBytes(own);
  const b = helloBytes(other);
  if (place === null || !a || !b) {
    return null;
  }
  const [first, second] = place === 0 ? [a, b] : [b, a];
  return concat(
    transcriptContext,
    Uint8Array.of(carriers[kind]),
    first,
    second,
  );
}

export async function peerProofMessage(
  kind: TransportKind,
  signer: PeerHello,
  other: PeerHello,
): Promise<Uint8Array<ArrayBuffer> | null> {
  const transcript = peerTranscript(kind, signer, other);
  const place = position(signer, other);
  if (!transcript || place === null) {
    return null;
  }
  const digest = await crypto.subtle.digest("SHA-256", transcript);
  return concat(proofContext, new Uint8Array(digest), Uint8Array.of(place));
}

type ChannelKeys = {
  send: CryptoKey;
  receive: CryptoKey;
  confirm: CryptoKey;
  expect: CryptoKey;
  digest: Uint8Array<ArrayBuffer>;
};

async function channelKeys(
  kind: TransportKind,
  own: PeerHello,
  other: PeerHello,
  privateKey: CryptoKey,
): Promise<ChannelKeys | null> {
  const share = decodeBase64Url(other.share, exchangeKeySize);
  const transcript = peerTranscript(kind, own, other);
  const place = position(own, other);
  if (
    !share ||
    !isCanonicalExchangeKey(share) ||
    !transcript ||
    place === null
  ) {
    return null;
  }
  try {
    const peerKey = await crypto.subtle.importKey(
      "raw",
      share,
      { name: "X25519" },
      false,
      [],
    );
    const secret = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "X25519", public: peerKey },
        privateKey,
        256,
      ),
    );
    if (secret.every((b) => b === 0)) {
      return null;
    }
    const material = await crypto.subtle.importKey(
      "raw",
      secret,
      "HKDF",
      false,
      ["deriveKey"],
    );
    secret.fill(0);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", transcript),
    );
    const params = (purpose: number, direction: number) => ({
      name: "HKDF",
      hash: "SHA-256",
      salt: digest,
      info: concat(keyContext, Uint8Array.of(purpose, direction)),
    });
    const frame = (direction: number) =>
      crypto.subtle.deriveKey(
        params(0, direction),
        material,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      );
    const confirmation = (direction: number) =>
      crypto.subtle.deriveKey(
        params(1, direction),
        material,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign", "verify"],
      );
    const [frame0, frame1, confirm0, confirm1] = await Promise.all([
      frame(0),
      frame(1),
      confirmation(0),
      confirmation(1),
    ]);
    return place === 0
      ? {
          send: frame0,
          receive: frame1,
          confirm: confirm0,
          expect: confirm1,
          digest,
        }
      : {
          send: frame1,
          receive: frame0,
          confirm: confirm1,
          expect: confirm0,
          digest,
        };
  } catch {
    return null;
  }
}

function frameIv(counter: number): Uint8Array<ArrayBuffer> {
  const iv = new Uint8Array(12);
  new DataView(iv.buffer).setUint32(8, counter);
  return iv;
}

type Session = {
  peer: PeerIdentity;
  entry: DeviceEntry;
  roster: Roster;
  keys: ChannelKeys;
  sent: number;
  received: number;
};

type Handshake = {
  hello: PeerHello;
  privateKey: CryptoKey;
  verified: {
    other: PeerHello;
    entry: DeviceEntry;
    roster: Roster;
    keys: ChannelKeys;
  } | null;
};

type Waiter = (outcome: SendOutcome) => void;

export class PeerEndpoint implements Relay {
  readonly authoritative = false;
  readonly #transport: Transport;
  readonly #keys: Keys;
  readonly #devices: OwnDevices;
  readonly #trust: PeerTrust;
  readonly #prekeys: BundleSource;
  readonly #timeout: number;
  readonly #requestTimeout: number;
  readonly #states = new Listeners<AuthState>();
  readonly #events = new Listeners<RelayEvent>();
  readonly #replies = new Map<string, (reply: Reply | null) => void>();
  readonly #sends = new Map<
    string,
    { waiters: Waiter[]; timer: ReturnType<typeof setTimeout> }
  >();
  readonly #unacknowledged = new Set<string>();
  readonly #frames: number;
  #state: AuthState = "unauthenticated";
  #failure: PeerFailure | null = null;
  #generation = 0;
  #handshake: Handshake | null = null;
  #session: Session | null = null;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #incoming: Promise<void> = Promise.resolve();
  #outgoing: Promise<void> = Promise.resolve();
  #backlog = 0;
  #setup = 0;
  #watch: (() => void) | null = null;
  #closed = false;
  readonly #detach: () => void;

  constructor(transport: Transport, options: PeerOptions) {
    this.#transport = transport;
    this.#keys = options.keys;
    this.#devices = options.devices;
    this.#trust = options.trust;
    this.#prekeys = options.prekeys;
    this.#timeout = options.timeout ?? peerTimeout;
    this.#requestTimeout = options.requestTimeout ?? peerRequestTimeout;
    this.#frames = Math.min(options.frames ?? maxCounter, maxCounter);
    const releases = [
      transport.onState((state) => {
        if (state === "connected") {
          this.#begin();
        } else if (
          this.#state === "authenticating" ||
          this.#state === "authenticated"
        ) {
          this.#reset();
          this.#setState("unauthenticated");
        }
      }),
      transport.onData((frame) => this.#receive(frame)),
      transport.onError((error) => {
        if (error === "oversized" || error === "malformed") {
          this.#fail(error);
        }
      }),
    ];
    this.#detach = () => releases.forEach((release) => release());
  }

  get closed(): boolean {
    return this.#closed;
  }

  get kind(): TransportKind {
    return this.#transport.kind;
  }

  get state(): AuthState {
    return this.#state;
  }

  get failure(): PeerFailure | null {
    return this.#failure;
  }

  get peer(): PeerIdentity | null {
    return this.#state === "authenticated" && this.#session
      ? this.#session.peer
      : null;
  }

  get authorization(): PeerAuthorization | null {
    const session = this.#session;
    if (this.#state !== "authenticated" || !session) {
      return null;
    }
    const confirmation = this.#trust.confirmation(session.peer.identity);
    const confirmed =
      confirmation !== null &&
      confirmation.version === session.roster.version &&
      confirmation.signature === session.roster.signature;
    return {
      roster: session.roster.version,
      basis: confirmed ? "confirmed" : "unconfirmed",
      confirmed: confirmation
        ? { version: confirmation.version, at: confirmation.at }
        : null,
    };
  }

  onState(listener: (state: AuthState) => void): () => void {
    return this.#states.add(listener);
  }

  onEvent(listener: (event: RelayEvent) => void): () => void {
    return this.#events.add(listener);
  }

  open(): void {
    if (
      this.#closed ||
      this.#state === "authenticating" ||
      this.#state === "authenticated"
    ) {
      return;
    }
    this.#failure = null;
    this.#setState("unauthenticated");
    if (!this.#authorized()) {
      return;
    }
    if (this.#transport.state === "connected") {
      this.#begin();
    } else {
      this.#transport.open();
    }
  }

  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#detach();
    this.#reset();
    this.#setState("unauthenticated");
    this.#transport.close();
  }

  reaches(peer: string, device: string): boolean {
    const current = this.peer;
    return current?.identity === peer && current.device === device;
  }

  async roster(identity: string): Promise<WireRoster | null> {
    const session = this.#session;
    return this.#state === "authenticated" &&
      session?.peer.identity === identity
      ? session.roster
      : null;
  }

  async publish(publication: Publication): Promise<number | null> {
    return this.#state === "authenticated" ? publication.onetime.length : null;
  }

  async bundle(identity: string): Promise<BundleResult> {
    const peer = this.peer;
    if (!peer || peer.identity !== identity) {
      return "unavailable";
    }
    const reply = await this.#request({ type: "bundle", payload: {} });
    if (
      reply?.type === "bundled" &&
      reply.payload.bundle.device === peer.device
    ) {
      return { bundles: [reply.payload.bundle] };
    }
    return reply?.type === "refused" ? "unavailable" : "failed";
  }

  async initiate(initiation: Initiation): Promise<InitiateOutcome> {
    const peer = this.peer;
    if (
      !peer ||
      peer.identity !== initiation.to ||
      peer.device !== initiation.device
    ) {
      return "unavailable";
    }
    const { to: _, ...payload } = initiation;
    const reply = await this.#request({ type: "initiate", payload });
    return reply?.type === "initiated" ? "initiated" : "failed";
  }

  async accept(acceptance: Acceptance): Promise<boolean> {
    const peer = this.peer;
    if (
      !peer ||
      peer.identity !== acceptance.to ||
      peer.device !== acceptance.device
    ) {
      return false;
    }
    const { to: _, ...payload } = acceptance;
    const reply = await this.#request({ type: "accept", payload });
    return reply?.type === "accepted";
  }

  send(
    to: string,
    id: string,
    envelopes: WireEnvelope[],
  ): Promise<SendOutcome> {
    const peer = this.peer;
    if (
      !peer ||
      peer.identity !== to ||
      envelopes.length !== 1 ||
      envelopes[0].device !== peer.device
    ) {
      return Promise.resolve(null);
    }
    const ciphertext = envelopes[0].ciphertext;
    if (!isMessageId(id) || !isMessage(ciphertext)) {
      return Promise.resolve("invalid_payload");
    }
    const existing = this.#sends.get(id);
    if (!existing && this.#sends.size >= maxPeerPending) {
      return Promise.resolve(null);
    }
    return new Promise<SendOutcome>((resolve) => {
      const entry = existing ?? {
        waiters: [],
        timer: setTimeout(() => this.#settle(id, null), this.#requestTimeout),
      };
      entry.waiters.push(resolve);
      this.#sends.set(id, entry);
      void this.#transmit({
        type: "message",
        payload: { id, ciphertext },
      }).then((sent) => {
        if (!sent) {
          this.#settle(id, null);
        }
      });
    });
  }

  async fetch(): Promise<void> {}

  acknowledge(delivery: Delivery): void {
    const peer = this.peer;
    if (peer?.identity !== delivery.from || peer.device !== delivery.device) {
      return;
    }
    this.#unacknowledged.delete(delivery.id);
    void this.#transmit({ type: "ack", payload: { id: delivery.id } });
  }

  clear(): void {}

  #authorized(): boolean {
    const status = this.#devices.status;
    if (status === "authorized" && this.#devices.roster) {
      return true;
    }
    this.#fail(
      status === "pending" ? "unauthorized" : "revoked",
      status === "pending" ? "pending" : "revoked",
    );
    return false;
  }

  #begin(): void {
    this.#reset();
    const roster = this.#devices.roster;
    if (!this.#authorized() || !roster) {
      return;
    }
    const generation = this.#generation;
    this.#setState("authenticating");
    this.#timer = setTimeout(() => {
      if (generation === this.#generation) {
        this.#fail("timeout");
      }
    }, this.#timeout);
    this.#incoming = this.#greet(generation, roster).catch(() => {
      if (generation === this.#generation) {
        this.#fail("protocol");
      }
    });
  }

  async #greet(generation: number, roster: Roster): Promise<void> {
    const pair = await generateRatchetKey().catch(() => null);
    if (generation !== this.#generation) {
      return;
    }
    if (!pair) {
      this.#fail("protocol");
      return;
    }
    const hello: PeerHello = {
      version: peerVersion,
      nonce: encodeBase64Url(crypto.getRandomValues(new Uint8Array(nonceSize))),
      share: encodeBase64Url(pair.publicKey),
      identity: this.#keys.identity,
      device: this.#keys.deviceId,
      roster,
    };
    this.#handshake = { hello, privateKey: pair.privateKey, verified: null };
    this.#write({ type: "hello", payload: hello });
  }

  #receive(frame: string): void {
    if (this.#state !== "authenticating" && this.#state !== "authenticated") {
      return;
    }
    if (this.#backlog >= maxPeerBacklog) {
      this.#fail("limit");
      return;
    }
    this.#backlog += 1;
    const generation = this.#generation;
    this.#incoming = this.#incoming
      .then(() => this.#process(frame, generation))
      .catch(() => {
        if (generation === this.#generation) {
          this.#fail("protocol");
        }
      })
      .finally(() => {
        if (generation === this.#generation) {
          this.#backlog -= 1;
        }
      });
  }

  async #process(data: string, generation: number): Promise<void> {
    if (generation !== this.#generation) {
      return;
    }
    const frame = parseHandshakeFrame(data);
    if (!frame) {
      this.#fail("malformed");
      return;
    }
    const handshake = this.#handshake;
    const session = this.#session;
    if (session) {
      if (frame.type !== "sealed") {
        this.#fail("protocol");
        return;
      }
      await this.#open(frame.payload.data, session, generation);
      return;
    }
    if (!handshake) {
      this.#fail("protocol");
      return;
    }
    if (!handshake.verified) {
      if (frame.type !== "hello") {
        this.#fail("protocol");
        return;
      }
      await this.#hello(frame.payload, handshake, generation);
      return;
    }
    if (frame.type !== "proof") {
      this.#fail("protocol");
      return;
    }
    await this.#proof(frame.payload, handshake, generation);
  }

  async #hello(
    other: PeerHello,
    handshake: Handshake,
    generation: number,
  ): Promise<void> {
    if (other.version !== peerVersion) {
      this.#fail("version");
      return;
    }
    if (
      other.identity === this.#keys.identity ||
      other.device === this.#keys.deviceId
    ) {
      this.#fail("self");
      return;
    }
    if (position(handshake.hello, other) === null) {
      this.#fail("protocol");
      return;
    }
    const roster = await verifyRoster(other.roster);
    if (generation !== this.#generation) {
      return;
    }
    const entry =
      roster && roster.identity === other.identity
        ? rosterDevice(roster, other.device)
        : null;
    if (!roster || !entry) {
      this.#fail("unauthorized");
      return;
    }
    const keys = await channelKeys(
      this.kind,
      handshake.hello,
      other,
      handshake.privateKey,
    );
    const message = await peerProofMessage(this.kind, handshake.hello, other);
    const signature = message && (await this.#keys.device.sign(message));
    const confirm =
      keys &&
      new Uint8Array(
        await crypto.subtle.sign("HMAC", keys.confirm, keys.digest),
      );
    if (generation !== this.#generation) {
      return;
    }
    if (!keys || !signature || !confirm) {
      this.#fail("protocol");
      return;
    }
    handshake.verified = { other, entry, roster, keys };
    this.#write({
      type: "proof",
      payload: { signature, confirm: encodeBase64Url(confirm) },
    });
  }

  async #proof(
    proof: { signature: string; confirm: string },
    handshake: Handshake,
    generation: number,
  ): Promise<void> {
    const verified = handshake.verified;
    if (!verified) {
      this.#fail("protocol");
      return;
    }
    const { other, entry, roster, keys } = verified;
    const message = await peerProofMessage(this.kind, other, handshake.hello);
    const valid =
      message !== null &&
      (await verify(entry.signing, message, proof.signature));
    const tag = decodeBase64Url(proof.confirm, confirmSize);
    const confirmed =
      tag !== null &&
      (await crypto.subtle.verify("HMAC", keys.expect, tag, keys.digest));
    if (generation !== this.#generation) {
      return;
    }
    if (!valid) {
      this.#fail("signature");
      return;
    }
    if (!confirmed) {
      this.#fail("integrity");
      return;
    }
    const observed = await this.#trust.observe(roster);
    if (generation !== this.#generation) {
      return;
    }
    if (!observed || !rosterDevice(observed, entry.id)) {
      this.#fail("stale");
      return;
    }
    if (this.#devices.status !== "authorized") {
      this.#fail("revoked", "revoked");
      return;
    }
    this.#clearTimer();
    this.#handshake = null;
    this.#session = {
      peer: { identity: other.identity, device: other.device },
      entry,
      roster: observed,
      keys,
      sent: 0,
      received: 0,
    };
    const releases = [
      this.#trust.onChange((identity) => {
        if (identity === other.identity) {
          this.#recheck();
        }
      }),
      this.#devices.onChange(() => this.#recheck()),
    ];
    this.#watch = () => releases.forEach((release) => release());
    this.#setState("authenticated");
    this.#recheck();
  }

  #recheck(): void {
    const session = this.#session;
    if (this.#state !== "authenticated" || !session) {
      return;
    }
    if (this.#devices.status !== "authorized") {
      this.#fail("revoked", "revoked");
      return;
    }
    const current = this.#trust.roster(session.peer.identity);
    if (current && !rosterDevice(current, session.peer.device)) {
      this.#fail("revoked");
    }
  }

  async #open(
    data: string,
    session: Session,
    generation: number,
  ): Promise<void> {
    const sealed = sealedSize(data);
    if (!sealed) {
      this.#fail("integrity");
      return;
    }
    if (session.received >= this.#frames) {
      this.#fail("limit");
      return;
    }
    const counter = session.received;
    session.received += 1;
    let plaintext: ArrayBuffer;
    try {
      plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: frameIv(counter), additionalData: frameContext },
        session.keys.receive,
        sealed,
      );
    } catch {
      if (generation === this.#generation) {
        this.#fail("integrity");
      }
      return;
    }
    if (generation !== this.#generation) {
      return;
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    } catch {
      this.#fail("malformed");
      return;
    }
    const frame = parseSessionFrame(text);
    if (!frame) {
      this.#fail("malformed");
      return;
    }
    await this.#dispatch(frame, session, generation);
  }

  async #dispatch(
    frame: SessionFrame,
    session: Session,
    generation: number,
  ): Promise<void> {
    const peer = session.peer;
    switch (frame.type) {
      case "bundle": {
        if (!this.#count()) {
          return;
        }
        const bundle = await this.#prekeys.reserve().catch(() => null);
        if (generation !== this.#generation) {
          return;
        }
        await this.#transmit(
          bundle && bundle.device === this.#keys.deviceId
            ? { type: "bundled", id: frame.id, payload: { bundle } }
            : { type: "refused", id: frame.id, payload: {} },
        );
        return;
      }
      case "initiate":
        if (!this.#count()) {
          return;
        }
        if (frame.payload.device !== this.#keys.deviceId) {
          this.#fail("protocol");
          return;
        }
        await this.#transmit({ type: "initiated", id: frame.id, payload: {} });
        this.#events.emit({
          type: "initiation",
          payload: {
            version: handshakeWireVersion,
            from: peer.identity,
            device: peer.device,
            signed: frame.payload.signed,
            onetime: frame.payload.onetime,
            ephemeral: frame.payload.ephemeral,
            ratchet: frame.payload.ratchet,
            proof: frame.payload.proof,
            confirm: frame.payload.confirm,
          },
        });
        return;
      case "accept":
        if (!this.#count()) {
          return;
        }
        if (frame.payload.device !== this.#keys.deviceId) {
          this.#fail("protocol");
          return;
        }
        await this.#transmit({ type: "accepted", id: frame.id, payload: {} });
        this.#events.emit({
          type: "acceptance",
          payload: {
            from: peer.identity,
            device: peer.device,
            ephemeral: frame.payload.ephemeral,
            confirm: frame.payload.confirm,
          },
        });
        return;
      case "message":
        if (
          !this.#unacknowledged.has(frame.payload.id) &&
          this.#unacknowledged.size >= maxPeerUnacknowledged
        ) {
          this.#fail("limit");
          return;
        }
        this.#unacknowledged.add(frame.payload.id);
        this.#events.emit({
          type: "message",
          payload: {
            id: frame.payload.id,
            from: peer.identity,
            device: peer.device,
            ciphertext: frame.payload.ciphertext,
          },
        });
        return;
      case "ack":
        this.#settle(frame.payload.id, "queued");
        return;
      default:
        this.#replies.get(frame.id)?.(frame);
    }
  }

  #count(): boolean {
    this.#setup += 1;
    if (this.#setup > maxPeerSetup) {
      this.#fail("limit");
      return false;
    }
    return true;
  }

  #request(
    frame:
      | { type: "bundle"; payload: Record<string, never> }
      | { type: "initiate"; payload: Omit<Initiation, "to"> }
      | { type: "accept"; payload: Omit<Acceptance, "to"> },
  ): Promise<Reply | null> {
    if (
      this.#state !== "authenticated" ||
      this.#replies.size >= maxPeerPending
    ) {
      return Promise.resolve(null);
    }
    const id = createId();
    return new Promise((resolve) => {
      const finish = (reply: Reply | null) => {
        clearTimeout(timer);
        this.#replies.delete(id);
        resolve(reply);
      };
      const timer = setTimeout(() => finish(null), this.#requestTimeout);
      this.#replies.set(id, finish);
      void this.#transmit({ ...frame, id } as SessionFrame).then((sent) => {
        if (!sent) {
          finish(null);
        }
      });
    });
  }

  #settle(id: string, outcome: SendOutcome): void {
    const entry = this.#sends.get(id);
    if (!entry) {
      return;
    }
    clearTimeout(entry.timer);
    this.#sends.delete(id);
    entry.waiters.forEach((waiter) => waiter(outcome));
    const peer = this.peer;
    if (outcome === "queued" && peer) {
      this.#events.emit({
        type: "receipt",
        payload: {
          to: peer.identity,
          device: peer.device,
          id,
          status: "delivered",
        },
      });
    }
  }

  #transmit(frame: SessionFrame): Promise<boolean> {
    const session = this.#session;
    const generation = this.#generation;
    if (!session || this.#state !== "authenticated") {
      return Promise.resolve(false);
    }
    const run = this.#outgoing.then(async () => {
      if (generation !== this.#generation) {
        return false;
      }
      if (session.sent >= this.#frames) {
        this.#fail("limit");
        return false;
      }
      const counter = session.sent;
      session.sent += 1;
      const sealed = await crypto.subtle
        .encrypt(
          {
            name: "AES-GCM",
            iv: frameIv(counter),
            additionalData: frameContext,
          },
          session.keys.send,
          encoder.encode(JSON.stringify(frame)),
        )
        .catch(() => null);
      if (generation !== this.#generation) {
        return false;
      }
      if (!sealed) {
        this.#fail("protocol");
        return false;
      }
      return this.#write({
        type: "sealed",
        payload: { data: encodeBase64Url(new Uint8Array(sealed)) },
      });
    });
    this.#outgoing = run.then(
      () => {},
      () => {},
    );
    return run.catch(() => false);
  }

  #write(frame: HandshakeFrame): boolean {
    if (this.#transport.send(JSON.stringify(frame)) === "sent") {
      return true;
    }
    this.#fail("lost");
    return false;
  }

  #fail(failure: PeerFailure, state: AuthState = "failed"): void {
    if (
      this.#state === "failed" ||
      this.#state === "revoked" ||
      this.#state === "pending"
    ) {
      return;
    }
    this.#reset();
    this.#failure = failure;
    this.#setState(state);
    this.#transport.close();
  }

  #reset(): void {
    this.#generation += 1;
    this.#clearTimer();
    this.#watch?.();
    this.#watch = null;
    this.#handshake = null;
    this.#session = null;
    this.#backlog = 0;
    this.#setup = 0;
    this.#unacknowledged.clear();
    for (const finish of [...this.#replies.values()]) {
      finish(null);
    }
    for (const id of [...this.#sends.keys()]) {
      this.#settle(id, null);
    }
  }

  #clearTimer(): void {
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
  }

  #setState(state: AuthState): void {
    if (this.#state === state) {
      return;
    }
    this.#state = state;
    this.#states.emit(state);
  }
}
