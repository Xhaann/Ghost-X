import type { Client } from "./client.ts";
import {
  type ExchangeKey,
  type KeyBundle,
  verifyBundle,
} from "./encryption.ts";
import {
  handshakeVersion,
  initiate,
  respond,
  verifyPrekey,
} from "./handshake.ts";
import { type IdentityKey, isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { MessengerState } from "./messenger.ts";
import type { PairState, Pairs } from "./pairs.ts";
import { type PrekeyStore, lowWater } from "./prekeys.ts";
import {
  type ServerMessage,
  exchangeKeySize,
  isMessageId,
  isValidBody,
  messageIdLength,
} from "./protocol.ts";
import { decodeBase64Url } from "./base64.ts";
import {
  type Generate,
  decodeHeader,
  generateRatchetKey,
  initiatorState,
  ratchetDecrypt,
  ratchetEncrypt,
  responderState,
} from "./ratchet.ts";

export type InitiateResult =
  "pending" | "established" | "unavailable" | "invalid_bundle" | "failed";

export type OpenResult =
  "accepted" | "deferred" | "rejected" | "failed" | "missing";

export interface Channel {
  establish(peer: string): Promise<InitiateResult>;
  initiate(peer: string): Promise<InitiateResult>;
  onChange(listener: (peer: string) => void): () => void;
  seal(
    peer: string,
    id: string,
    body: string,
  ): Promise<Uint8Array<ArrayBuffer> | null>;
  open(
    peer: string,
    id: string,
    data: Uint8Array<ArrayBuffer>,
    record: (body: string) => Promise<boolean>,
  ): Promise<OpenResult>;
}

type StateSource = {
  readonly state: MessengerState;
  onState(listener: (state: MessengerState) => void): () => void;
};

type Initiation = Extract<ServerMessage, { type: "initiation" }>["payload"];
type Acceptance = Extract<ServerMessage, { type: "acceptance" }>["payload"];

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const establishTimeout = 5000;

export function frame(id: string, body: string): Uint8Array<ArrayBuffer> {
  const head = encoder.encode(id);
  const tail = encoder.encode(body);
  const out = new Uint8Array(head.length + tail.length);
  out.set(head);
  out.set(tail, head.length);
  return out;
}

export function unframe(plaintext: Uint8Array, id: string): string | null {
  try {
    if (
      plaintext.length <= messageIdLength ||
      decoder.decode(plaintext.subarray(0, messageIdLength)) !== id
    ) {
      return null;
    }
    const body = decoder.decode(plaintext.subarray(messageIdLength));
    return isValidBody(body) ? body : null;
  } catch {
    return null;
  }
}

export class Pairing implements Channel {
  readonly #client: Client;
  readonly #identity: IdentityKey;
  readonly #exchange: ExchangeKey;
  readonly #prekeys: PrekeyStore;
  readonly #pairs: Pairs;
  readonly #generate: Generate;
  readonly #bundles = new Listeners<KeyBundle>();
  readonly #inflight = new Map<string, Promise<InitiateResult>>();
  #source: StateSource | null = null;
  #queue: Promise<void> = Promise.resolve();
  #published = false;
  #generation = 0;
  #detach: (() => void) | null = null;

  constructor(
    client: Client,
    identity: IdentityKey,
    exchange: ExchangeKey,
    prekeys: PrekeyStore,
    pairs: Pairs,
    generate: Generate = generateRatchetKey,
  ) {
    this.#client = client;
    this.#identity = identity;
    this.#exchange = exchange;
    this.#prekeys = prekeys;
    this.#pairs = pairs;
    this.#generate = generate;
  }

  get published(): boolean {
    return this.#published;
  }

  onKey(listener: (bundle: KeyBundle) => void): () => void {
    return this.#bundles.add(listener);
  }

  state(peer: string): PairState {
    return this.#pairs.state(peer);
  }

  onChange(listener: (peer: string) => void): () => void {
    return this.#pairs.onChange(listener);
  }

  start(source: StateSource): void {
    if (this.#detach) {
      return;
    }
    this.#source = source;
    const detach = [
      this.#client.onMessage((message) => {
        if (message.type === "initiation") {
          this.#enqueue(() => this.#respond(message.payload));
        } else if (message.type === "acceptance") {
          this.#enqueue(() => this.#accept(message.payload));
        }
      }),
      source.onState((state) => {
        this.#generation += 1;
        this.#published = false;
        if (state.active) {
          void this.publish();
        }
      }),
    ];
    this.#detach = () => detach.forEach((release) => release());
    if (source.state.active) {
      void this.publish();
    }
  }

  stop(): void {
    this.#detach?.();
    this.#detach = null;
    this.#generation += 1;
    this.#published = false;
  }

  async publish(): Promise<boolean> {
    const generation = this.#generation;
    for (let round = 0; round < 2; round++) {
      const publication = await this.#prekeys.publication();
      if (!publication || generation !== this.#generation) {
        return false;
      }
      const reply = await this.#client.request({
        type: "prekeys",
        payload: publication,
      });
      if (reply?.type !== "prekeys" || generation !== this.#generation) {
        return false;
      }
      this.#published = true;
      if (!(await this.#prekeys.replenish(reply.payload.available))) {
        return true;
      }
    }
    return true;
  }

  initiate(peer: string): Promise<InitiateResult> {
    const existing = this.#inflight.get(peer);
    if (existing) {
      return existing;
    }
    const run = this.#initiate(peer, false).finally(() =>
      this.#inflight.delete(peer),
    );
    this.#inflight.set(peer, run);
    return run;
  }

  async establish(peer: string): Promise<InitiateResult> {
    if (this.#pairs.state(peer) === "established") {
      return "established";
    }
    const established = new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        release();
        resolve(false);
      }, establishTimeout);
      const release = this.#pairs.onChange((changed) => {
        if (changed === peer && this.#pairs.state(peer) === "established") {
          clearTimeout(timer);
          release();
          resolve(true);
        }
      });
    });
    const result = await this.#initiate(peer, true);
    if (result !== "pending") {
      return result;
    }
    return (await established) ? "established" : "pending";
  }

  async seal(
    peer: string,
    id: string,
    body: string,
  ): Promise<Uint8Array<ArrayBuffer> | null> {
    if (!isValidBody(body) || !isMessageId(id)) {
      return null;
    }
    return this.#pairs.transact(peer, async (state) => {
      const sealed = await ratchetEncrypt(state, frame(id, body));
      return sealed && { state: sealed.state, value: sealed.message };
    });
  }

  async open(
    peer: string,
    id: string,
    data: Uint8Array<ArrayBuffer>,
    record: (body: string) => Promise<boolean>,
  ): Promise<OpenResult> {
    const header = decodeHeader(data);
    if (!header || !isMessageId(id)) {
      return "rejected";
    }
    const current = this.#pairs.state(peer);
    if (current === "none") {
      return "missing";
    }
    if (current === "pending") {
      return header.session === this.#pairs.id(peer) ? "deferred" : "rejected";
    }
    let recorded = false;
    let failed = false;
    const opened = await this.#pairs.transact(peer, async (state) => {
      const result = await ratchetDecrypt(state, data, this.#generate);
      const body = result && unframe(result.plaintext, id);
      if (!result || body === null) {
        return null;
      }
      const stored = await record(body).catch(() => false);
      if (!stored) {
        failed = true;
        return null;
      }
      recorded = true;
      return { state: result.state, value: true };
    });
    if (opened) {
      return "accepted";
    }
    return recorded || failed ? "failed" : "rejected";
  }

  async #initiate(peer: string, replace: boolean): Promise<InitiateResult> {
    const current = this.#pairs.state(peer);
    if (current === "established" || (current === "pending" && !replace)) {
      return current;
    }
    if (
      !this.#source?.state.active ||
      !isIdentity(peer) ||
      peer === this.#identity.identity
    ) {
      return "failed";
    }
    const reply = await this.#client.request({
      type: "bundle",
      payload: { identity: peer },
    });
    if (reply?.type === "error") {
      return reply.payload.code === "recipient_unavailable"
        ? "unavailable"
        : "failed";
    }
    if (reply?.type !== "bundle" || reply.payload.identity !== peer) {
      return "failed";
    }
    const staticBundle: KeyBundle = {
      identity: peer,
      key: reply.payload.key,
      signature: reply.payload.signature,
    };
    const staticKey = await verifyBundle(staticBundle);
    if (!staticKey) {
      return "invalid_bundle";
    }
    this.#bundles.emit(staticBundle);
    const device = reply.payload.bundles[0];
    const signed = await verifyPrekey(
      "signed",
      peer,
      staticKey,
      device.device,
      device.signed,
    );
    const onetime = device.onetime
      ? await verifyPrekey(
          "onetime",
          peer,
          staticKey,
          device.device,
          device.onetime,
        )
      : null;
    if (!signed || (device.onetime && !onetime)) {
      return "invalid_bundle";
    }
    const result = await initiate(
      { identity: this.#identity, exchange: this.#exchange },
      {
        identity: peer,
        staticKey,
        device: device.device,
        signed: { id: device.signed.id, key: signed },
        onetime:
          device.onetime && onetime
            ? { id: device.onetime.id, key: onetime }
            : null,
      },
      this.#generate,
    );
    if (!result) {
      return "failed";
    }
    const ratchet = await initiatorState(
      result.pending.secret,
      signed,
      {
        initiator: this.#identity.identity,
        responder: peer,
        session: result.pending.id,
        role: "initiator",
      },
      result.pending.ratchet,
    );
    if (
      !(await this.#pairs.savePending(
        peer,
        result.initiation.ephemeral,
        result.pending,
        ratchet,
      ))
    ) {
      return "failed";
    }
    const sent = await this.#client.request({
      type: "initiate",
      payload: { version: handshakeVersion, to: peer, ...result.initiation },
    });
    if (sent?.type !== "initiated") {
      await this.#pairs.discard(peer, result.pending.id);
      return sent?.type === "error" &&
        sent.payload.code === "recipient_unavailable"
        ? "unavailable"
        : "failed";
    }
    return this.#pairs.state(peer) === "established"
      ? "established"
      : "pending";
  }

  #enqueue(task: () => Promise<void>): void {
    this.#queue = this.#queue.then(task).catch(() => {});
  }

  async #respond(initiation: Initiation): Promise<void> {
    if (initiation.device !== this.#prekeys.device) {
      return;
    }
    if (
      this.#pairs.state(initiation.from) === "pending" &&
      this.#identity.identity < initiation.from
    ) {
      return;
    }
    const sender: KeyBundle = {
      identity: initiation.from,
      key: initiation.key,
      signature: initiation.signature,
    };
    const fromStatic = await verifyBundle(sender);
    const peerRatchet = decodeBase64Url(initiation.ratchet, exchangeKeySize);
    if (!fromStatic || !peerRatchet) {
      return;
    }
    this.#bundles.emit(sender);
    const signedBefore = this.#prekeys.inventory.signed;
    const outcome = await this.#prekeys.consume(
      initiation.signed,
      initiation.onetime,
      async (keys) => {
        const established = await respond(
          { identity: this.#identity, exchange: this.#exchange },
          keys,
          {
            from: initiation.from,
            fromStatic,
            device: initiation.device,
            ephemeral: initiation.ephemeral,
            ratchet: initiation.ratchet,
            proof: initiation.proof,
            confirm: initiation.confirm,
          },
        );
        if (!established) {
          return null;
        }
        const ratchet = await responderState(
          established.secret,
          { publicKey: keys.signed.key, privateKey: keys.signed.privateKey },
          peerRatchet,
          {
            initiator: initiation.from,
            responder: this.#identity.identity,
            session: established.id,
            role: "responder",
          },
          this.#generate,
        );
        return { id: established.id, accept: established.accept, ratchet };
      },
    );
    if (outcome.status !== "consumed") {
      return;
    }
    if (
      !(await this.#pairs.saveResponder(
        initiation.from,
        initiation.ephemeral,
        outcome.value.ratchet,
      ))
    ) {
      return;
    }
    await this.#client.request({
      type: "accept",
      payload: {
        to: initiation.from,
        ephemeral: initiation.ephemeral,
        confirm: outcome.value.accept,
      },
    });
    if (
      this.#prekeys.inventory.onetime.length < lowWater ||
      this.#prekeys.inventory.signed !== signedBefore
    ) {
      await this.publish();
    }
  }

  async #accept(acceptance: Acceptance): Promise<void> {
    await this.#pairs.accept(
      acceptance.from,
      acceptance.ephemeral,
      acceptance.confirm,
    );
  }
}
