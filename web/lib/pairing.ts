import type { Client } from "./client.ts";
import {
  type ExchangeKey,
  type KeyBundle,
  verifyBundle,
} from "./encryption.ts";
import { initiate, respond, verifyPrekey } from "./handshake.ts";
import { type IdentityKey, isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { MessengerState } from "./messenger.ts";
import type { PairState, Pairs } from "./pairs.ts";
import { type PrekeyStore, lowWater } from "./prekeys.ts";
import type { ServerMessage } from "./protocol.ts";

export type InitiateResult =
  "pending" | "established" | "unavailable" | "invalid_bundle" | "failed";

type StateSource = {
  readonly state: MessengerState;
  onState(listener: (state: MessengerState) => void): () => void;
};

type Initiation = Extract<ServerMessage, { type: "initiation" }>["payload"];
type Acceptance = Extract<ServerMessage, { type: "acceptance" }>["payload"];

export class Pairing {
  readonly #client: Client;
  readonly #source: StateSource;
  readonly #identity: IdentityKey;
  readonly #exchange: ExchangeKey;
  readonly #prekeys: PrekeyStore;
  readonly #pairs: Pairs;
  readonly #bundles = new Listeners<KeyBundle>();
  readonly #inflight = new Map<string, Promise<InitiateResult>>();
  #queue: Promise<void> = Promise.resolve();
  #published = false;
  #generation = 0;
  #detach: (() => void) | null = null;

  constructor(
    client: Client,
    source: StateSource,
    identity: IdentityKey,
    exchange: ExchangeKey,
    prekeys: PrekeyStore,
    pairs: Pairs,
  ) {
    this.#client = client;
    this.#source = source;
    this.#identity = identity;
    this.#exchange = exchange;
    this.#prekeys = prekeys;
    this.#pairs = pairs;
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

  start(): void {
    if (this.#detach) {
      return;
    }
    const detach = [
      this.#client.onMessage((message) => {
        if (message.type === "initiation") {
          this.#enqueue(() => this.#respond(message.payload));
        } else if (message.type === "acceptance") {
          this.#enqueue(() => this.#accept(message.payload));
        }
      }),
      this.#source.onState((state) => {
        this.#generation += 1;
        this.#published = false;
        if (state.active) {
          void this.publish();
        }
      }),
    ];
    this.#detach = () => detach.forEach((release) => release());
    if (this.#source.state.active) {
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
    const run = this.#initiate(peer).finally(() => this.#inflight.delete(peer));
    this.#inflight.set(peer, run);
    return run;
  }

  async #initiate(peer: string): Promise<InitiateResult> {
    const current = this.#pairs.state(peer);
    if (current !== "none") {
      return current;
    }
    if (!this.#source.state.active || !isIdentity(peer)) {
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
    );
    if (!result) {
      return "failed";
    }
    const sent = await this.#client.request({
      type: "initiate",
      payload: { version: 1, to: peer, ...result.initiation },
    });
    if (sent?.type !== "initiated") {
      return sent?.type === "error" &&
        sent.payload.code === "recipient_unavailable"
        ? "unavailable"
        : "failed";
    }
    return (await this.#pairs.savePending(
      peer,
      result.initiation.ephemeral,
      result.pending,
    ))
      ? "pending"
      : "failed";
  }

  #enqueue(task: () => Promise<void>): void {
    this.#queue = this.#queue.then(task).catch(() => {});
  }

  async #respond(initiation: Initiation): Promise<void> {
    if (initiation.device !== this.#prekeys.device) {
      return;
    }
    const sender: KeyBundle = {
      identity: initiation.from,
      key: initiation.key,
      signature: initiation.signature,
    };
    const fromStatic = await verifyBundle(sender);
    if (!fromStatic) {
      return;
    }
    this.#bundles.emit(sender);
    const signedBefore = this.#prekeys.inventory.signed;
    const outcome = await this.#prekeys.consume(
      initiation.signed,
      initiation.onetime,
      (keys) =>
        respond({ identity: this.#identity, exchange: this.#exchange }, keys, {
          from: initiation.from,
          fromStatic,
          device: initiation.device,
          ephemeral: initiation.ephemeral,
          proof: initiation.proof,
          confirm: initiation.confirm,
        }),
    );
    if (outcome.status !== "consumed") {
      return;
    }
    await this.#pairs.saveResponder(
      initiation.from,
      initiation.ephemeral,
      outcome.value,
    );
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
