import { type DeviceEntry, type Roster, rosterDevice } from "./device.ts";
import {
  type ResponderKeys,
  handshakeVersion,
  initiate,
  respond,
  verifyPrekey,
} from "./handshake.ts";
import { isIdentity } from "./identity.ts";
import type { MessengerState } from "./messenger.ts";
import {
  type PairState,
  type Pairs,
  pairAddress,
  splitAddress,
} from "./pairs.ts";
import { type PrekeyStore, lowWater } from "./prekeys.ts";
import {
  type WireDeviceBundle,
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
import type { Relay, RelayEvent } from "./relay.ts";
import type { Rosters } from "./rosters.ts";
import type { Keys } from "./vault.ts";

export type InitiateResult =
  "pending" | "established" | "unavailable" | "invalid_bundle" | "failed";

export type OpenResult =
  "accepted" | "deferred" | "rejected" | "failed" | "missing";

export type Establishment = {
  result: InitiateResult;
  devices: string[];
  pending: string[];
};

export interface Channel {
  establish(peer: string): Promise<Establishment>;
  initiate(peer: string, device?: string): Promise<InitiateResult>;
  state(peer: string, device: string): PairState;
  onChange(listener: (address: string) => void): () => void;
  seal(
    peer: string,
    device: string,
    id: string,
    body: string,
  ): Promise<Uint8Array<ArrayBuffer> | null>;
  open(
    peer: string,
    device: string,
    id: string,
    data: Uint8Array<ArrayBuffer>,
    record: (body: string) => Promise<boolean>,
  ): Promise<OpenResult>;
}

type StateSource = {
  readonly state: MessengerState;
  onState(listener: (state: MessengerState) => void): () => void;
};

type Initiated = Extract<RelayEvent, { type: "initiation" }>["payload"];
type Accepted = Extract<RelayEvent, { type: "acceptance" }>["payload"];

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
  readonly #relay: Relay;
  readonly #keys: Keys;
  readonly #rosters: Rosters;
  readonly #prekeys: PrekeyStore;
  readonly #pairs: Pairs;
  readonly #generate: Generate;
  readonly #inflight = new Map<string, Promise<InitiateResult>>();
  #source: StateSource | null = null;
  #queue: Promise<void> = Promise.resolve();
  #published = false;
  #generation = 0;
  #detach: (() => void) | null = null;

  constructor(
    relay: Relay,
    keys: Keys,
    rosters: Rosters,
    prekeys: PrekeyStore,
    pairs: Pairs,
    generate: Generate = generateRatchetKey,
  ) {
    this.#relay = relay;
    this.#keys = keys;
    this.#rosters = rosters;
    this.#prekeys = prekeys;
    this.#pairs = pairs;
    this.#generate = generate;
  }

  get published(): boolean {
    return this.#published;
  }

  state(peer: string, device: string): PairState {
    return this.#pairs.state(pairAddress(peer, device));
  }

  onChange(listener: (address: string) => void): () => void {
    return this.#pairs.onChange(listener);
  }

  start(source: StateSource): void {
    if (this.#detach) {
      return;
    }
    this.#source = source;
    const detach = [
      this.#relay.onEvent((event) => {
        if (event.type === "initiation") {
          this.#enqueue(() => this.#respond(event.payload));
        } else if (event.type === "acceptance") {
          this.#enqueue(() => this.#accept(event.payload));
        }
      }),
      this.#rosters.onUpdate((roster) =>
        this.#enqueue(() => this.#prune(roster)),
      ),
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
      const publication = await this.#prekeys
        .publication()
        .catch(() => null);
      if (!publication || generation !== this.#generation) {
        return false;
      }
      const available = await this.#relay.publish(publication);
      if (available === null || generation !== this.#generation) {
        return false;
      }
      this.#published = true;
      if (!(await this.#prekeys.replenish(available).catch(() => false))) {
        return true;
      }
    }
    return true;
  }

  initiate(peer: string, device?: string): Promise<InitiateResult> {
    const key = device ? pairAddress(peer, device) : peer;
    const existing = this.#inflight.get(key);
    if (existing) {
      return existing;
    }
    const run = this.#initiate(peer, device ?? null, false).finally(() =>
      this.#inflight.delete(key),
    );
    this.#inflight.set(key, run);
    return run;
  }

  summary(peer: string): PairState {
    const states = (this.#rosters.cached(peer)?.devices ?? []).map((d) =>
      this.#pairs.state(pairAddress(peer, d.id)),
    );
    return states.includes("established")
      ? "established"
      : states.includes("pending")
        ? "pending"
        : "none";
  }

  established(peer: string): string[] {
    const roster = this.#rosters.cached(peer);
    return (roster?.devices ?? [])
      .map((d) => d.id)
      .filter(
        (id) =>
          this.#relay.reaches(peer, id) &&
          this.#pairs.state(pairAddress(peer, id)) === "established",
      );
  }

  async establish(peer: string): Promise<Establishment> {
    const roster = await this.#rosters.fetch(peer);
    if (!roster) {
      return { result: "unavailable", devices: [], pending: [] };
    }
    const outcome = (result: InitiateResult): Establishment => {
      const devices = this.established(peer);
      const pending = (this.#rosters.cached(peer) ?? roster).devices
        .map((d) => d.id)
        .filter((id) => this.#relay.reaches(peer, id) && !devices.includes(id));
      return {
        result: devices.length > 0 ? "established" : result,
        devices,
        pending,
      };
    };
    if (this.established(peer).length > 0) {
      if (
        roster.devices.some(
          (d) =>
            this.#relay.reaches(peer, d.id) &&
            this.#pairs.state(pairAddress(peer, d.id)) === "none",
        )
      ) {
        void this.initiate(peer);
      }
      return outcome("established");
    }
    let settle = (_: boolean) => {};
    const established = new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => settle(false), establishTimeout);
      const releases = [
        this.#pairs.onChange((changed) => {
          const target = splitAddress(changed);
          if (
            target?.peer === peer &&
            this.#pairs.state(changed) === "established"
          ) {
            settle(true);
          }
        }),
        this.#source?.onState(() => settle(false)) ?? (() => {}),
      ];
      settle = (value) => {
        settle = () => {};
        clearTimeout(timer);
        releases.forEach((release) => release());
        resolve(value);
      };
    });
    const result = await this.#initiate(peer, null, true);
    if (result === "pending") {
      await established;
    }
    settle(false);
    if (result !== "pending" && result !== "established") {
      return { result, devices: [], pending: [] };
    }
    return outcome("pending");
  }

  async seal(
    peer: string,
    device: string,
    id: string,
    body: string,
  ): Promise<Uint8Array<ArrayBuffer> | null> {
    if (!isValidBody(body) || !isMessageId(id)) {
      return null;
    }
    return this.#pairs.transact(pairAddress(peer, device), async (state) => {
      const sealed = await ratchetEncrypt(state, frame(id, body));
      return sealed && { state: sealed.state, value: sealed.message };
    });
  }

  async open(
    peer: string,
    device: string,
    id: string,
    data: Uint8Array<ArrayBuffer>,
    record: (body: string) => Promise<boolean>,
  ): Promise<OpenResult> {
    const header = decodeHeader(data);
    if (!header || !isMessageId(id) || !isIdentity(peer)) {
      return "rejected";
    }
    const address = pairAddress(peer, device);
    if (
      !splitAddress(address) ||
      !(await this.#rosters.resolve(peer, device))
    ) {
      return "rejected";
    }
    const current = this.#pairs.state(address);
    if (current === "none") {
      return "missing";
    }
    if (current === "pending") {
      return header.session === this.#pairs.id(address)
        ? "deferred"
        : "rejected";
    }
    let recorded = false;
    let failed = false;
    const opened = await this.#pairs.transact(address, async (state) => {
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

  async #prune(roster: Roster): Promise<void> {
    for (const device of this.#pairs.devices(roster.identity)) {
      if (!rosterDevice(roster, device)) {
        await this.#pairs.remove(pairAddress(roster.identity, device));
      }
    }
  }

  async #initiate(
    peer: string,
    device: string | null,
    replace: boolean,
  ): Promise<InitiateResult> {
    if (
      !this.#source?.state.active ||
      !isIdentity(peer) ||
      peer === this.#keys.identity
    ) {
      return "failed";
    }
    const roster = await this.#rosters.fetch(peer);
    if (!roster) {
      return "unavailable";
    }
    const wanted = roster.devices.filter((d) => {
      const state = this.#pairs.state(pairAddress(peer, d.id));
      return (
        (device === null || d.id === device) &&
        this.#relay.reaches(peer, d.id) &&
        (state === "none" ||
          (state === "pending" &&
            replace &&
            device === null &&
            this.established(peer).length === 0))
      );
    });
    if (wanted.length === 0) {
      return this.established(peer).length > 0 ? "established" : "pending";
    }
    const reply = await this.#relay.bundle(peer);
    if (reply === "unavailable" || reply === "failed") {
      return reply;
    }
    let outcome: InitiateResult = "unavailable";
    for (const entry of wanted) {
      const bundle = reply.bundles.find((b) => b.device === entry.id);
      if (!bundle) {
        continue;
      }
      const address = pairAddress(peer, entry.id);
      const result = await this.#serial(() => {
        const state = this.#pairs.state(address);
        const replaceable =
          state === "pending" &&
          replace &&
          device === null &&
          this.established(peer).length === 0;
        return state === "none" || replaceable
          ? this.#start(peer, entry, bundle)
          : Promise.resolve<InitiateResult>(
              state === "established" ? "established" : "pending",
            );
      }).catch((): InitiateResult => "failed");
      if (
        result === "established" ||
        (result === "pending" && outcome !== "established")
      ) {
        outcome = result;
      } else if (outcome === "unavailable") {
        outcome = result;
      }
    }
    if (outcome === "unavailable" && reply.bundles.length > 0) {
      return "invalid_bundle";
    }
    return this.established(peer).length > 0 ? "established" : outcome;
  }

  async #start(
    peer: string,
    entry: DeviceEntry,
    bundle: WireDeviceBundle,
  ): Promise<InitiateResult> {
    const signed = await verifyPrekey("signed", peer, entry, bundle.signed);
    const onetime = bundle.onetime
      ? await verifyPrekey("onetime", peer, entry, bundle.onetime)
      : null;
    if (!signed || (bundle.onetime && !onetime)) {
      return "invalid_bundle";
    }
    const result = await initiate(
      this.#keys,
      {
        identity: peer,
        device: entry,
        signed: { id: bundle.signed.id, key: signed },
        onetime:
          bundle.onetime && onetime
            ? { id: bundle.onetime.id, key: onetime }
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
        initiator: this.#keys.identity,
        responder: peer,
        session: result.pending.id,
        role: "initiator",
      },
      result.pending.ratchet,
    );
    const address = pairAddress(peer, entry.id);
    if (
      !(await this.#pairs.savePending(
        address,
        result.initiation.ephemeral,
        result.pending,
        ratchet,
      ))
    ) {
      return "failed";
    }
    const sent = await this.#relay.initiate({
      version: handshakeVersion,
      to: peer,
      ...result.initiation,
    });
    if (sent !== "initiated") {
      await this.#pairs.discard(address, result.pending.id);
      return sent;
    }
    return this.#pairs.state(address) === "established"
      ? "established"
      : "pending";
  }

  #enqueue(task: () => Promise<void>): void {
    void this.#serial(task).catch(() => {});
  }

  #serial<T>(task: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(task);
    this.#queue = run.then(
      () => {},
      () => {},
    );
    return run;
  }

  async #respond(initiation: Initiated): Promise<void> {
    const peer = initiation.from;
    const address = pairAddress(peer, initiation.device);
    if (
      this.#pairs.state(address) === "pending" &&
      pairAddress(this.#keys.identity, this.#keys.deviceId) < address
    ) {
      return;
    }
    const fromDevice = await this.#rosters.resolve(peer, initiation.device);
    const peerRatchet = decodeBase64Url(initiation.ratchet, exchangeKeySize);
    if (!fromDevice || !peerRatchet || peer === this.#keys.identity) {
      return;
    }
    const signedBefore = this.#prekeys.inventory.signed;
    const outcome = await this.#prekeys.consume(
      initiation.signed,
      initiation.onetime,
      async (keys: ResponderKeys) => {
        const established = await respond(this.#keys, keys, {
          from: peer,
          fromDevice,
          ephemeral: initiation.ephemeral,
          ratchet: initiation.ratchet,
          proof: initiation.proof,
          confirm: initiation.confirm,
        });
        if (!established) {
          return null;
        }
        const ratchet = await responderState(
          established.secret,
          { publicKey: keys.signed.key, privateKey: keys.signed.privateKey },
          peerRatchet,
          {
            initiator: peer,
            responder: this.#keys.identity,
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
        address,
        initiation.ephemeral,
        outcome.value.ratchet,
      ))
    ) {
      return;
    }
    await this.#relay.accept({
      to: peer,
      device: initiation.device,
      ephemeral: initiation.ephemeral,
      confirm: outcome.value.accept,
    });
    if (
      this.#prekeys.inventory.onetime.length < lowWater ||
      this.#prekeys.inventory.signed !== signedBefore
    ) {
      await this.publish();
    }
  }

  async #accept(acceptance: Accepted): Promise<void> {
    await this.#pairs.accept(
      pairAddress(acceptance.from, acceptance.device),
      acceptance.ephemeral,
      acceptance.confirm,
    );
  }
}
