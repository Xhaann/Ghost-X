import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { isCanonicalExchangeKey } from "./fingerprint.ts";
import {
  type Pending,
  confirmAcceptance,
  initiationIdSize,
} from "./handshake.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import { deviceIdSize, exchangeKeySize, isFixed } from "./protocol.ts";
import {
  type Chain,
  type RatchetState,
  type Role,
  type SkippedKey,
  maxSkipped,
} from "./ratchet.ts";
import type { KeyValueStore } from "./storage.ts";

export const pairsVersion = 3;
export const maxPairs = 256;

export type PairState = "none" | "pending" | "established";

const macSize = 32;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const context = encoder.encode("ghostx/pairs/v3\0");
const blobContext = encoder.encode("ghostx/pairs/v3/ratchet\0");
const fields = [
  "v",
  "peer",
  "device",
  "id",
  "role",
  "state",
  "ephemeral",
  "transcript",
  "responder",
  "own",
  "ratchet",
  "stamp",
  "mac",
];

type Blob = { iv: string; ciphertext: string };

type Fields = {
  v: number;
  peer: string;
  device: string;
  id: string;
  role: Role;
  state: "pending" | "established";
  ephemeral: string;
  transcript: string | null;
  responder: CryptoKey | null;
  own: CryptoKey;
  ratchet: Blob;
  stamp: number;
};

type StoredPair = Fields & { mac: string };

function isPrivate(key: unknown): key is CryptoKey {
  return (
    key instanceof CryptoKey &&
    key.type === "private" &&
    !key.extractable &&
    key.algorithm.name === "X25519" &&
    key.usages.includes("deriveBits")
  );
}

function isVerifier(key: unknown): key is CryptoKey {
  return (
    key instanceof CryptoKey &&
    key.type === "secret" &&
    !key.extractable &&
    key.algorithm.name === "HMAC" &&
    key.usages.includes("verify")
  );
}

function bytesOf(text: unknown, max = 4096): Uint8Array<ArrayBuffer> | null {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) {
    return null;
  }
  if (text.length === 0 || text.length > max) {
    return null;
  }
  try {
    const bytes = Uint8Array.from(
      atob(text.replaceAll("-", "+").replaceAll("_", "/")),
      (c) => c.charCodeAt(0),
    );
    return encodeBase64Url(bytes) === text ? bytes : null;
  } catch {
    return null;
  }
}

function macInput(f: Fields): Uint8Array<ArrayBuffer> {
  const values = encoder.encode(
    JSON.stringify([
      f.v,
      f.peer,
      f.device,
      f.id,
      f.role,
      f.state,
      f.ephemeral,
      f.transcript,
      f.ratchet.iv,
      f.ratchet.ciphertext,
      f.stamp,
    ]),
  );
  return concat(context, values);
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function blobData(f: {
  peer: string;
  device: string;
  id: string;
  role: Role;
  stamp: number;
}): Uint8Array<ArrayBuffer> {
  return concat(
    blobContext,
    encoder.encode(JSON.stringify([f.peer, f.device, f.id, f.role, f.stamp])),
  );
}

export function pairAddress(peer: string, device: string): string {
  return `${peer}/${device}`;
}

export function splitAddress(
  address: string,
): { peer: string; device: string } | null {
  const [peer, device, ...rest] = address.split("/");
  return rest.length === 0 && isIdentity(peer) && isFixed(device, deviceIdSize)
    ? { peer, device }
    : null;
}

async function owns(pair: {
  publicKey: Uint8Array<ArrayBuffer>;
  privateKey: CryptoKey;
}): Promise<boolean> {
  try {
    const probe = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const own = await crypto.subtle.importKey(
      "raw",
      pair.publicKey,
      { name: "X25519" },
      false,
      [],
    );
    const [forward, backward] = await Promise.all([
      crypto.subtle.deriveBits(
        { name: "X25519", public: probe.publicKey },
        pair.privateKey,
        256,
      ),
      crypto.subtle.deriveBits(
        { name: "X25519", public: own },
        probe.privateKey,
        256,
      ),
    ]);
    return (
      encodeBase64Url(new Uint8Array(forward)) ===
      encodeBase64Url(new Uint8Array(backward))
    );
  } catch {
    return false;
  }
}

export function parsePair(key: string, value: unknown): StoredPair | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const r = value as { [name: string]: unknown };
  const names = Object.keys(r);
  const pending = r.state === "pending";
  const ratchet = r.ratchet as { [name: string]: unknown } | null;
  if (
    r.v !== pairsVersion ||
    names.length !== fields.length ||
    !fields.every((name) => names.includes(name)) ||
    !isIdentity(r.peer) ||
    !isFixed(r.device, deviceIdSize) ||
    pairAddress(r.peer as string, r.device as string) !== key ||
    !isFixed(r.id, initiationIdSize) ||
    (r.role !== "initiator" && r.role !== "responder") ||
    (r.state !== "pending" && r.state !== "established") ||
    (pending && r.role !== "initiator") ||
    !isFixed(r.ephemeral, exchangeKeySize) ||
    !Number.isSafeInteger(r.stamp) ||
    (r.stamp as number) < 1 ||
    !isPrivate(r.own) ||
    typeof ratchet !== "object" ||
    ratchet === null ||
    Object.keys(ratchet).length !== 2 ||
    !isFixed(ratchet.iv, 12) ||
    !bytesOf(ratchet.ciphertext, 65536) ||
    (pending
      ? !isVerifier(r.responder) || !bytesOf(r.transcript, 512)
      : r.responder !== null || r.transcript !== null) ||
    !isFixed(r.mac, macSize)
  ) {
    return null;
  }
  return r as unknown as StoredPair;
}

type Encoded = {
  initiator: string;
  responder: string;
  session: string;
  role: Role;
  root: string;
  sending: [string, number] | null;
  receiving: [string, number] | null;
  previous: number;
  own: string;
  peer: string | null;
  skipped: [string, number, string][];
};

function encodeChain(chain: Chain | null): [string, number] | null {
  return chain ? [encodeBase64Url(chain.key), chain.n] : null;
}

function decodeChain(value: unknown): Chain | null | undefined {
  if (value === null) {
    return null;
  }
  if (
    !Array.isArray(value) ||
    value.length !== 2 ||
    !Number.isSafeInteger(value[1]) ||
    value[1] < 0 ||
    value[1] > 2 ** 32 - 1
  ) {
    return undefined;
  }
  const key = decodeBase64Url(value[0], 32);
  return key ? { key, n: value[1] } : undefined;
}

function encodeState(state: RatchetState): Encoded {
  return {
    ...state.binding,
    root: encodeBase64Url(state.root),
    sending: encodeChain(state.sending),
    receiving: encodeChain(state.receiving),
    previous: state.previous,
    own: encodeBase64Url(state.own.publicKey),
    peer: state.peer ? encodeBase64Url(state.peer) : null,
    skipped: state.skipped.map((k) => [k.ratchet, k.n, encodeBase64Url(k.key)]),
  };
}

function decodeState(
  value: unknown,
  own: CryptoKey,
  expected: { self: string; peer: string; id: string; role: Role },
): RatchetState | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const e = value as { [name: string]: unknown };
  const names = Object.keys(e);
  const required = [
    "initiator",
    "responder",
    "session",
    "role",
    "root",
    "sending",
    "receiving",
    "previous",
    "own",
    "peer",
    "skipped",
  ];
  if (
    names.length !== required.length ||
    !required.every((n) => names.includes(n))
  ) {
    return null;
  }
  const initiator =
    expected.role === "initiator" ? expected.self : expected.peer;
  const responder =
    expected.role === "initiator" ? expected.peer : expected.self;
  const root = decodeBase64Url(e.root, 32);
  const sending = decodeChain(e.sending);
  const receiving = decodeChain(e.receiving);
  const ownPublic = decodeBase64Url(e.own, exchangeKeySize);
  const peer =
    e.peer === null ? null : decodeBase64Url(e.peer, exchangeKeySize);
  if (
    e.initiator !== initiator ||
    e.responder !== responder ||
    e.session !== expected.id ||
    e.role !== expected.role ||
    !root ||
    sending === undefined ||
    receiving === undefined ||
    !Number.isSafeInteger(e.previous) ||
    (e.previous as number) < 0 ||
    !ownPublic ||
    !isCanonicalExchangeKey(ownPublic) ||
    (e.peer !== null && (!peer || !isCanonicalExchangeKey(peer))) ||
    !Array.isArray(e.skipped) ||
    e.skipped.length > maxSkipped
  ) {
    return null;
  }
  const skipped: SkippedKey[] = [];
  for (const item of e.skipped as unknown[]) {
    if (!Array.isArray(item) || item.length !== 3) {
      return null;
    }
    const ratchet = decodeBase64Url(item[0], exchangeKeySize);
    const key = decodeBase64Url(item[2], 32);
    if (!ratchet || !key || !Number.isSafeInteger(item[1]) || item[1] < 0) {
      return null;
    }
    skipped.push({ ratchet: item[0] as string, n: item[1] as number, key });
  }
  return {
    binding: {
      initiator,
      responder,
      session: expected.id,
      role: expected.role,
    },
    root,
    sending,
    receiving,
    previous: e.previous as number,
    own: { publicKey: ownPublic, privateKey: own },
    peer,
    skipped,
  };
}

export class Pairs {
  readonly #store: KeyValueStore;
  readonly #integrity: CryptoKey;
  readonly #storage: CryptoKey;
  readonly #self: string;
  readonly #records = new Map<string, StoredPair>();
  readonly #changes = new Listeners<string>();
  #rejected = 0;
  #queue: Promise<unknown> = Promise.resolve();
  #closed = false;

  private constructor(
    store: KeyValueStore,
    integrity: CryptoKey,
    storage: CryptoKey,
    self: string,
  ) {
    this.#store = store;
    this.#integrity = integrity;
    this.#storage = storage;
    this.#self = self;
  }

  static async open(
    store: KeyValueStore,
    integrity: CryptoKey,
    storage: CryptoKey,
    self: string,
  ): Promise<Pairs> {
    const pairs = new Pairs(store, integrity, storage, self);
    const previous: string[] = [];
    for (const { key, value } of await store.getAll("pairs")) {
      if (
        typeof value === "object" &&
        value !== null &&
        (value as { v?: unknown }).v === 2
      ) {
        previous.push(key);
        continue;
      }
      const record = await pairs.#verify(key, value);
      if (record) {
        pairs.#records.set(key, record);
      } else {
        pairs.#rejected += 1;
      }
    }
    if (previous.length > 0) {
      await store.delete("pairs", previous);
    }
    return pairs;
  }

  get rejected(): number {
    return this.#rejected;
  }

  onChange(listener: (address: string) => void): () => void {
    return this.#changes.add(listener);
  }

  state(address: string): PairState {
    return this.#records.get(address)?.state ?? "none";
  }

  role(address: string): Role | null {
    return this.#records.get(address)?.role ?? null;
  }

  id(address: string): string | null {
    return this.#records.get(address)?.id ?? null;
  }

  devices(peer: string): string[] {
    return [...this.#records.values()]
      .filter((r) => r.peer === peer)
      .map((r) => r.device);
  }

  remove(address: string): Promise<boolean> {
    return this.#enqueue(async () => {
      await this.#reload(address);
      if (!this.#records.has(address)) {
        return false;
      }
      await this.#store.delete("pairs", [address]);
      this.#records.delete(address);
      this.#changes.emit(address);
      return true;
    }).then((r) => r === true);
  }

  savePending(
    address: string,
    ephemeral: string,
    pending: Pending,
    ratchet: RatchetState,
  ): Promise<boolean> {
    const target = splitAddress(address);
    if (!target) {
      return Promise.resolve(false);
    }
    return this.#enqueue(() =>
      this.#write(
        {
          v: pairsVersion,
          ...target,
          id: pending.id,
          role: "initiator",
          state: "pending",
          ephemeral,
          transcript: encodeBase64Url(pending.transcript),
          responder: pending.responder,
          own: ratchet.own.privateKey,
          ratchet: { iv: "", ciphertext: "" },
          stamp: 0,
        },
        ratchet,
      ),
    ).then((r) => r === true);
  }

  saveResponder(
    address: string,
    ephemeral: string,
    ratchet: RatchetState,
  ): Promise<boolean> {
    const target = splitAddress(address);
    if (!target) {
      return Promise.resolve(false);
    }
    return this.#enqueue(() =>
      this.#write(
        {
          v: pairsVersion,
          ...target,
          id: ratchet.binding.session,
          role: "responder",
          state: "established",
          ephemeral,
          transcript: null,
          responder: null,
          own: ratchet.own.privateKey,
          ratchet: { iv: "", ciphertext: "" },
          stamp: 0,
        },
        ratchet,
      ),
    ).then((r) => r === true);
  }

  discard(address: string, id: string): Promise<boolean> {
    return this.#enqueue(async () => {
      await this.#reload(address);
      const record = this.#records.get(address);
      if (!record || record.id !== id || record.state !== "pending") {
        return false;
      }
      await this.#store.delete("pairs", [address]);
      this.#records.delete(address);
      this.#changes.emit(address);
      return true;
    }).then((r) => r === true);
  }

  accept(address: string, ephemeral: string, accept: string): Promise<boolean> {
    return this.#enqueue(async () => {
      await this.#reload(address);
      const record = this.#records.get(address);
      const transcript = record && bytesOf(record.transcript, 512);
      if (
        !record ||
        record.state !== "pending" ||
        record.ephemeral !== ephemeral ||
        !record.responder ||
        !transcript ||
        !(await confirmAcceptance(record.responder, transcript, accept))
      ) {
        return false;
      }
      const ratchet = await this.#decrypt(record);
      if (!ratchet) {
        return false;
      }
      const { mac: _, ...rest } = record;
      return this.#write(
        { ...rest, state: "established", transcript: null, responder: null },
        ratchet,
      );
    }).then((r) => r === true);
  }

  transact<T>(
    address: string,
    change: (
      state: RatchetState,
    ) => Promise<{ state: RatchetState; value: T } | null>,
  ): Promise<T | null> {
    return this.#enqueue(async () => {
      await this.#reload(address);
      const record = this.#records.get(address);
      if (!record || record.state !== "established") {
        return null;
      }
      const ratchet = await this.#decrypt(record);
      if (!ratchet) {
        return null;
      }
      const outcome = await change(ratchet);
      if (!outcome) {
        return null;
      }
      const { mac: _, ...rest } = record;
      const saved = await this.#write(
        { ...rest, own: outcome.state.own.privateKey },
        outcome.state,
      );
      return saved ? outcome.value : null;
    }).then((r) => (r === undefined ? null : (r as T | null)));
  }

  close(): Promise<void> {
    this.#closed = true;
    return this.#queue.then(() => {});
  }

  #enqueue<T>(task: () => Promise<T>): Promise<T | undefined> {
    if (this.#closed) {
      return Promise.resolve(undefined);
    }
    const run = this.#queue.then(task);
    this.#queue = run.catch(() => {});
    return run.catch(() => undefined);
  }

  async #reload(address: string): Promise<void> {
    const value = await this.#store.get("pairs", address);
    const record =
      value === undefined ? null : await this.#verify(address, value);
    if (record) {
      this.#records.set(address, record);
    } else {
      this.#records.delete(address);
    }
  }

  async #decrypt(record: StoredPair): Promise<RatchetState | null> {
    try {
      const iv = decodeBase64Url(record.ratchet.iv, 12);
      const ciphertext = bytesOf(record.ratchet.ciphertext, 65536);
      if (!iv || !ciphertext) {
        return null;
      }
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: blobData(record) },
        this.#storage,
        ciphertext,
      );
      return decodeState(JSON.parse(decoder.decode(plaintext)), record.own, {
        self: this.#self,
        peer: record.peer,
        id: record.id,
        role: record.role,
      });
    } catch {
      return null;
    }
  }

  async #verify(key: string, value: unknown): Promise<StoredPair | null> {
    const record = parsePair(key, value);
    const mac = record && decodeBase64Url(record.mac, macSize);
    if (!record || !mac) {
      return null;
    }
    try {
      const { mac: _, ...rest } = record;
      if (
        !(await crypto.subtle.verify(
          "HMAC",
          this.#integrity,
          mac,
          macInput(rest),
        ))
      ) {
        return null;
      }
      const state = await this.#decrypt(record);
      return state && (await owns(state.own)) ? record : null;
    } catch {
      return null;
    }
  }

  async #write(fields: Fields, ratchet: RatchetState): Promise<boolean> {
    if (
      ratchet.binding.session !== fields.id ||
      ratchet.binding.role !== fields.role ||
      ratchet.own.privateKey !== fields.own
    ) {
      return false;
    }
    const stamp =
      Math.max(0, ...[...this.#records.values()].map((r) => r.stamp)) + 1;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: blobData({ ...fields, stamp }),
      },
      this.#storage,
      encoder.encode(JSON.stringify(encodeState(ratchet))),
    );
    const next: Fields = {
      ...fields,
      stamp,
      ratchet: {
        iv: encodeBase64Url(iv),
        ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
      },
    };
    const mac = await crypto.subtle.sign(
      "HMAC",
      this.#integrity,
      macInput(next),
    );
    const record: StoredPair = {
      ...next,
      mac: encodeBase64Url(new Uint8Array(mac)),
    };
    const address = pairAddress(next.peer, next.device);
    if (!parsePair(address, record)) {
      return false;
    }
    await this.#store.put("pairs", address, record);
    this.#records.set(address, record);
    const excess = [...this.#records.values()]
      .sort((a, b) => a.stamp - b.stamp)
      .slice(0, Math.max(0, this.#records.size - maxPairs))
      .map((r) => pairAddress(r.peer, r.device));
    if (excess.length > 0) {
      await this.#store.delete("pairs", excess);
      excess.forEach((peer) => this.#records.delete(peer));
    }
    this.#changes.emit(address);
    return true;
  }
}
