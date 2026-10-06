import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import {
  type Established,
  type Pending,
  confirmAcceptance,
  initiationIdSize,
} from "./handshake.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import { exchangeKeySize, isEpoch, isFixed } from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";

export const pairsVersion = 1;
export const maxPairs = 256;

export type PairState = "none" | "pending" | "established";

const macSize = 32;
const encoder = new TextEncoder();
const context = encoder.encode("ghostx/pairs/v1\0");
const fields = [
  "v",
  "peer",
  "id",
  "role",
  "state",
  "ephemeral",
  "transcript",
  "stamp",
  "root",
  "responder",
  "mac",
];

type Fields = {
  v: number;
  peer: string;
  id: string;
  role: "initiator" | "responder";
  state: "pending" | "established";
  ephemeral: string;
  transcript: string | null;
  stamp: number;
  root: CryptoKey;
  responder: CryptoKey | null;
};

type Record = Fields & { mac: string };

function isHmac(key: unknown, usage: KeyUsage): key is CryptoKey {
  return (
    key instanceof CryptoKey &&
    key.type === "secret" &&
    !key.extractable &&
    key.algorithm.name === "HMAC" &&
    key.usages.includes(usage)
  );
}

function macInput(f: Fields): Uint8Array<ArrayBuffer> {
  const values = encoder.encode(
    JSON.stringify([
      f.v,
      f.peer,
      f.id,
      f.role,
      f.state,
      f.ephemeral,
      f.transcript,
      f.stamp,
    ]),
  );
  const out = new Uint8Array(context.length + values.length);
  out.set(context);
  out.set(values, context.length);
  return out;
}

function transcriptOf(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(text) || text.length > 512) {
    return null;
  }
  const bytes = Uint8Array.from(
    atob(text.replaceAll("-", "+").replaceAll("_", "/")),
    (c) => c.charCodeAt(0),
  );
  return encodeBase64Url(bytes) === text ? bytes : null;
}

export function parsePair(key: string, value: unknown): Record | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const r = value as { [name: string]: unknown };
  const names = Object.keys(r);
  const pending = r.state === "pending";
  if (
    r.v !== pairsVersion ||
    names.length !== fields.length ||
    !fields.every((name) => names.includes(name)) ||
    !isIdentity(r.peer) ||
    r.peer !== key ||
    !isFixed(r.id, initiationIdSize) ||
    (r.role !== "initiator" && r.role !== "responder") ||
    (r.state !== "pending" && r.state !== "established") ||
    (pending && r.role !== "initiator") ||
    !isFixed(r.ephemeral, exchangeKeySize) ||
    !isEpoch(r.stamp) ||
    !isHmac(r.root, "sign") ||
    (pending
      ? !isHmac(r.responder, "verify") ||
        typeof r.transcript !== "string" ||
        transcriptOf(r.transcript) === null
      : r.responder !== null || r.transcript !== null) ||
    !isFixed(r.mac, macSize)
  ) {
    return null;
  }
  return r as unknown as Record;
}

export class Pairs {
  readonly #store: KeyValueStore;
  readonly #integrity: CryptoKey;
  readonly #records = new Map<string, Record>();
  readonly #changes = new Listeners<string>();
  #rejected = 0;
  #queue: Promise<unknown> = Promise.resolve();
  #closed = false;

  private constructor(store: KeyValueStore, integrity: CryptoKey) {
    this.#store = store;
    this.#integrity = integrity;
  }

  static async open(
    store: KeyValueStore,
    integrity: CryptoKey,
  ): Promise<Pairs> {
    const pairs = new Pairs(store, integrity);
    for (const { key, value } of await store.getAll("pairs")) {
      const record = await pairs.#verify(key, value);
      if (record) {
        pairs.#records.set(key, record);
      } else {
        pairs.#rejected += 1;
      }
    }
    return pairs;
  }

  get rejected(): number {
    return this.#rejected;
  }

  onChange(listener: (peer: string) => void): () => void {
    return this.#changes.add(listener);
  }

  state(peer: string): PairState {
    return this.#records.get(peer)?.state ?? "none";
  }

  id(peer: string): string | null {
    return this.#records.get(peer)?.id ?? null;
  }

  pending(): string[] {
    return [...this.#records.values()]
      .filter((r) => r.state === "pending")
      .map((r) => r.peer);
  }

  savePending(
    peer: string,
    ephemeral: string,
    pending: Pending,
  ): Promise<boolean> {
    return this.#write({
      v: pairsVersion,
      peer,
      id: pending.id,
      role: "initiator",
      state: "pending",
      ephemeral,
      transcript: encodeBase64Url(pending.transcript),
      root: pending.root,
      responder: pending.responder,
      stamp: 0,
    });
  }

  saveResponder(
    peer: string,
    ephemeral: string,
    established: Established,
  ): Promise<boolean> {
    return this.#write({
      v: pairsVersion,
      peer,
      id: established.id,
      role: "responder",
      state: "established",
      ephemeral,
      transcript: null,
      root: established.root,
      responder: null,
      stamp: 0,
    });
  }

  async accept(
    peer: string,
    ephemeral: string,
    accept: string,
  ): Promise<boolean> {
    await this.#reload(peer);
    const record = this.#records.get(peer);
    if (
      !record ||
      record.state !== "pending" ||
      record.ephemeral !== ephemeral ||
      !record.responder ||
      record.transcript === null
    ) {
      return false;
    }
    const transcript = transcriptOf(record.transcript);
    if (
      !transcript ||
      !(await confirmAcceptance(
        {
          id: record.id,
          root: record.root,
          responder: record.responder,
          transcript,
        },
        accept,
      ))
    ) {
      return false;
    }
    const { mac: _, ...fieldsOf } = record;
    return this.#write({
      ...fieldsOf,
      state: "established",
      transcript: null,
      responder: null,
    });
  }

  close(): Promise<void> {
    this.#closed = true;
    return this.#queue.then(() => {});
  }

  async #reload(peer: string): Promise<void> {
    const value = await this.#store.get("pairs", peer);
    const record = value === undefined ? null : await this.#verify(peer, value);
    if (record) {
      this.#records.set(peer, record);
    } else {
      this.#records.delete(peer);
    }
  }

  async #verify(key: string, value: unknown): Promise<Record | null> {
    const record = parsePair(key, value);
    const mac = record && decodeBase64Url(record.mac, macSize);
    if (!record || !mac) {
      return null;
    }
    try {
      const { mac: _, ...rest } = record;
      return (await crypto.subtle.verify(
        "HMAC",
        this.#integrity,
        mac,
        macInput(rest),
      ))
        ? record
        : null;
    } catch {
      return null;
    }
  }

  #write(fields: Fields): Promise<boolean> {
    if (this.#closed) {
      return Promise.resolve(false);
    }
    const run = this.#queue.then(async () => {
      const stamp =
        Math.max(0, ...[...this.#records.values()].map((r) => r.stamp)) + 1;
      const next = { ...fields, stamp };
      const mac = await crypto.subtle.sign(
        "HMAC",
        this.#integrity,
        macInput(next),
      );
      const record: Record = {
        ...next,
        mac: encodeBase64Url(new Uint8Array(mac)),
      };
      if (!parsePair(next.peer, record)) {
        return false;
      }
      await this.#store.put("pairs", next.peer, record);
      this.#records.set(next.peer, record);
      const excess = [...this.#records.values()]
        .sort((a, b) => a.stamp - b.stamp)
        .slice(0, Math.max(0, this.#records.size - maxPairs))
        .map((r) => r.peer);
      if (excess.length > 0) {
        await this.#store.delete("pairs", excess);
        excess.forEach((peer) => this.#records.delete(peer));
      }
      this.#changes.emit(next.peer);
      return true;
    });
    this.#queue = run.catch(() => {});
    return run.catch(() => false);
  }
}
