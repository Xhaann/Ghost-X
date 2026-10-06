import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import type {
  HistoryPort,
  Restored,
  SettledDelivery,
} from "./conversations.ts";
import { maxConversations, maxMessages } from "./conversations.ts";
import { type Parties, verifyBundle } from "./encryption.ts";
import { isIdentity } from "./identity.ts";
import type { SealedRecord } from "./messenger.ts";
import {
  exchangeKeySize,
  isFixed,
  isValidId,
  ivSize,
  saltSize,
  signatureSize,
} from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";
import type { Keys } from "./vault.ts";

export const historyVersion = 1;
export const maxStoredMessages = 5000;
export const maxRecordSize = 8192;

const macSize = 32;
const encoder = new TextEncoder();
const context = encoder.encode("ghostx/history/v1\0");
const deliveries: readonly SettledDelivery[] = [
  "delivered",
  "unavailable",
  "failed",
];
const sealedFields = ["key", "signature", "salt", "iv", "ciphertext"] as const;
const sentFields = ["v", "id", "peer", "direction", "delivery", "sequence"];
const receivedFields = ["v", "id", "peer", "direction", "read", "sequence"];

type Common = {
  v: number;
  id: string;
  peer: string;
  sequence: number;
  key: string;
  signature: string;
  salt: string;
  iv: string;
  ciphertext: string;
};

export type StoredRecord =
  | (Common & { direction: "sent"; delivery: SettledDelivery })
  | (Common & { direction: "received"; read: boolean });

export type PersistedRecord = StoredRecord & { mac: string };

function storageKey(peer: string, id: string): string {
  return `${peer}/${id}`;
}

function fieldsOf(direction: "sent" | "received"): string[] {
  return [
    ...(direction === "sent" ? sentFields : receivedFields),
    ...sealedFields,
  ];
}

function macInput(record: StoredRecord): Uint8Array<ArrayBuffer> {
  const fields = fieldsOf(record.direction) as (keyof StoredRecord)[];
  const values = encoder.encode(
    JSON.stringify(fields.map((name) => record[name as keyof typeof record])),
  );
  const out = new Uint8Array(context.length + values.length);
  out.set(context);
  out.set(values, context.length);
  return out;
}

export function parseRecord(
  key: string,
  value: unknown,
): PersistedRecord | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  if (record.v !== historyVersion) {
    return null;
  }
  if (record.direction !== "sent" && record.direction !== "received") {
    return null;
  }
  const expected = [...fieldsOf(record.direction), "mac"];
  const names = Object.keys(record);
  if (
    names.length !== expected.length ||
    !expected.every((name) => names.includes(name))
  ) {
    return null;
  }
  if (
    !isValidId(record.id) ||
    !isIdentity(record.peer) ||
    key !== storageKey(record.peer, record.id) ||
    typeof record.sequence !== "number" ||
    !Number.isSafeInteger(record.sequence) ||
    record.sequence < 1 ||
    !isFixed(record.key, exchangeKeySize) ||
    !isFixed(record.signature, signatureSize) ||
    !isFixed(record.salt, saltSize) ||
    !isFixed(record.iv, ivSize) ||
    typeof record.ciphertext !== "string" ||
    !isFixed(record.mac, macSize)
  ) {
    return null;
  }
  if (
    record.direction === "sent"
      ? !deliveries.includes(record.delivery as SettledDelivery)
      : typeof record.read !== "boolean"
  ) {
    return null;
  }
  if (JSON.stringify(record).length > maxRecordSize) {
    return null;
  }
  return record as PersistedRecord;
}

export type RestoreResult = { restored: Restored[]; rejected: number };

export class History implements HistoryPort {
  readonly #store: KeyValueStore;
  readonly #keys: Keys;
  readonly #integrity: CryptoKey;
  readonly #records = new Map<string, PersistedRecord>();
  #rejected = 0;
  #queue: Promise<void> = Promise.resolve();
  #closed = false;

  private constructor(store: KeyValueStore, keys: Keys, integrity: CryptoKey) {
    this.#store = store;
    this.#keys = keys;
    this.#integrity = integrity;
  }

  static async open(
    store: KeyValueStore,
    keys: Keys,
    integrity: CryptoKey,
  ): Promise<History> {
    const history = new History(store, keys, integrity);
    const entries = await store.getAll("messages");
    const checked = await Promise.all(
      entries.map(async ({ key, value }) => {
        const record = parseRecord(key, value);
        return record && (await history.#authentic(record)) ? record : null;
      }),
    );
    checked.forEach((record, i) => {
      if (record) {
        history.#records.set(entries[i].key, record);
      } else {
        history.#rejected += 1;
      }
    });
    return history;
  }

  get rejected(): number {
    return this.#rejected;
  }

  async restore(): Promise<RestoreResult> {
    const self = this.#keys.identity.identity;
    const own = this.#keys.exchange.publicRaw;
    const entries = [...this.#records.entries()];
    const opened = await Promise.all(
      entries.map(async ([, record]): Promise<Restored | null> => {
        const peerKey = await verifyBundle({
          identity: record.peer,
          key: record.key,
          signature: record.signature,
        });
        if (!peerKey) {
          return null;
        }
        const sent = record.direction === "sent";
        const parties: Parties = {
          id: record.id,
          from: sent ? self : record.peer,
          to: sent ? record.peer : self,
          fromKey: sent ? own : peerKey,
          toKey: sent ? peerKey : own,
        };
        const sealed = {
          salt: record.salt,
          iv: record.iv,
          ciphertext: record.ciphertext,
        };
        const body = sent
          ? await this.#keys.exchange.openOwn(parties, sealed)
          : await this.#keys.exchange.open(parties, sealed);
        if (body === null) {
          return null;
        }
        const base = {
          id: record.id,
          from: parties.from,
          to: parties.to,
          sequence: record.sequence,
        };
        return record.direction === "sent"
          ? { ...base, direction: "sent", body, delivery: record.delivery }
          : { ...base, direction: "received", body, read: record.read };
      }),
    );
    const restored: Restored[] = [];
    opened.forEach((message, i) => {
      if (message) {
        restored.push(message);
      } else {
        this.#records.delete(entries[i][0]);
        this.#rejected += 1;
      }
    });
    restored.sort((a, b) => a.sequence - b.sequence || (a.id < b.id ? -1 : 1));
    return { restored, rejected: this.#rejected };
  }

  received(entry: {
    id: string;
    peer: string;
    sequence: number;
    read: boolean;
    record: SealedRecord;
  }): void {
    this.#write({
      v: historyVersion,
      id: entry.id,
      peer: entry.peer,
      direction: "received",
      read: entry.read,
      sequence: entry.sequence,
      ...this.#sealedFields(entry.record),
    });
  }

  sent(entry: {
    id: string;
    peer: string;
    sequence: number;
    delivery: SettledDelivery;
    record: SealedRecord;
  }): void {
    this.#write({
      v: historyVersion,
      id: entry.id,
      peer: entry.peer,
      direction: "sent",
      delivery: entry.delivery,
      sequence: entry.sequence,
      ...this.#sealedFields(entry.record),
    });
  }

  read(identity: string): void {
    this.#enqueue(async () => {
      for (const record of [...this.#records.values()]) {
        if (
          record.peer === identity &&
          record.direction === "received" &&
          !record.read
        ) {
          const { mac: _, ...rest } = record;
          await this.#persist({ ...rest, read: true });
        }
      }
    });
  }

  flush(): Promise<void> {
    return this.#queue;
  }

  close(): Promise<void> {
    this.#closed = true;
    return this.#queue;
  }

  #sealedFields(record: SealedRecord) {
    return {
      key: record.peer.key,
      signature: record.peer.signature,
      salt: record.sealed.salt,
      iv: record.sealed.iv,
      ciphertext: record.sealed.ciphertext,
    };
  }

  async #authentic(record: PersistedRecord): Promise<boolean> {
    const mac = decodeBase64Url(record.mac, macSize);
    if (!mac) {
      return false;
    }
    try {
      return await crypto.subtle.verify(
        "HMAC",
        this.#integrity,
        mac,
        macInput(record),
      );
    } catch {
      return false;
    }
  }

  #write(record: StoredRecord): void {
    this.#enqueue(() => this.#persist(record));
  }

  #enqueue(task: () => Promise<void>): void {
    if (this.#closed) {
      return;
    }
    this.#queue = this.#queue.then(task).catch(() => {});
  }

  async #persist(record: StoredRecord): Promise<void> {
    const key = storageKey(record.peer, record.id);
    const mac = await crypto.subtle.sign(
      "HMAC",
      this.#integrity,
      macInput(record),
    );
    const sealed: PersistedRecord = {
      ...record,
      mac: encodeBase64Url(new Uint8Array(mac)),
    };
    if (parseRecord(key, sealed) === null) {
      return;
    }
    await this.#store.put("messages", key, sealed);
    this.#records.set(key, sealed);
    const expired = this.#expired(key);
    if (expired.length > 0) {
      await this.#store.delete("messages", expired);
      expired.forEach((name) => this.#records.delete(name));
    }
  }

  #expired(written: string): string[] {
    const bySequence = (
      a: [string, PersistedRecord],
      b: [string, PersistedRecord],
    ) => a[1].sequence - b[1].sequence || (a[0] < b[0] ? -1 : 1);
    const peer = this.#records.get(written)?.peer;
    const expired = new Set<string>();
    const latest = new Map<string, number>();
    const own: [string, PersistedRecord][] = [];
    for (const entry of this.#records.entries()) {
      const record = entry[1];
      latest.set(
        record.peer,
        Math.max(latest.get(record.peer) ?? 0, record.sequence),
      );
      if (record.peer === peer) {
        own.push(entry);
      }
    }
    if (own.length > maxMessages) {
      own
        .sort(bySequence)
        .slice(0, own.length - maxMessages)
        .forEach(([key]) => expired.add(key));
    }
    if (latest.size > maxConversations) {
      const stale = [...latest.entries()]
        .sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1))
        .slice(0, latest.size - maxConversations)
        .map(([name]) => name);
      for (const [key, record] of this.#records) {
        if (stale.includes(record.peer)) {
          expired.add(key);
        }
      }
    }
    const remaining = this.#records.size - expired.size;
    if (remaining > maxStoredMessages) {
      [...this.#records.entries()]
        .filter(([key]) => !expired.has(key))
        .sort(bySequence)
        .slice(0, remaining - maxStoredMessages)
        .forEach(([key]) => expired.add(key));
    }
    return [...expired];
  }
}
