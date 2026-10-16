import {
  decodeBase64Url,
  decodeBase64UrlRange,
  encodeBase64Url,
} from "./base64.ts";
import type {
  HistoryPort,
  Restored,
  SettledDelivery,
} from "./conversations.ts";
import { advances, maxConversations, maxMessages } from "./conversations.ts";
import { type Parties, verifyBundle } from "./encryption.ts";
import { isIdentity } from "./identity.ts";
import {
  exchangeKeySize,
  isFixed,
  isValidBody,
  isValidId,
  ivSize,
  maxSealedSize,
  minSealedSize,
  saltSize,
  signatureSize,
} from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";
import type { Keys } from "./vault.ts";

export const historyVersion = 2;
export const legacyVersion = 1;
export const maxStoredMessages = 5000;
export const maxRecordSize = 8192;

const macSize = 32;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const context = encoder.encode("ghostx/history/v2\0");
const legacyContext = encoder.encode("ghostx/history/v1\0");
const deliveries: readonly SettledDelivery[] = [
  "pending",
  "queued",
  "delivered",
  "expired",
  "unavailable",
  "failed",
];
const sentFields = ["v", "id", "peer", "direction", "delivery", "sequence"];
const acceptedDeliveries: readonly SettledDelivery[] = [
  "queued",
  "delivered",
  "expired",
];
const receivedFields = ["v", "id", "peer", "direction", "read", "sequence"];
const legacySealed = ["key", "signature", "salt", "iv", "ciphertext", "mac"];

type Metadata =
  | {
      id: string;
      peer: string;
      sequence: number;
      direction: "sent";
      delivery: SettledDelivery;
      accepted?: number;
    }
  | {
      id: string;
      peer: string;
      sequence: number;
      direction: "received";
      read: boolean;
    };

export type PersistedRecord = Metadata & {
  v: number;
  iv: string;
  ciphertext: string;
};

type LegacyRecord = Metadata & {
  v: number;
  key: string;
  signature: string;
  salt: string;
  iv: string;
  ciphertext: string;
  mac: string;
};

function storageKey(peer: string, id: string): string {
  return `${peer}/${id}`;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function state(record: Metadata): SettledDelivery | boolean {
  return record.direction === "sent" ? record.delivery : record.read;
}

function associatedData(v: number, record: Metadata): Uint8Array<ArrayBuffer> {
  return concat(
    context,
    encoder.encode(
      JSON.stringify([
        v,
        record.id,
        record.peer,
        record.direction,
        state(record),
        record.sequence,
        ...(record.direction === "sent" && record.accepted !== undefined
          ? [record.accepted]
          : []),
      ]),
    ),
  );
}

function shapeOf(
  key: string,
  value: unknown,
  version: number,
  extra: readonly string[],
): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  if (record.v !== version) {
    return null;
  }
  if (record.direction !== "sent" && record.direction !== "received") {
    return null;
  }
  const accepted =
    record.direction === "sent" &&
    version === historyVersion &&
    Object.hasOwn(record, "accepted");
  const expected = [
    ...(record.direction === "sent" ? sentFields : receivedFields),
    ...(accepted ? ["accepted"] : []),
    ...extra,
  ];
  const names = Object.keys(record);
  if (
    names.length !== expected.length ||
    !expected.every((name) => names.includes(name)) ||
    !isValidId(record.id) ||
    !isIdentity(record.peer) ||
    key !== storageKey(record.peer, record.id) ||
    typeof record.sequence !== "number" ||
    !Number.isSafeInteger(record.sequence) ||
    record.sequence < 1 ||
    (record.direction === "sent"
      ? !deliveries.includes(record.delivery as SettledDelivery)
      : typeof record.read !== "boolean") ||
    (accepted &&
      (typeof record.accepted !== "number" ||
        !Number.isSafeInteger(record.accepted) ||
        record.accepted < 1 ||
        !acceptedDeliveries.includes(record.delivery as SettledDelivery))) ||
    JSON.stringify(record).length > maxRecordSize
  ) {
    return null;
  }
  return record;
}

export function parseRecord(
  key: string,
  value: unknown,
): PersistedRecord | null {
  const record = shapeOf(key, value, historyVersion, ["iv", "ciphertext"]);
  if (
    !record ||
    !isFixed(record.iv, ivSize) ||
    decodeBase64UrlRange(record.ciphertext, minSealedSize, maxSealedSize) ===
      null
  ) {
    return null;
  }
  return record as PersistedRecord;
}

export function parseLegacyRecord(
  key: string,
  value: unknown,
): LegacyRecord | null {
  const record = shapeOf(key, value, legacyVersion, legacySealed);
  if (
    !record ||
    !isFixed(record.key, exchangeKeySize) ||
    !isFixed(record.signature, signatureSize) ||
    !isFixed(record.salt, saltSize) ||
    !isFixed(record.iv, ivSize) ||
    typeof record.ciphertext !== "string" ||
    !isFixed(record.mac, macSize)
  ) {
    return null;
  }
  return record as LegacyRecord;
}

function legacyMacInput(record: LegacyRecord): Uint8Array<ArrayBuffer> {
  const fields = [
    ...(record.direction === "sent" ? sentFields : receivedFields),
    "key",
    "signature",
    "salt",
    "iv",
    "ciphertext",
  ];
  const values = fields.map(
    (name) => (record as unknown as Record<string, unknown>)[name],
  );
  return concat(legacyContext, encoder.encode(JSON.stringify(values)));
}

function metadataOf(record: Metadata): Metadata {
  return record.direction === "sent"
    ? {
        id: record.id,
        peer: record.peer,
        sequence: record.sequence,
        direction: "sent",
        delivery: record.delivery,
        ...(record.accepted === undefined ? {} : { accepted: record.accepted }),
      }
    : {
        id: record.id,
        peer: record.peer,
        sequence: record.sequence,
        direction: "received",
        read: record.read,
      };
}

export type RestoreResult = { restored: Restored[]; rejected: number };

export class History implements HistoryPort {
  readonly #store: KeyValueStore;
  readonly #keys: Keys;
  readonly #integrity: CryptoKey;
  readonly #storage: CryptoKey;
  readonly #records = new Map<string, PersistedRecord>();
  #rejected = 0;
  #migrated = 0;
  #queue: Promise<void> = Promise.resolve();
  #closed = false;

  private constructor(
    store: KeyValueStore,
    keys: Keys,
    integrity: CryptoKey,
    storage: CryptoKey,
  ) {
    this.#store = store;
    this.#keys = keys;
    this.#integrity = integrity;
    this.#storage = storage;
  }

  static async open(
    store: KeyValueStore,
    keys: Keys,
    integrity: CryptoKey,
    storage: CryptoKey,
  ): Promise<History> {
    const history = new History(store, keys, integrity, storage);
    const entries = await store.getAll("messages");
    const checked = await Promise.all(
      entries.map(async ({ key, value }) => {
        const record = parseRecord(key, value);
        if (record) {
          return record;
        }
        const legacy = parseLegacyRecord(key, value);
        return legacy ? history.#migrate(key, legacy) : null;
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

  get migrated(): number {
    return this.#migrated;
  }

  async restore(): Promise<RestoreResult> {
    const self = this.#keys.identity;
    const entries = [...this.#records.entries()];
    const opened = await Promise.all(
      entries.map(async ([, record]): Promise<Restored | null> => {
        const body = await this.#decrypt(record);
        if (body === null) {
          return null;
        }
        const sent = record.direction === "sent";
        const base = {
          id: record.id,
          from: sent ? self : record.peer,
          to: sent ? record.peer : self,
          sequence: record.sequence,
        };
        return record.direction === "sent"
          ? {
              ...base,
              direction: "sent",
              body,
              delivery: record.delivery,
              ...(record.accepted === undefined
                ? {}
                : { accepted: record.accepted }),
            }
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

  has(peer: string, id: string): boolean {
    return this.#records.get(storageKey(peer, id))?.direction === "received";
  }

  received(entry: {
    id: string;
    peer: string;
    sequence: number;
    read: boolean;
    body: string;
  }): Promise<boolean> {
    const { body, ...metadata } = entry;
    return this.#enqueue(
      () => this.#persist({ ...metadata, direction: "received" }, body),
      false,
    );
  }

  sent(entry: {
    id: string;
    peer: string;
    sequence: number;
    delivery: SettledDelivery;
    body: string;
    accepted?: number;
  }): Promise<boolean> {
    const { body, accepted, ...rest } = entry;
    const metadata = accepted === undefined ? rest : { ...rest, accepted };
    return this.#enqueue(async () => {
      const current = this.#records.get(storageKey(metadata.peer, metadata.id));
      if (
        current?.direction === "sent" &&
        !advances(current.delivery, metadata.delivery)
      ) {
        return true;
      }
      return this.#persist({ ...metadata, direction: "sent" }, body);
    }, false);
  }

  settle(
    peer: string,
    id: string,
    delivery: SettledDelivery,
    accepted?: number,
  ): Promise<boolean> {
    return this.#enqueue(async () => {
      const record = this.#records.get(storageKey(peer, id));
      if (
        record?.direction !== "sent" ||
        !advances(record.delivery, delivery)
      ) {
        return true;
      }
      const body = await this.#decrypt(record);
      if (body === null) {
        return false;
      }
      return this.#persist(
        {
          ...metadataOf(record),
          delivery,
          ...(accepted === undefined || record.accepted !== undefined
            ? {}
            : { accepted }),
        } as Metadata,
        body,
      );
    }, false);
  }

  read(identity: string): void {
    void this.#enqueue(async () => {
      for (const record of [...this.#records.values()]) {
        if (
          record.peer === identity &&
          record.direction === "received" &&
          !record.read
        ) {
          const body = await this.#decrypt(record);
          if (body !== null) {
            await this.#persist(
              { ...metadataOf(record), read: true } as Metadata,
              body,
            );
          }
        }
      }
      return true;
    }, false);
  }

  flush(): Promise<void> {
    return this.#queue;
  }

  close(): Promise<void> {
    this.#closed = true;
    return this.#queue;
  }

  async #migrate(
    key: string,
    legacy: LegacyRecord,
  ): Promise<PersistedRecord | null> {
    try {
      const mac = decodeBase64Url(legacy.mac, macSize);
      const authentic =
        mac &&
        (await crypto.subtle.verify(
          "HMAC",
          this.#integrity,
          mac,
          legacyMacInput(legacy),
        ));
      const peerKey =
        authentic &&
        (await verifyBundle({
          identity: legacy.peer,
          key: legacy.key,
          signature: legacy.signature,
        }));
      if (!peerKey) {
        return null;
      }
      const self = this.#keys.identity;
      const own = this.#keys.exchange.publicRaw;
      const sent = legacy.direction === "sent";
      const parties: Parties = {
        id: legacy.id,
        from: sent ? self : legacy.peer,
        to: sent ? legacy.peer : self,
        fromKey: sent ? own : peerKey,
        toKey: sent ? peerKey : own,
      };
      const body = await this.#keys.exchange.openLegacy(parties, {
        salt: legacy.salt,
        iv: legacy.iv,
        ciphertext: legacy.ciphertext,
      });
      if (body === null || !isValidBody(body)) {
        return null;
      }
      const record = await this.#seal(metadataOf(legacy), body);
      if (!record) {
        return null;
      }
      const replaced = await this.#store.swap(
        "messages",
        key,
        (current) =>
          typeof current === "object" &&
          current !== null &&
          (current as { mac?: unknown }).mac === legacy.mac,
        record,
      );
      if (!replaced) {
        const current = parseRecord(
          key,
          await this.#store.get("messages", key),
        );
        return current && (await this.#decrypt(current)) !== null
          ? current
          : null;
      }
      this.#migrated += 1;
      return record;
    } catch {
      return null;
    }
  }

  async #seal(
    metadata: Metadata,
    body: string,
  ): Promise<PersistedRecord | null> {
    const iv = crypto.getRandomValues(new Uint8Array(ivSize));
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: associatedData(historyVersion, metadata),
      },
      this.#storage,
      encoder.encode(body),
    );
    const record = {
      v: historyVersion,
      ...metadata,
      iv: encodeBase64Url(iv),
      ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
    };
    return parseRecord(storageKey(metadata.peer, metadata.id), record);
  }

  async #decrypt(record: PersistedRecord): Promise<string | null> {
    try {
      const iv = decodeBase64Url(record.iv, ivSize);
      const ciphertext = decodeBase64UrlRange(
        record.ciphertext,
        minSealedSize,
        maxSealedSize,
      );
      if (!iv || !ciphertext) {
        return null;
      }
      const plaintext = await crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: associatedData(record.v, metadataOf(record)),
        },
        this.#storage,
        ciphertext,
      );
      const body = decoder.decode(plaintext);
      return isValidBody(body) ? body : null;
    } catch {
      return null;
    }
  }

  #enqueue<T>(task: () => Promise<T>, fallback: T): Promise<T> {
    if (this.#closed) {
      return Promise.resolve(fallback);
    }
    const run = this.#queue.then(task);
    this.#queue = run.then(
      () => {},
      () => {},
    );
    return run.catch(() => fallback);
  }

  async #persist(metadata: Metadata, body: string): Promise<boolean> {
    if (!isValidBody(body)) {
      return false;
    }
    const record = await this.#seal(metadata, body);
    if (!record) {
      return false;
    }
    const key = storageKey(record.peer, record.id);
    await this.#store.put("messages", key, record);
    this.#records.set(key, record);
    const expired = this.#expired(key);
    if (expired.length > 0) {
      await this.#store.delete("messages", expired);
      expired.forEach((name) => this.#records.delete(name));
    }
    return true;
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
