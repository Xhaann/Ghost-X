import {
  decodeBase64Url,
  decodeBase64UrlRange,
  encodeBase64Url,
} from "./base64.ts";
import { isIdentity } from "./identity.ts";
import { pairAddress } from "./pairs.ts";
import {
  deviceIdSize,
  isFixed,
  isMessageId,
  isValidBody,
  maxBodySize,
} from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";

export const outboxVersion = 1;
export const maxOutbox = 256;
export const outboxLifetime = 72 * 60 * 60 * 1000;

export type Path = { peer: string; device: string; id: string };

export type Pending = Path & { body: string; created: number };

type Sealed = Path & {
  v: number;
  created: number;
  iv: string;
  ciphertext: string;
};

const ivSize = 12;
const tagSize = 16;
const fields = ["v", "peer", "device", "id", "created", "iv", "ciphertext"];
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function keyOf(path: Path): string {
  return `${path.peer}/${path.device}/${path.id}`;
}

function associatedData(record: Path & { created: number }) {
  return encoder.encode(
    JSON.stringify([
      "ghostx/outbox/v1",
      record.peer,
      record.device,
      record.id,
      record.created,
    ]),
  );
}

function parse(key: string, value: unknown): Sealed | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const r = value as Record<string, unknown>;
  const names = Object.keys(r);
  if (
    names.length !== fields.length ||
    !fields.every((name) => names.includes(name)) ||
    r.v !== outboxVersion ||
    !isIdentity(r.peer) ||
    !isFixed(r.device, deviceIdSize) ||
    !isMessageId(r.id) ||
    !Number.isSafeInteger(r.created) ||
    (r.created as number) < 0 ||
    !isFixed(r.iv, ivSize) ||
    typeof r.ciphertext !== "string"
  ) {
    return null;
  }
  const record = r as Sealed;
  return keyOf(record) === key ? record : null;
}

export class Outbox {
  readonly #store: KeyValueStore;
  readonly #storage: CryptoKey;
  readonly #records = new Map<string, Sealed>();

  private constructor(store: KeyValueStore, storage: CryptoKey) {
    this.#store = store;
    this.#storage = storage;
  }

  static async open(store: KeyValueStore, storage: CryptoKey): Promise<Outbox> {
    const outbox = new Outbox(store, storage);
    const invalid: string[] = [];
    for (const { key, value } of await store.getAll("outbox")) {
      const record = parse(key, value);
      if (record && outbox.#records.size < maxOutbox) {
        outbox.#records.set(key, record);
      } else {
        invalid.push(key);
      }
    }
    if (invalid.length > 0) {
      await store.delete("outbox", invalid);
    }
    return outbox;
  }

  get size(): number {
    return this.#records.size;
  }

  fits(count: number): boolean {
    return this.#records.size + count <= maxOutbox;
  }

  addresses(): string[] {
    return [
      ...new Set(
        [...this.#records.values()].map((r) => pairAddress(r.peer, r.device)),
      ),
    ];
  }

  paths(): (Path & { created: number })[] {
    return [...this.#records.values()].map((r) => ({
      peer: r.peer,
      device: r.device,
      id: r.id,
      created: r.created,
    }));
  }

  async add(paths: readonly Path[], body: string, now: number) {
    const fresh = paths.filter((p) => !this.#records.has(keyOf(p)));
    if (!isValidBody(body) || !this.fits(fresh.length)) {
      return false;
    }
    const sealed: Sealed[] = [];
    for (const path of fresh) {
      if (
        !isIdentity(path.peer) ||
        !isFixed(path.device, deviceIdSize) ||
        !isMessageId(path.id)
      ) {
        return false;
      }
      const iv = crypto.getRandomValues(new Uint8Array(ivSize));
      const ciphertext = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: associatedData({ ...path, created: now }),
        },
        this.#storage,
        encoder.encode(body),
      );
      sealed.push({
        v: outboxVersion,
        peer: path.peer,
        device: path.device,
        id: path.id,
        created: now,
        iv: encodeBase64Url(iv),
        ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
      });
    }
    for (const record of sealed) {
      await this.#store.put("outbox", keyOf(record), record);
      this.#records.set(keyOf(record), record);
    }
    return true;
  }

  async take(peer: string, device: string): Promise<Pending[]> {
    const records = [...this.#records.values()]
      .filter((r) => r.peer === peer && r.device === device)
      .sort((a, b) => a.created - b.created || (a.id < b.id ? -1 : 1));
    const out: Pending[] = [];
    for (const record of records) {
      const body = await this.#open(record);
      if (body === null) {
        await this.remove([record]);
        continue;
      }
      out.push({ ...record, body });
    }
    return out;
  }

  async remove(paths: readonly Path[]): Promise<void> {
    const keys = paths.map(keyOf).filter((key) => this.#records.has(key));
    if (keys.length === 0) {
      return;
    }
    await this.#store.delete("outbox", keys);
    keys.forEach((key) => this.#records.delete(key));
  }

  async #open(record: Sealed): Promise<string | null> {
    const iv = decodeBase64Url(record.iv, ivSize);
    const ciphertext = decodeBase64UrlRange(
      record.ciphertext,
      tagSize + 1,
      tagSize + maxBodySize,
    );
    if (!iv || !ciphertext) {
      return null;
    }
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: associatedData(record) },
        this.#storage,
        ciphertext,
      );
      const body = decoder.decode(plaintext);
      return isValidBody(body) ? body : null;
    } catch {
      return null;
    }
  }
}
