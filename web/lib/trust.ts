import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { type KeyBundle, verifyBundle } from "./encryption.ts";
import {
  type Fingerprint,
  fingerprint,
  isFingerprintValue,
} from "./fingerprint.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import { exchangeKeySize, isFixed } from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";

export const trustVersion = 1;

export type TrustState = "unavailable" | "unverified" | "verified" | "changed";

export type TrustView = {
  identity: string;
  state: TrustState;
  current: Fingerprint | null;
  verified: Fingerprint | null;
};

type TrustFields = {
  v: number;
  identity: string;
  status: "verified" | "changed";
  key: string;
  fingerprint: string;
};

export type TrustRecord = TrustFields & { mac: string };

type Entry = { record: TrustRecord; verified: Fingerprint };
type Observation = { key: string; fingerprint: Fingerprint };

const macSize = 32;
const encoder = new TextEncoder();
const context = encoder.encode("ghostx/trust/v1\0");
const recordFields = ["v", "identity", "status", "key", "fingerprint", "mac"];

function macInput(fields: TrustFields): Uint8Array<ArrayBuffer> {
  const values = encoder.encode(
    JSON.stringify([
      fields.v,
      fields.identity,
      fields.status,
      fields.key,
      fields.fingerprint,
    ]),
  );
  const out = new Uint8Array(context.length + values.length);
  out.set(context);
  out.set(values, context.length);
  return out;
}

function tag(value: unknown): string {
  if (value === undefined) {
    return "absent";
  }
  if (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { mac?: unknown }).mac === "string"
  ) {
    return `mac:${(value as { mac: string }).mac}`;
  }
  try {
    return `raw:${JSON.stringify(value)}`;
  } catch {
    return "raw:unserializable";
  }
}

export function parseTrustRecord(
  key: string,
  value: unknown,
): TrustRecord | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const names = Object.keys(record);
  if (
    record.v !== trustVersion ||
    names.length !== recordFields.length ||
    !recordFields.every((name) => names.includes(name)) ||
    !isIdentity(record.identity) ||
    record.identity !== key ||
    (record.status !== "verified" && record.status !== "changed") ||
    !isFixed(record.key, exchangeKeySize) ||
    !isFingerprintValue(record.fingerprint) ||
    !isFixed(record.mac, macSize)
  ) {
    return null;
  }
  return record as TrustRecord;
}

export class Trust {
  readonly #store: KeyValueStore;
  readonly #integrity: CryptoKey;
  readonly #entries = new Map<string, Entry>();
  readonly #seen = new Map<string, string>();
  readonly #observed = new Map<string, Observation>();
  readonly #order = new Map<string, number>();
  readonly #changes = new Listeners<string>();
  #counter = 0;
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
  ): Promise<Trust> {
    const trust = new Trust(store, integrity);
    const entries = await store.getAll("trust");
    await Promise.all(
      entries.map(async ({ key, value }) => {
        trust.#seen.set(key, tag(value));
        const entry = await trust.#restore(key, value);
        if (entry) {
          trust.#entries.set(key, entry);
        } else {
          trust.#rejected += 1;
        }
      }),
    );
    return trust;
  }

  get rejected(): number {
    return this.#rejected;
  }

  onChange(listener: (identity: string) => void): () => void {
    return this.#changes.add(listener);
  }

  view(identity: string): TrustView {
    const entry = this.#entries.get(identity);
    const observed = this.#observed.get(identity);
    const current = observed?.fingerprint ?? null;
    const verified = entry?.verified ?? null;
    let state: TrustState;
    if (entry?.record.status === "changed") {
      state = "changed";
    } else if (entry) {
      state = !observed
        ? "unavailable"
        : observed.fingerprint.value === entry.record.fingerprint
          ? "verified"
          : "changed";
    } else {
      state = observed ? "unverified" : "unavailable";
    }
    return { identity, state, current, verified };
  }

  async observe(bundle: KeyBundle): Promise<void> {
    const order = ++this.#counter;
    if (!(await verifyBundle(bundle))) {
      return;
    }
    const print = await fingerprint(bundle.identity, bundle.key);
    const identity = bundle.identity;
    if (!print || this.#closed || (this.#order.get(identity) ?? 0) > order) {
      return;
    }
    this.#order.set(identity, order);
    const previous = this.#observed.get(identity);
    this.#observed.set(identity, { key: bundle.key, fingerprint: print });
    if (previous?.fingerprint.value !== print.value) {
      this.#changes.emit(identity);
    }
    const entry = this.#entries.get(identity);
    if (
      entry?.record.status === "verified" &&
      entry.record.fingerprint !== print.value
    ) {
      await this.#enqueue(() => this.#invalidate(identity, entry.record));
    }
  }

  verify(identity: string, value: string): Promise<boolean> {
    return this.#enqueue(async () => {
      const current = this.#observed.get(identity);
      if (!current || current.fingerprint.value !== value) {
        return false;
      }
      const record = await this.#seal({
        v: trustVersion,
        identity,
        status: "verified",
        key: current.key,
        fingerprint: value,
      });
      if (!(await this.#swap(identity, record))) {
        return false;
      }
      this.#entries.set(identity, {
        record,
        verified: current.fingerprint,
      });
      this.#changes.emit(identity);
      return true;
    }).then((result) => result === true);
  }

  refresh(identity: string): Promise<void> {
    return this.#enqueue(() => this.#reload(identity)).then(() => {});
  }

  flush(): Promise<void> {
    return this.#queue.then(() => {});
  }

  close(): Promise<void> {
    this.#closed = true;
    return this.flush();
  }

  async #invalidate(identity: string, expected: TrustRecord): Promise<void> {
    if (this.#entries.get(identity)?.record.mac !== expected.mac) {
      return;
    }
    const { mac: _, ...fields } = expected;
    const record = await this.#seal({ ...fields, status: "changed" });
    if (await this.#swap(identity, record)) {
      const entry = this.#entries.get(identity);
      if (entry) {
        this.#entries.set(identity, { ...entry, record });
      }
      this.#changes.emit(identity);
    }
  }

  async #swap(identity: string, record: TrustRecord): Promise<boolean> {
    const expected = this.#seen.get(identity) ?? "absent";
    const swapped = await this.#store.swap(
      "trust",
      identity,
      (current) => tag(current) === expected,
      record,
    );
    if (swapped) {
      this.#seen.set(identity, tag(record));
      return true;
    }
    await this.#reload(identity);
    return false;
  }

  async #reload(identity: string): Promise<void> {
    const value = await this.#store.get("trust", identity);
    this.#seen.set(identity, tag(value));
    const entry =
      value === undefined ? null : await this.#restore(identity, value);
    if (entry) {
      this.#entries.set(identity, entry);
    } else {
      this.#entries.delete(identity);
    }
    this.#changes.emit(identity);
  }

  async #restore(key: string, value: unknown): Promise<Entry | null> {
    const record = parseTrustRecord(key, value);
    const mac = record && decodeBase64Url(record.mac, macSize);
    if (!record || !mac) {
      return null;
    }
    try {
      const { mac: _, ...fields } = record;
      const [authentic, verified] = await Promise.all([
        crypto.subtle.verify("HMAC", this.#integrity, mac, macInput(fields)),
        fingerprint(record.identity, record.key),
      ]);
      return authentic && verified && verified.value === record.fingerprint
        ? { record, verified }
        : null;
    } catch {
      return null;
    }
  }

  async #seal(fields: TrustFields): Promise<TrustRecord> {
    const mac = await crypto.subtle.sign(
      "HMAC",
      this.#integrity,
      macInput(fields),
    );
    return { ...fields, mac: encodeBase64Url(new Uint8Array(mac)) };
  }

  #enqueue<T>(task: () => Promise<T>): Promise<T | undefined> {
    if (this.#closed) {
      return Promise.resolve(undefined);
    }
    const run = this.#queue.then(task);
    this.#queue = run.catch(() => {});
    return run.catch(() => undefined);
  }
}
