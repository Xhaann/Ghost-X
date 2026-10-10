import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { type Roster, rosterFingerprint, verifyRoster } from "./device.ts";
import {
  type Fingerprint,
  fingerprintOf,
  isFingerprintValue,
} from "./fingerprint.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import {
  exchangeKeySize,
  isFixed,
  isRosterVersion,
  signatureSize,
} from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";

export const trustVersion = 3;

export type TrustState = "unavailable" | "unverified" | "verified" | "changed";

export type TrustView = {
  identity: string;
  state: TrustState;
  current: Fingerprint | null;
  verified: Fingerprint | null;
};

type Status = "observed" | "verified" | "changed";

type TrustFields = {
  v: number;
  identity: string;
  status: Status;
  version: number;
  fingerprint: string | null;
  signature: string | null;
  confirmed: number;
  confirmedAt: number;
};

export type TrustRecord = TrustFields & { mac: string };

type Observation = { roster: Roster; fingerprint: Fingerprint };

export type Confirmation = {
  version: number;
  signature: string | null;
  at: number;
};

const macSize = 32;
const encoder = new TextEncoder();
const context = encoder.encode("ghostx/trust/v3\0");
const previousContext = encoder.encode("ghostx/trust/v2\0");
const legacyContext = encoder.encode("ghostx/trust/v1\0");
const previousFields = [
  "v",
  "identity",
  "status",
  "version",
  "fingerprint",
  "mac",
];
const recordFields = [
  ...previousFields,
  "signature",
  "confirmed",
  "confirmedAt",
];
const legacyFields = ["v", "identity", "status", "key", "fingerprint", "mac"];

function withContext(
  prefix: Uint8Array,
  values: unknown[],
): Uint8Array<ArrayBuffer> {
  const body = encoder.encode(JSON.stringify(values));
  const out = new Uint8Array(prefix.length + body.length);
  out.set(prefix);
  out.set(body, prefix.length);
  return out;
}

function macInput(f: TrustFields): Uint8Array<ArrayBuffer> {
  return withContext(context, [
    f.v,
    f.identity,
    f.status,
    f.version,
    f.fingerprint,
    f.signature,
    f.confirmed,
    f.confirmedAt,
  ]);
}

function isStatus(value: unknown): value is Status {
  return value === "observed" || value === "verified" || value === "changed";
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

function shape(
  key: string,
  value: unknown,
  names: string[],
): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  return keys.length === names.length &&
    names.every((name) => keys.includes(name)) &&
    isIdentity(record.identity) &&
    record.identity === key &&
    isFixed(record.mac, macSize)
    ? record
    : null;
}

export function parseTrustRecord(
  key: string,
  value: unknown,
): TrustRecord | null {
  const record = shape(key, value, recordFields);
  if (
    !record ||
    record.v !== trustVersion ||
    !isStatus(record.status) ||
    !(record.version === 0 || isRosterVersion(record.version)) ||
    (record.status === "observed"
      ? record.fingerprint !== null
      : !isFingerprintValue(record.fingerprint)) ||
    (record.version === 0
      ? record.signature !== null
      : record.signature !== null &&
        !isFixed(record.signature, signatureSize)) ||
    !(record.confirmed === 0 || isRosterVersion(record.confirmed)) ||
    (record.confirmed as number) > (record.version as number) ||
    !Number.isSafeInteger(record.confirmedAt) ||
    (record.confirmedAt as number) < 0 ||
    (record.confirmed === 0) !== (record.confirmedAt === 0)
  ) {
    return null;
  }
  return record as TrustRecord;
}

export class Trust {
  readonly #store: KeyValueStore;
  readonly #integrity: CryptoKey;
  readonly #entries = new Map<string, TrustRecord>();
  readonly #seen = new Map<string, string>();
  readonly #observed = new Map<string, Observation>();
  readonly #checked = new Map<string, number>();
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
  ): Promise<Trust> {
    const trust = new Trust(store, integrity);
    for (const { key, value } of await store.getAll("trust")) {
      trust.#seen.set(key, tag(value));
      const record =
        (await trust.#restore(key, value)) ??
        (await trust.#upgrade(key, value)) ??
        (await trust.#migrate(key, value));
      if (record) {
        trust.#entries.set(key, record);
      } else {
        trust.#rejected += 1;
      }
    }
    return trust;
  }

  get rejected(): number {
    return this.#rejected;
  }

  onChange(listener: (identity: string) => void): () => void {
    return this.#changes.add(listener);
  }

  pinned(identity: string): number {
    return this.#entries.get(identity)?.version ?? 0;
  }

  roster(identity: string): Roster | null {
    return this.#observed.get(identity)?.roster ?? null;
  }

  confirmation(identity: string): Confirmation | null {
    const entry = this.#entries.get(identity);
    if (!entry || entry.confirmed === 0) {
      return null;
    }
    return {
      version: entry.confirmed,
      signature: entry.confirmed === entry.version ? entry.signature : null,
      at: Math.max(entry.confirmedAt, this.#checked.get(identity) ?? 0),
    };
  }

  view(identity: string): TrustView {
    const entry = this.#entries.get(identity);
    const observed = this.#observed.get(identity);
    const current = observed?.fingerprint ?? null;
    const verified =
      entry && entry.status !== "observed"
        ? fingerprintOf(entry.fingerprint)
        : null;
    let state: TrustState;
    if (entry?.status === "changed") {
      state = "changed";
    } else if (entry?.status === "verified") {
      state = !observed
        ? "unavailable"
        : observed.fingerprint.value === entry.fingerprint
          ? "verified"
          : "changed";
    } else {
      state = observed ? "unverified" : "unavailable";
    }
    return { identity, state, current, verified };
  }

  observe(value: unknown, authoritative = false): Promise<Roster | null> {
    return this.#enqueue(async () => {
      const roster = await verifyRoster(value);
      const print = roster && (await rosterFingerprint(roster));
      if (!roster || !print || this.#closed) {
        return null;
      }
      const identity = roster.identity;
      const entry = this.#entries.get(identity);
      const pinned = entry?.version ?? 0;
      const previous = this.#observed.get(identity);
      if (
        roster.version < pinned ||
        (previous && roster.version < previous.roster.version)
      ) {
        return null;
      }
      if (
        previous &&
        roster.version === previous.roster.version &&
        roster.signature !== previous.roster.signature
      ) {
        return null;
      }
      if (
        entry?.signature &&
        roster.version === pinned &&
        roster.signature !== entry.signature
      ) {
        return null;
      }
      const now = Date.now();
      const confirms = authoritative && entry?.confirmed !== roster.version;
      if (
        roster.version > pinned ||
        (entry && entry.signature === null) ||
        confirms
      ) {
        const status: Status =
          roster.version > pinned &&
          entry?.status === "verified" &&
          entry.fingerprint !== print.value
            ? "changed"
            : (entry?.status ?? "observed");
        const record = await this.#seal({
          v: trustVersion,
          identity,
          status,
          version: roster.version,
          fingerprint: entry?.fingerprint ?? null,
          signature: roster.signature,
          confirmed: authoritative ? roster.version : (entry?.confirmed ?? 0),
          confirmedAt: authoritative ? now : (entry?.confirmedAt ?? 0),
        });
        if (await this.#swap(identity, record)) {
          this.#entries.set(identity, record);
        } else if (roster.version < this.pinned(identity)) {
          return null;
        }
      }
      if (
        authoritative &&
        this.#entries.get(identity)?.confirmed === roster.version
      ) {
        this.#checked.set(identity, now);
      }
      this.#observed.set(identity, { roster, fingerprint: print });
      if (previous?.fingerprint.value !== print.value) {
        this.#changes.emit(identity);
      }
      return roster;
    }).then((r) => r ?? null);
  }

  verify(identity: string, value: string): Promise<boolean> {
    return this.#enqueue(async () => {
      const current = this.#observed.get(identity);
      if (!current || current.fingerprint.value !== value) {
        return false;
      }
      const entry = this.#entries.get(identity);
      const newer = current.roster.version >= this.pinned(identity);
      const record = await this.#seal({
        v: trustVersion,
        identity,
        status: "verified",
        version: Math.max(this.pinned(identity), current.roster.version),
        fingerprint: value,
        signature: newer
          ? current.roster.signature
          : (entry?.signature ?? null),
        confirmed: entry?.confirmed ?? 0,
        confirmedAt: entry?.confirmedAt ?? 0,
      });
      if (!(await this.#swap(identity, record))) {
        return false;
      }
      this.#entries.set(identity, record);
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
    const record =
      value === undefined ? null : await this.#restore(identity, value);
    if (record) {
      this.#entries.set(identity, record);
    } else {
      this.#entries.delete(identity);
    }
    this.#changes.emit(identity);
  }

  async #restore(key: string, value: unknown): Promise<TrustRecord | null> {
    const record = parseTrustRecord(key, value);
    const mac = record && decodeBase64Url(record.mac, macSize);
    if (!record || !mac) {
      return null;
    }
    try {
      const { mac: _, ...fields } = record;
      return (await crypto.subtle.verify(
        "HMAC",
        this.#integrity,
        mac,
        macInput(fields),
      ))
        ? record
        : null;
    } catch {
      return null;
    }
  }

  async #upgrade(key: string, value: unknown): Promise<TrustRecord | null> {
    const previous = shape(key, value, previousFields);
    const mac = previous && decodeBase64Url(previous.mac, macSize);
    if (
      !previous ||
      !mac ||
      previous.v !== 2 ||
      !isStatus(previous.status) ||
      !(previous.version === 0 || isRosterVersion(previous.version)) ||
      (previous.status === "observed"
        ? previous.fingerprint !== null
        : !isFingerprintValue(previous.fingerprint))
    ) {
      return null;
    }
    try {
      const authentic = await crypto.subtle.verify(
        "HMAC",
        this.#integrity,
        mac,
        withContext(previousContext, [
          previous.v,
          previous.identity,
          previous.status,
          previous.version,
          previous.fingerprint,
        ]),
      );
      if (!authentic) {
        return null;
      }
      const record = await this.#seal({
        v: trustVersion,
        identity: key,
        status: previous.status,
        version: previous.version as number,
        fingerprint: previous.fingerprint as string | null,
        signature: null,
        confirmed: 0,
        confirmedAt: 0,
      });
      return (await this.#store.swap(
        "trust",
        key,
        (current) => tag(current) === tag(value),
        record,
      ))
        ? (this.#seen.set(key, tag(record)), record)
        : null;
    } catch {
      return null;
    }
  }

  async #migrate(key: string, value: unknown): Promise<TrustRecord | null> {
    const legacy = shape(key, value, legacyFields);
    const mac = legacy && decodeBase64Url(legacy.mac, macSize);
    if (
      !legacy ||
      !mac ||
      legacy.v !== 1 ||
      (legacy.status !== "verified" && legacy.status !== "changed") ||
      !isFixed(legacy.key, exchangeKeySize) ||
      !isFingerprintValue(legacy.fingerprint)
    ) {
      return null;
    }
    try {
      const authentic = await crypto.subtle.verify(
        "HMAC",
        this.#integrity,
        mac,
        withContext(legacyContext, [
          legacy.v,
          legacy.identity,
          legacy.status,
          legacy.key,
          legacy.fingerprint,
        ]),
      );
      if (!authentic) {
        return null;
      }
      const record = await this.#seal({
        v: trustVersion,
        identity: key,
        status: "changed",
        version: 0,
        fingerprint: legacy.fingerprint as string,
        signature: null,
        confirmed: 0,
        confirmedAt: 0,
      });
      return (await this.#store.swap(
        "trust",
        key,
        (current) => tag(current) === tag(value),
        record,
      ))
        ? (this.#seen.set(key, tag(record)), record)
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
