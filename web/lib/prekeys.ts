import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { isCanonicalExchangeKey } from "./fingerprint.ts";
import {
  type Prekey,
  type ResponderKeys,
  deviceIdSize,
  initiationIdSize,
  signPrekey,
} from "./handshake.ts";
import { exchangeKeySize, isEpoch, isFixed, maxEpoch } from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";
import type { Keys } from "./vault.ts";

export const prekeysVersion = 2;
export const poolSize = 20;
export const lowWater = 5;
export const maxLocalOnetime = 40;
export const signedLifetime = 50;
export const consumedLimit = 256;

const recordKey = "prekeys";
const macSize = 32;
const encoder = new TextEncoder();
const context = encoder.encode("ghostx/prekeys/v2\0");
const fields = [
  "v",
  "device",
  "nextSigned",
  "nextOnetime",
  "uses",
  "signed",
  "previous",
  "onetime",
  "consumed",
  "mac",
];

type Slot = { id: number; key: string; privateKey: CryptoKey };

type State = {
  v: number;
  device: string;
  nextSigned: number;
  nextOnetime: number;
  uses: number;
  signed: Slot;
  previous: Slot | null;
  onetime: Slot[];
  consumed: string[];
};

type Stored = State & { mac: string };

export type Publication = {
  device: string;
  signed: Prekey;
  onetime: Prekey[];
};

export type Consumption<T> =
  | { status: "consumed"; value: T }
  | { status: "replay" }
  | { status: "rejected" };

function isPrivate(key: unknown): key is CryptoKey {
  return (
    key instanceof CryptoKey &&
    key.type === "private" &&
    !key.extractable &&
    key.algorithm.name === "X25519" &&
    key.usages.includes("deriveBits")
  );
}

function isSlot(value: unknown): value is Slot {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const slot = value as Record<string, unknown>;
  const key = decodeBase64Url(slot.key, exchangeKeySize);
  return (
    Object.keys(slot).length === 3 &&
    isEpoch(slot.id) &&
    key !== null &&
    isCanonicalExchangeKey(key) &&
    isPrivate(slot.privateKey)
  );
}

function publicOf(slot: Slot | null): [number, string] | null {
  return slot ? [slot.id, slot.key] : null;
}

function macInput(state: State): Uint8Array<ArrayBuffer> {
  const values = encoder.encode(
    JSON.stringify([
      state.v,
      state.device,
      state.nextSigned,
      state.nextOnetime,
      state.uses,
      publicOf(state.signed),
      publicOf(state.previous),
      state.onetime.map(publicOf),
      state.consumed,
    ]),
  );
  const out = new Uint8Array(context.length + values.length);
  out.set(context);
  out.set(values, context.length);
  return out;
}

export function parsePrekeys(value: unknown): Stored | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const names = Object.keys(record);
  if (
    record.v !== prekeysVersion ||
    names.length !== fields.length ||
    !fields.every((name) => names.includes(name)) ||
    !isFixed(record.device, deviceIdSize) ||
    !isEpoch(record.nextSigned) ||
    !isEpoch(record.nextOnetime) ||
    !isEpoch(record.uses) ||
    !isSlot(record.signed) ||
    (record.previous !== null && !isSlot(record.previous)) ||
    !Array.isArray(record.onetime) ||
    record.onetime.length > maxLocalOnetime ||
    !record.onetime.every(isSlot) ||
    !Array.isArray(record.consumed) ||
    record.consumed.length > consumedLimit ||
    !record.consumed.every((id) => isFixed(id, initiationIdSize)) ||
    !isFixed(record.mac, macSize)
  ) {
    return null;
  }
  const state = record as unknown as Stored;
  const ids = state.onetime.map((slot) => slot.id);
  if (
    new Set(ids).size !== ids.length ||
    ids.some((id) => id >= state.nextOnetime) ||
    state.signed.id >= state.nextSigned ||
    (state.previous !== null && state.previous.id >= state.signed.id) ||
    new Set(state.consumed).size !== state.consumed.length
  ) {
    return null;
  }
  return state;
}

async function generate(id: number): Promise<Slot> {
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return { id, key: encodeBase64Url(raw), privateKey: pair.privateKey };
}

function tag(value: unknown): string {
  return typeof value === "object" &&
    value !== null &&
    typeof (value as { mac?: unknown }).mac === "string"
    ? (value as { mac: string }).mac
    : value === undefined
      ? "absent"
      : "invalid";
}

export class PrekeyStore {
  readonly #store: KeyValueStore;
  readonly #keys: Keys;
  readonly #integrity: CryptoKey;
  #state: Stored;

  private constructor(
    store: KeyValueStore,
    keys: Keys,
    integrity: CryptoKey,
    state: Stored,
  ) {
    this.#store = store;
    this.#keys = keys;
    this.#integrity = integrity;
    this.#state = state;
  }

  static async open(
    store: KeyValueStore,
    keys: Keys,
    integrity: CryptoKey,
  ): Promise<PrekeyStore | null> {
    const existing = await store.get("vault", recordKey);
    const stale =
      typeof existing === "object" &&
      existing !== null &&
      (existing as { v?: unknown }).v === 1;
    if (existing !== undefined && !stale) {
      const state = await PrekeyStore.#verify(existing, integrity);
      return state && state.device === keys.deviceId
        ? new PrekeyStore(store, keys, integrity, state)
        : null;
    }
    const slots = await Promise.all(
      Array.from({ length: poolSize }, (_, i) => generate(i + 1)),
    );
    const fresh = await PrekeyStore.#seal(
      {
        v: prekeysVersion,
        device: keys.deviceId,
        nextSigned: 2,
        nextOnetime: poolSize + 1,
        uses: 0,
        signed: await generate(1),
        previous: null,
        onetime: slots,
        consumed: [],
      },
      integrity,
    );
    if (
      stale
        ? await store.swap(
            "vault",
            recordKey,
            (current) =>
              current !== undefined && (current as { v?: unknown }).v === 1,
            fresh,
          )
        : await store.add("vault", recordKey, fresh)
    ) {
      return new PrekeyStore(store, keys, integrity, fresh);
    }
    const winner = await PrekeyStore.#verify(
      await store.get("vault", recordKey),
      integrity,
    );
    return winner ? new PrekeyStore(store, keys, integrity, winner) : null;
  }

  static async #verify(
    value: unknown,
    integrity: CryptoKey,
  ): Promise<Stored | null> {
    const state = parsePrekeys(value);
    const mac = state && decodeBase64Url(state.mac, macSize);
    if (!state || !mac) {
      return null;
    }
    try {
      return (await crypto.subtle.verify(
        "HMAC",
        integrity,
        mac,
        macInput(state),
      ))
        ? state
        : null;
    } catch {
      return null;
    }
  }

  static async #seal(state: State, integrity: CryptoKey): Promise<Stored> {
    const mac = await crypto.subtle.sign("HMAC", integrity, macInput(state));
    return { ...state, mac: encodeBase64Url(new Uint8Array(mac)) };
  }

  get device(): string {
    return this.#state.device;
  }

  get inventory(): {
    signed: number;
    previous: number | null;
    onetime: number[];
  } {
    return {
      signed: this.#state.signed.id,
      previous: this.#state.previous?.id ?? null,
      onetime: this.#state.onetime.map((slot) => slot.id),
    };
  }

  async publication(): Promise<Publication | null> {
    await this.#refresh();
    const state = this.#state;
    const sign = (kind: "signed" | "onetime", slot: Slot) =>
      signPrekey(
        kind,
        this.#keys,
        slot.id,
        decodeBase64Url(slot.key, exchangeKeySize) ?? new Uint8Array(),
      );
    const [signed, ...onetime] = await Promise.all([
      sign("signed", state.signed),
      ...state.onetime.map((slot) => sign("onetime", slot)),
    ]);
    if (!signed || onetime.some((p) => p === null)) {
      return null;
    }
    return { device: state.device, signed, onetime: onetime as Prekey[] };
  }

  async replenish(available: number): Promise<boolean> {
    return this.#update(async (state) => {
      const wanted = Math.max(0, poolSize - Math.max(0, available));
      if (available >= lowWater || wanted === 0) {
        return null;
      }
      if (state.nextOnetime + wanted > maxEpoch) {
        return null;
      }
      const added = await Promise.all(
        Array.from({ length: wanted }, (_, i) =>
          generate(state.nextOnetime + i),
        ),
      );
      const onetime = [...state.onetime, ...added].slice(-maxLocalOnetime);
      return { ...state, onetime, nextOnetime: state.nextOnetime + wanted };
    });
  }

  async rotate(): Promise<boolean> {
    return this.#update(async (state) => {
      if (state.nextSigned >= maxEpoch) {
        return null;
      }
      return {
        ...state,
        previous: state.signed,
        signed: await generate(state.nextSigned),
        nextSigned: state.nextSigned + 1,
        uses: 0,
      };
    });
  }

  async consume<T extends { id: string }>(
    signedId: number,
    onetimeId: number | null,
    use: (keys: ResponderKeys) => Promise<T | null>,
  ): Promise<Consumption<T>> {
    for (let attempt = 0; attempt < 5; attempt++) {
      await this.#refresh();
      const state = this.#state;
      const signed = [state.signed, state.previous].find(
        (slot) => slot !== null && slot.id === signedId,
      );
      const onetime =
        onetimeId === null
          ? null
          : (state.onetime.find((slot) => slot.id === onetimeId) ?? null);
      if (!signed || (onetimeId !== null && !onetime)) {
        return { status: "rejected" };
      }
      const raw = (slot: Slot) =>
        decodeBase64Url(slot.key, exchangeKeySize) ?? new Uint8Array();
      const value = await use({
        signed: {
          id: signed.id,
          key: raw(signed),
          privateKey: signed.privateKey,
        },
        onetime: onetime
          ? {
              id: onetime.id,
              key: raw(onetime),
              privateKey: onetime.privateKey,
            }
          : null,
      });
      if (!value) {
        return { status: "rejected" };
      }
      if (state.consumed.includes(value.id)) {
        return { status: "replay" };
      }
      const next: State = {
        ...state,
        onetime: state.onetime.filter((slot) => slot.id !== onetimeId),
        consumed: [...state.consumed, value.id].slice(-consumedLimit),
        uses: Math.min(state.uses + 1, maxEpoch),
      };
      if (await this.#swap(state, next)) {
        if (next.uses >= signedLifetime) {
          await this.rotate();
        }
        return { status: "consumed", value };
      }
    }
    return { status: "rejected" };
  }

  async #refresh(): Promise<void> {
    const current = await this.#store.get("vault", recordKey);
    if (tag(current) === this.#state.mac) {
      return;
    }
    const state = await PrekeyStore.#verify(current, this.#integrity);
    if (state) {
      this.#state = state;
    }
  }

  async #swap(expected: Stored, next: State): Promise<boolean> {
    const sealed = await PrekeyStore.#seal(next, this.#integrity);
    const swapped = await this.#store.swap(
      "vault",
      recordKey,
      (current) => tag(current) === expected.mac,
      sealed,
    );
    if (swapped) {
      this.#state = sealed;
    }
    return swapped;
  }

  async #update(
    change: (state: Stored) => Promise<State | null>,
  ): Promise<boolean> {
    for (let attempt = 0; attempt < 5; attempt++) {
      await this.#refresh();
      const state = this.#state;
      const next = await change(state);
      if (!next) {
        return false;
      }
      if (await this.#swap(state, next)) {
        return true;
      }
    }
    return false;
  }
}
