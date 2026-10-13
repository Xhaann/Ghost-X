import type { Client } from "./client.ts";
import {
  type DeviceEntry,
  type Roster,
  createLinkRequest,
  rosterDevice,
  signRoster,
  verifyLinkRequest,
  verifyRoster,
} from "./device.ts";
import { Listeners } from "./listeners.ts";
import { maxDevices } from "./protocol.ts";
import type { KeyValueStore } from "./storage.ts";
import type { Keys } from "./vault.ts";

export type DeviceStatus = "authorized" | "pending" | "revoked";

export type AuthorizeResult =
  | { ok: true; roster: Roster }
  | {
      ok: false;
      reason:
        | "not_root"
        | "invalid_request"
        | "other_identity"
        | "already_authorized"
        | "device_limit"
        | "not_published";
    };

const rosterKey = "roster";

function now(): number {
  return Math.floor(Date.now() / 1000);
}

export class Devices {
  readonly #store: KeyValueStore;
  readonly #keys: Keys;
  readonly #changes = new Listeners<Roster | null>();
  #roster: Roster | null;
  #queue: Promise<unknown> = Promise.resolve();

  private constructor(store: KeyValueStore, keys: Keys, roster: Roster | null) {
    this.#store = store;
    this.#keys = keys;
    this.#roster = roster;
  }

  static async open(store: KeyValueStore, keys: Keys): Promise<Devices | null> {
    const stored = await store.get("vault", rosterKey);
    let roster =
      stored === undefined ? null : await verifyRoster(stored, true);
    if (
      stored !== undefined &&
      (!roster || roster.identity !== keys.identity)
    ) {
      return null;
    }
    if (!roster && keys.root) {
      roster = await signRoster(keys.root, 1, [ownEntry(keys)]);
      if (!roster) {
        throw new Error("the device roster could not be signed");
      }
      if (!(await store.add("vault", rosterKey, roster))) {
        const existing = await store.get("vault", rosterKey);
        if (existing === undefined) {
          throw new Error("the device roster could not be stored");
        }
        const winner = await verifyRoster(existing, true);
        if (!winner || winner.identity !== keys.identity) {
          return null;
        }
        roster = winner;
      }
    }
    if (roster && keys.root && !rosterDevice(roster, keys.deviceId)) {
      return null;
    }
    return new Devices(store, keys, roster);
  }

  get roster(): Roster | null {
    return this.#roster;
  }

  get own(): DeviceEntry {
    return ownEntry(this.#keys);
  }

  get canManage(): boolean {
    return this.#keys.root !== null;
  }

  get status(): DeviceStatus {
    if (!this.#roster) {
      return "pending";
    }
    return rosterDevice(this.#roster, this.#keys.deviceId)
      ? "authorized"
      : "revoked";
  }

  onChange(listener: (roster: Roster | null) => void): () => void {
    return this.#changes.add(listener);
  }

  adopt(value: unknown): Promise<boolean> {
    return this.#enqueue(async () => {
      const roster = await verifyRoster(value);
      const current = this.#roster;
      if (!roster || roster.identity !== this.#keys.identity) {
        return false;
      }
      if (current && roster.version < current.version) {
        return false;
      }
      if (current && roster.version === current.version) {
        return roster.signature === current.signature;
      }
      if (!current && !rosterDevice(roster, this.#keys.deviceId)) {
        return false;
      }
      if (this.#keys.root && !rosterDevice(roster, this.#keys.deviceId)) {
        return false;
      }
      await this.#store.put("vault", rosterKey, roster);
      this.#roster = roster;
      this.#changes.emit(roster);
      return true;
    }).then((r) => r === true);
  }

  async linkRequest(): Promise<string | null> {
    if (this.#keys.root) {
      return null;
    }
    return createLinkRequest(
      this.#keys.identity,
      this.#keys.device,
      this.#keys.exchange.publicRaw,
      now(),
    );
  }

  async sync(client: Client): Promise<DeviceStatus> {
    const current = this.#roster;
    if (this.#keys.root && current) {
      const reply = await client.request({
        type: "register",
        payload: current,
      });
      if (reply?.type === "registered") {
        return this.status;
      }
      if (reply?.type !== "error" || reply.payload.code !== "stale_roster") {
        return this.status;
      }
    }
    const fetched = await client.request({
      type: "devices",
      payload: { identity: this.#keys.identity },
    });
    if (fetched?.type === "devices") {
      await this.adopt(fetched.payload);
    }
    return this.status;
  }

  async authorize(client: Client, request: string): Promise<AuthorizeResult> {
    const root = this.#keys.root;
    const current = this.#roster;
    if (!root || !current) {
      return { ok: false, reason: "not_root" };
    }
    const link = await verifyLinkRequest(request, now());
    if (!link) {
      return { ok: false, reason: "invalid_request" };
    }
    if (link.identity !== this.#keys.identity) {
      return { ok: false, reason: "other_identity" };
    }
    if (rosterDevice(current, link.device.id)) {
      return { ok: false, reason: "already_authorized" };
    }
    if (current.devices.length >= maxDevices) {
      return { ok: false, reason: "device_limit" };
    }
    return this.#publish(client, root, current, [
      ...current.devices,
      link.device,
    ]);
  }

  async revoke(client: Client, id: string): Promise<AuthorizeResult> {
    const root = this.#keys.root;
    const current = this.#roster;
    if (!root || !current) {
      return { ok: false, reason: "not_root" };
    }
    if (id === this.#keys.deviceId || !rosterDevice(current, id)) {
      return { ok: false, reason: "invalid_request" };
    }
    return this.#publish(
      client,
      root,
      current,
      current.devices.filter((d) => d.id !== id),
    );
  }

  async #publish(
    client: Client,
    root: NonNullable<Keys["root"]>,
    current: Roster,
    devices: DeviceEntry[],
  ): Promise<AuthorizeResult> {
    const next = await signRoster(root, current.version + 1, devices);
    if (!next) {
      return { ok: false, reason: "invalid_request" };
    }
    const reply = await client.request({ type: "register", payload: next });
    if (reply?.type !== "registered" || !(await this.adopt(next))) {
      return { ok: false, reason: "not_published" };
    }
    return { ok: true, roster: next };
  }

  #enqueue<T>(task: () => Promise<T>): Promise<T | undefined> {
    const run = this.#queue.then(task);
    this.#queue = run.catch(() => {});
    return run.catch(() => undefined);
  }
}

function ownEntry(keys: Keys): DeviceEntry {
  return {
    id: keys.deviceId,
    signing: keys.device.identity,
    exchange: keys.exchange.publicKey,
  };
}
