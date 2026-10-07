import type { Client } from "./client.ts";
import { type DeviceEntry, type Roster, rosterDevice } from "./device.ts";
import { isIdentity } from "./identity.ts";
import type { Trust } from "./trust.ts";

export class Rosters {
  readonly #client: Client;
  readonly #trust: Trust;
  readonly #inflight = new Map<string, Promise<Roster | null>>();

  constructor(client: Client, trust: Trust) {
    this.#client = client;
    this.#trust = trust;
  }

  cached(identity: string): Roster | null {
    return this.#trust.roster(identity);
  }

  device(identity: string, id: string): DeviceEntry | null {
    return rosterDevice(this.cached(identity), id);
  }

  fetch(identity: string): Promise<Roster | null> {
    if (!isIdentity(identity)) {
      return Promise.resolve(null);
    }
    const existing = this.#inflight.get(identity);
    if (existing) {
      return existing;
    }
    const run = this.#fetch(identity).finally(() =>
      this.#inflight.delete(identity),
    );
    this.#inflight.set(identity, run);
    return run;
  }

  async resolve(identity: string, id: string): Promise<DeviceEntry | null> {
    return (
      this.device(identity, id) ?? rosterDevice(await this.fetch(identity), id)
    );
  }

  async #fetch(identity: string): Promise<Roster | null> {
    const reply = await this.#client.request({
      type: "devices",
      payload: { identity },
    });
    if (reply?.type !== "devices" || reply.payload.identity !== identity) {
      return this.cached(identity);
    }
    return (await this.#trust.observe(reply.payload)) ?? this.cached(identity);
  }
}
