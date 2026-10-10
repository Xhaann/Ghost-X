import { type DeviceEntry, type Roster, rosterDevice } from "./device.ts";
import { isIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import type { Relay } from "./relay.ts";
import type { Trust } from "./trust.ts";

export class Rosters {
  readonly #relay: Relay;
  readonly #trust: Trust;
  readonly #inflight = new Map<string, Promise<Roster | null>>();
  readonly #updates = new Listeners<Roster>();

  constructor(relay: Relay, trust: Trust) {
    this.#relay = relay;
    this.#trust = trust;
  }

  onUpdate(listener: (roster: Roster) => void): () => void {
    return this.#updates.add(listener);
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
    const roster = await this.#relay.roster(identity);
    if (!roster || roster.identity !== identity) {
      return this.cached(identity);
    }
    const observed = await this.#trust.observe(roster);
    if (!observed) {
      return this.cached(identity);
    }
    this.#updates.emit(observed);
    return observed;
  }
}
