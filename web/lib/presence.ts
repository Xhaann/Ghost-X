import type { AuthState } from "./auth.ts";
import type { Client } from "./client.ts";
import { Listeners } from "./listeners.ts";

export type PresenceStatus = "inactive" | "pending" | "active";

export type PresenceState = {
  status: PresenceStatus;
  identities: readonly string[];
};

export interface AuthSource {
  readonly state: AuthState;
  onState(listener: (state: AuthState) => void): () => void;
}

const inactive: PresenceState = { status: "inactive", identities: [] };

export class Presence {
  readonly #client: Client;
  readonly #auth: AuthSource;
  readonly #states = new Listeners<PresenceState>();
  readonly #identities = new Set<string>();
  #status: PresenceStatus = "inactive";
  #state: PresenceState = inactive;
  #generation = 0;
  #detach: (() => void) | null = null;

  constructor(client: Client, auth: AuthSource) {
    this.#client = client;
    this.#auth = auth;
  }

  get state(): PresenceState {
    return this.#state;
  }

  onState(listener: (state: PresenceState) => void): () => void {
    return this.#states.add(listener);
  }

  start(): void {
    if (this.#detach) {
      return;
    }
    const detach = [
      this.#client.onMessage((message) => {
        if (message.type === "present" || message.type === "absent") {
          this.#apply(message.payload.identity, message.type === "present");
        }
      }),
      this.#auth.onState((state) => {
        if (state === "authenticated") {
          this.#subscribe();
        } else {
          this.#reset();
        }
      }),
    ];
    this.#detach = () => detach.forEach((release) => release());
    if (this.#auth.state === "authenticated") {
      this.#subscribe();
    }
  }

  stop(): void {
    this.#detach?.();
    this.#detach = null;
    this.#reset();
  }

  #subscribe(): void {
    const generation = ++this.#generation;
    this.#identities.clear();
    this.#status = "pending";
    this.#publish();
    this.#client.request({ type: "presence", payload: {} }).then(
      (reply) => this.#settle(generation, reply?.type === "presence"),
      () => this.#settle(generation, false),
    );
  }

  #settle(generation: number, ok: boolean): void {
    if (generation !== this.#generation) {
      return;
    }
    if (ok) {
      this.#status = "active";
      this.#publish();
    } else {
      this.#reset();
    }
  }

  #apply(identity: string, present: boolean): void {
    if (this.#status === "inactive") {
      return;
    }
    const changed = present
      ? !this.#identities.has(identity) && !!this.#identities.add(identity)
      : this.#identities.delete(identity);
    if (changed) {
      this.#publish();
    }
  }

  #reset(): void {
    this.#generation += 1;
    this.#identities.clear();
    this.#status = "inactive";
    this.#publish();
  }

  #publish(): void {
    const identities = [...this.#identities].sort();
    if (
      this.#state.status === this.#status &&
      this.#state.identities.length === identities.length &&
      this.#state.identities.every((id, i) => id === identities[i])
    ) {
      return;
    }
    this.#state = { status: this.#status, identities };
    this.#states.emit(this.#state);
  }
}
