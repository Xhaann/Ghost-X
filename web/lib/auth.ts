import { decodeBase64Url } from "./base64.ts";
import type { Client } from "./client.ts";
import type { IdentityKey } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import { nonceSize } from "./protocol.ts";

export type AuthState =
  "unauthenticated" | "authenticating" | "authenticated" | "failed";

const context = new TextEncoder().encode("ghostx/session/authenticate/v1\0");

export function authMessage(nonce: Uint8Array): Uint8Array<ArrayBuffer> {
  const message = new Uint8Array(context.length + nonce.length);
  message.set(context);
  message.set(nonce, context.length);
  return message;
}

export class Authenticator {
  readonly #client: Client;
  readonly #key: IdentityKey;
  readonly #states = new Listeners<AuthState>();
  #state: AuthState = "unauthenticated";
  #attempt = 0;
  #detach: (() => void) | null = null;

  constructor(client: Client, key: IdentityKey) {
    this.#client = client;
    this.#key = key;
  }

  get state(): AuthState {
    return this.#state;
  }

  onState(listener: (state: AuthState) => void): () => void {
    return this.#states.add(listener);
  }

  start(): void {
    if (this.#detach) {
      return;
    }
    this.#detach = this.#client.onState((state) => {
      if (state === "connected") {
        this.#run();
      } else {
        this.#reset();
      }
    });
    if (this.#client.state === "connected") {
      this.#run();
    }
  }

  stop(): void {
    this.#detach?.();
    this.#detach = null;
    this.#reset();
  }

  retry(): void {
    if (
      this.#detach &&
      this.#state === "failed" &&
      this.#client.state === "connected"
    ) {
      this.#run();
    }
  }

  #reset(): void {
    this.#attempt += 1;
    this.#setState("unauthenticated");
  }

  #run(): void {
    const attempt = ++this.#attempt;
    this.#setState("authenticating");
    this.#authenticate(attempt).then(
      (ok) => this.#finish(attempt, ok),
      () => this.#finish(attempt, false),
    );
  }

  #finish(attempt: number, ok: boolean): void {
    if (attempt === this.#attempt) {
      this.#setState(ok ? "authenticated" : "failed");
    }
  }

  async #authenticate(attempt: number): Promise<boolean> {
    const challenge = await this.#client.request({
      type: "challenge",
      payload: {},
    });
    if (attempt !== this.#attempt || challenge?.type !== "challenge") {
      return false;
    }
    const nonce = decodeBase64Url(challenge.payload.nonce, nonceSize);
    const signature = nonce && (await this.#key.sign(authMessage(nonce)));
    if (attempt !== this.#attempt || !signature) {
      return false;
    }
    const reply = await this.#client.request({
      type: "authenticate",
      payload: { identity: this.#key.identity, signature },
    });
    return (
      reply?.type === "authenticated" &&
      reply.payload.identity === this.#key.identity
    );
  }

  #setState(state: AuthState): void {
    if (this.#state === state) {
      return;
    }
    this.#state = state;
    this.#states.emit(state);
  }
}
