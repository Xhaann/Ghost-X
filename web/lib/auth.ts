import { decodeBase64Url } from "./base64.ts";
import type { Client } from "./client.ts";
import type { DeviceStatus } from "./devices.ts";
import { parseIdentity } from "./identity.ts";
import { Listeners } from "./listeners.ts";
import { deviceIdSize, nonceSize } from "./protocol.ts";
import type { Keys } from "./vault.ts";

export type AuthState =
  | "unauthenticated"
  | "authenticating"
  | "authenticated"
  | "failed"
  | "pending"
  | "revoked";

export interface DeviceSync {
  sync(client: Client): Promise<DeviceStatus>;
}

export const pendingRetry = 2000;

const context = new TextEncoder().encode("ghostx/session/authenticate/v2\0");

export function authMessage(
  nonce: Uint8Array,
  identity: string,
  device: string,
): Uint8Array<ArrayBuffer> | null {
  const owner = parseIdentity(identity);
  const deviceRaw = decodeBase64Url(device, deviceIdSize);
  if (!owner || !deviceRaw) {
    return null;
  }
  const message = new Uint8Array(
    context.length + nonce.length + owner.length + deviceRaw.length,
  );
  message.set(context);
  message.set(nonce, context.length);
  message.set(owner, context.length + nonce.length);
  message.set(deviceRaw, context.length + nonce.length + owner.length);
  return message;
}

export class Authenticator {
  readonly #client: Client;
  readonly #keys: Keys;
  readonly #devices: DeviceSync;
  readonly #states = new Listeners<AuthState>();
  #state: AuthState = "unauthenticated";
  #attempt = 0;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #detach: (() => void) | null = null;

  constructor(client: Client, keys: Keys, devices: DeviceSync) {
    this.#client = client;
    this.#keys = keys;
    this.#devices = devices;
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
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    this.#setState("unauthenticated");
  }

  #run(): void {
    const attempt = ++this.#attempt;
    if (this.#timer) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    this.#setState("authenticating");
    this.#authenticate(attempt).then(
      (state) => this.#finish(attempt, state),
      () => this.#finish(attempt, "failed"),
    );
  }

  #finish(attempt: number, state: AuthState): void {
    if (attempt !== this.#attempt) {
      return;
    }
    this.#setState(state);
    if (state === "pending" && this.#detach) {
      this.#timer = setTimeout(() => {
        this.#timer = null;
        if (attempt === this.#attempt && this.#client.state === "connected") {
          this.#run();
        }
      }, pendingRetry);
    }
  }

  async #authenticate(attempt: number): Promise<AuthState> {
    const status = await this.#devices.sync(this.#client);
    if (attempt !== this.#attempt) {
      return "failed";
    }
    if (status !== "authorized") {
      return status;
    }
    const challenge = await this.#client.request({
      type: "challenge",
      payload: {},
    });
    if (attempt !== this.#attempt || challenge?.type !== "challenge") {
      return "failed";
    }
    const { identity, deviceId, device } = this.#keys;
    const nonce = decodeBase64Url(challenge.payload.nonce, nonceSize);
    const message = nonce && authMessage(nonce, identity, deviceId);
    const signature = message && (await device.sign(message));
    if (attempt !== this.#attempt || !signature) {
      return "failed";
    }
    const reply = await this.#client.request({
      type: "authenticate",
      payload: { identity, device: deviceId, signature },
    });
    return reply?.type === "authenticated" &&
      reply.payload.identity === identity &&
      reply.payload.device === deviceId
      ? "authenticated"
      : "failed";
  }

  #setState(state: AuthState): void {
    if (this.#state === state) {
      return;
    }
    this.#state = state;
    this.#states.emit(state);
  }
}
