import type { Client } from "./client.ts";
import type { Receipt } from "./messenger.ts";
import type { Publication } from "./prekeys.ts";
import type {
  ClientMessage,
  ErrorCode,
  ServerMessage,
  WireDeviceBundle,
  WireEnvelope,
  WireRoster,
} from "./protocol.ts";

export type RelayEvent = Extract<
  ServerMessage,
  { type: "initiation" | "acceptance" | "message" | "receipt" }
>;

export type Delivery = Extract<RelayEvent, { type: "message" }>["payload"];

export type Initiation = Extract<
  ClientMessage,
  { type: "initiate" }
>["payload"];

export type Acceptance = Extract<ClientMessage, { type: "accept" }>["payload"];

export type BundleResult =
  { bundles: WireDeviceBundle[] } | "unavailable" | "failed";

export type InitiateOutcome = "initiated" | "unavailable" | "failed";

export type SendOutcome = "queued" | ErrorCode | null;

export interface Relay {
  reaches(peer: string, device: string): boolean;
  roster(identity: string): Promise<WireRoster | null>;
  publish(publication: Publication): Promise<number | null>;
  bundle(identity: string): Promise<BundleResult>;
  initiate(initiation: Initiation): Promise<InitiateOutcome>;
  accept(acceptance: Acceptance): Promise<boolean>;
  send(to: string, id: string, envelopes: WireEnvelope[]): Promise<SendOutcome>;
  fetch(): Promise<void>;
  acknowledge(delivery: Delivery): void;
  clear(receipt: Receipt): void;
  onEvent(listener: (event: RelayEvent) => void): () => void;
}

export class ServerRelay implements Relay {
  readonly #client: Client;

  constructor(client: Client) {
    this.#client = client;
  }

  reaches(): boolean {
    return true;
  }

  async roster(identity: string): Promise<WireRoster | null> {
    const reply = await this.#client.request({
      type: "devices",
      payload: { identity },
    });
    return reply?.type === "devices" && reply.payload.identity === identity
      ? reply.payload
      : null;
  }

  async publish(publication: Publication): Promise<number | null> {
    const reply = await this.#client.request({
      type: "prekeys",
      payload: publication,
    });
    return reply?.type === "prekeys" ? reply.payload.available : null;
  }

  async bundle(identity: string): Promise<BundleResult> {
    const reply = await this.#client.request({
      type: "bundle",
      payload: { identity },
    });
    if (reply?.type === "error") {
      return reply.payload.code === "recipient_unavailable"
        ? "unavailable"
        : "failed";
    }
    return reply?.type === "bundle" && reply.payload.identity === identity
      ? { bundles: reply.payload.bundles }
      : "failed";
  }

  async initiate(initiation: Initiation): Promise<InitiateOutcome> {
    const reply = await this.#client.request({
      type: "initiate",
      payload: initiation,
    });
    if (reply?.type === "initiated") {
      return "initiated";
    }
    return reply?.type === "error" &&
      reply.payload.code === "recipient_unavailable"
      ? "unavailable"
      : "failed";
  }

  async accept(acceptance: Acceptance): Promise<boolean> {
    const reply = await this.#client.request({
      type: "accept",
      payload: acceptance,
    });
    return reply?.type === "accepted";
  }

  async send(
    to: string,
    id: string,
    envelopes: WireEnvelope[],
  ): Promise<SendOutcome> {
    const reply = await this.#client.request({
      type: "send",
      payload: { to, id, envelopes },
    });
    if (reply?.type === "queued") {
      return "queued";
    }
    return reply?.type === "error" ? reply.payload.code : null;
  }

  async fetch(): Promise<void> {
    await this.#client.request({ type: "fetch", payload: {} });
  }

  acknowledge(delivery: Delivery): void {
    this.#client.send({
      type: "ack",
      payload: {
        from: delivery.from,
        device: delivery.device,
        id: delivery.id,
      },
    });
  }

  clear(receipt: Receipt): void {
    this.#client.send({
      type: "clear",
      payload: { to: receipt.to, device: receipt.device, id: receipt.id },
    });
  }

  onEvent(listener: (event: RelayEvent) => void): () => void {
    return this.#client.onMessage((message) => {
      if (
        message.type === "initiation" ||
        message.type === "acceptance" ||
        message.type === "message" ||
        message.type === "receipt"
      ) {
        listener(message);
      }
    });
  }
}
