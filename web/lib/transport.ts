export type TransportState =
  "disconnected" | "connecting" | "connected" | "reconnecting";

export type TransportError = "unavailable" | "lost";

export interface Transport {
  readonly state: TransportState;
  open(): void;
  close(): void;
  retry?(): void;
  send(data: string): boolean;
  onState(listener: (state: TransportState) => void): () => void;
  onData(listener: (data: string) => void): () => void;
  onError(listener: (error: TransportError) => void): () => void;
}
