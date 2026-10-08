export type TransportKind = "websocket" | "local";

export type TransportState =
  "disconnected" | "connecting" | "connected" | "reconnecting" | "error";

export type TransportError =
  "unavailable" | "failed" | "lost" | "timeout" | "oversized" | "malformed";

export type SendResult =
  "sent" | "not_connected" | "oversized" | "busy" | "failed";

export const maxFrameSize = 32 * 1024;
export const maxBufferedBytes = 1024 * 1024;

const encoder = new TextEncoder();

export function isFrameSize(frame: string): boolean {
  return (
    frame.length > 0 &&
    (frame.length * 3 <= maxFrameSize ||
      encoder.encode(frame).length <= maxFrameSize)
  );
}

export interface Transport {
  readonly kind: TransportKind;
  readonly state: TransportState;
  open(): void;
  close(): void;
  retry?(): void;
  send(frame: string): SendResult;
  onState(listener: (state: TransportState) => void): () => void;
  onData(listener: (frame: string) => void): () => void;
  onError(listener: (error: TransportError) => void): () => void;
}
