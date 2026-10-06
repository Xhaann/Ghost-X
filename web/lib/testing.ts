import assert from "node:assert/strict";
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, before } from "node:test";
import { fileURLToPath } from "node:url";
import type { KeyValueStore, StoreName } from "./storage.ts";
import type { TransportState } from "./transport.ts";

const NativeWebSocket = globalThis.WebSocket;
export const created: WebSocket[] = [];

class TrackedWebSocket extends NativeWebSocket {
  constructor(url: string | URL, protocols?: string | string[]) {
    super(url, protocols);
    created.push(this);
  }
}

let workdir = "";
let binary = "";
const servers = new Set<ChildProcess>();
const closables = new Set<{ close(): void }>();

export function useServer(): void {
  before(() => {
    globalThis.WebSocket = TrackedWebSocket;
    workdir = mkdtempSync(join(tmpdir(), "ghostx-"));
    binary = join(workdir, "server");
    const serverDir = fileURLToPath(new URL("../../server", import.meta.url));
    execFileSync("go", ["build", "-o", binary, "."], { cwd: serverDir });
  });

  afterEach(async () => {
    for (const item of closables) {
      item.close();
    }
    closables.clear();
    created.length = 0;
    await Promise.all([...servers].map(stopServer));
  });

  after(() => {
    globalThis.WebSocket = NativeWebSocket;
    rmSync(workdir, { recursive: true, force: true });
  });
}

export function track<T extends { close(): void }>(item: T): T {
  closables.add(item);
  return item;
}

export function record(target: {
  onState(listener: (state: TransportState) => void): () => void;
}): TransportState[] {
  const states: TransportState[] = [];
  target.onState((state) => states.push(state));
  return states;
}

export async function freePort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  server.close();
  await once(server, "close");
  assert.ok(address && typeof address === "object");
  return address.port;
}

export async function startServer(port: number): Promise<ChildProcess> {
  const server = spawn(binary, [], {
    env: { ...process.env, SERVER_ADDR: `127.0.0.1:${port}` },
    stdio: "ignore",
  });
  servers.add(server);
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/healthz`);
      if (response.status === 204) {
        return server;
      }
    } catch {}
    await sleep(20);
  }
  throw new Error("server did not start");
}

export async function stopServer(server: ChildProcess): Promise<void> {
  servers.delete(server);
  if (server.exitCode !== null || server.signalCode !== null) {
    return;
  }
  const exited = once(server, "exit");
  server.kill("SIGTERM");
  await exited;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitFor(
  target: { readonly state: TransportState },
  state: TransportState,
): Promise<void> {
  const deadline = Date.now() + 5000;
  while (target.state !== state) {
    if (Date.now() > deadline) {
      throw new Error(
        `timed out waiting for ${state}, state is ${target.state}`,
      );
    }
    await sleep(10);
  }
}

export async function waitForCount(
  items: readonly unknown[],
  count: number,
): Promise<void> {
  const deadline = Date.now() + 5000;
  while (items.length < count) {
    if (Date.now() > deadline) {
      throw new Error(`received ${items.length} of ${count}`);
    }
    await sleep(5);
  }
}

export function openSockets(): WebSocket[] {
  return created.filter(
    (ws) =>
      ws.readyState === NativeWebSocket.CONNECTING ||
      ws.readyState === NativeWebSocket.OPEN,
  );
}

export function pingFrame(id: string, sentAt: number): string {
  return JSON.stringify({ type: "ping", id, payload: { sentAt } });
}

export function memoryStore(): KeyValueStore & {
  data: Map<string, unknown>;
  writes: number;
} {
  const data = new Map<string, unknown>();
  const key = (store: StoreName, name: string) => `${store}:${name}`;
  const store = {
    data,
    writes: 0,
    async get(name: StoreName, k: string) {
      await Promise.resolve();
      const value = data.get(key(name, k));
      return value === undefined ? undefined : structuredClone(value);
    },
    async getAll(name: StoreName) {
      await Promise.resolve();
      return [...data.entries()]
        .filter(([k]) => k.startsWith(`${name}:`))
        .map(([k, value]) => ({
          key: k.slice(name.length + 1),
          value: structuredClone(value),
        }));
    },
    async put(name: StoreName, k: string, value: unknown) {
      await Promise.resolve();
      store.writes += 1;
      data.set(key(name, k), structuredClone(value));
    },
    async add(name: StoreName, k: string, value: unknown) {
      await Promise.resolve();
      if (data.has(key(name, k))) {
        return false;
      }
      store.writes += 1;
      data.set(key(name, k), structuredClone(value));
      return true;
    },
    async delete(name: StoreName, keys: readonly string[]) {
      await Promise.resolve();
      keys.forEach((k) => data.delete(key(name, k)));
    },
    async clear() {
      await Promise.resolve();
      data.clear();
    },
    close() {},
  };
  return store;
}
