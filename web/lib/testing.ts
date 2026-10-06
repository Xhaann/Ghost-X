import assert from "node:assert/strict";
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, afterEach, before } from "node:test";
import { fileURLToPath } from "node:url";
import { encodeBase64Url } from "./base64.ts";
import {
  type KeyBundle,
  type Parties,
  associatedData as legacyAssociatedData,
  keyBindingMessage,
} from "./encryption.ts";
import { IdentityKey, parseIdentity } from "./identity.ts";
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
    async swap(
      name: StoreName,
      k: string,
      matches: (current: unknown) => boolean,
      value: unknown,
    ) {
      await Promise.resolve();
      const current = data.get(key(name, k));
      if (
        !matches(current === undefined ? undefined : structuredClone(current))
      ) {
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

export type LegacyParty = {
  identity: IdentityKey;
  publicRaw: Uint8Array<ArrayBuffer>;
  privateKey: CryptoKey;
  bundle: KeyBundle;
};

export async function legacyParty(): Promise<LegacyParty> {
  const identity = await IdentityKey.generate();
  const pair = (await crypto.subtle.generateKey({ name: "X25519" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  const signature = await identity.sign(
    keyBindingMessage(identity.identity, publicRaw),
  );
  assert.ok(signature);
  return {
    identity,
    publicRaw,
    privateKey: pair.privateKey,
    bundle: {
      identity: identity.identity,
      key: encodeBase64Url(publicRaw),
      signature,
    },
  };
}

export async function legacySeal(
  parties: Parties,
  privateKey: CryptoKey,
  peer: Uint8Array<ArrayBuffer>,
  body: string,
): Promise<{ salt: string; iv: string; ciphertext: string }> {
  const from = parseIdentity(parties.from);
  const to = parseIdentity(parties.to);
  const additionalData = legacyAssociatedData(parties);
  assert.ok(from && to && additionalData);
  const context = new TextEncoder().encode("ghostx/message/v1\0");
  const info = new Uint8Array([
    ...context,
    ...from,
    ...to,
    ...parties.fromKey,
    ...parties.toKey,
  ]);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const peerKey = await crypto.subtle.importKey(
    "raw",
    peer,
    { name: "X25519" },
    false,
    [],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: "X25519", public: peerKey },
    privateKey,
    256,
  );
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData },
    key,
    new TextEncoder().encode(body),
  );
  return {
    salt: encodeBase64Url(salt),
    iv: encodeBase64Url(iv),
    ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
  };
}
