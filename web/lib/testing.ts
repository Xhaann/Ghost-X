import assert from "node:assert/strict";
import { type ChildProcess, execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { type Socket, createConnection, createServer } from "node:net";
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
import type { Transport, TransportKind, TransportState } from "./transport.ts";
import { Authenticator } from "./auth.ts";
import { Client } from "./client.ts";
import {
  type Link,
  type LinkConnection,
  type LinkHandlers,
  LocalTransport,
} from "./local.ts";
import { History } from "./history.ts";
import {
  Messenger,
  type MessengerState,
  type Receipt,
  type Receiver,
} from "./messenger.ts";
import { Outbox } from "./outbox.ts";
import { Pairing } from "./pairing.ts";
import { Pairs } from "./pairs.ts";
import { PeerEndpoint } from "./peer.ts";
import { PrekeyStore } from "./prekeys.ts";
import { WebSocketTransport } from "./socket.ts";
import { Trust } from "./trust.ts";
import { Devices } from "./devices.ts";
import { ServerRelay } from "./relay.ts";
import { Rosters } from "./rosters.ts";
import { type Unlocked, createVault, linkVault, loadVault } from "./vault.ts";

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
    env: {
      ...process.env,
      SERVER_ADDR: `127.0.0.1:${port}`,
      DEVICE_STORE: join(workdir, `devices-${port}.json`),
      LOCAL_SOCKET: localSocket(port),
    },
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

export function localSocket(port: number): string {
  return join(workdir, `l${port}.sock`);
}

export type Wire = { out: Buffer[]; in: Buffer[] };

export function wireFrames(chunks: Buffer[]): string[] {
  let buffered = Buffer.concat(chunks);
  const out: string[] = [];
  while (buffered.length >= 4) {
    const size = buffered.readUInt32BE(0);
    assert.ok(size > 0 && size <= 32 * 1024, "length prefix within limits");
    assert.ok(buffered.length >= 4 + size, "complete frame");
    out.push(buffered.subarray(4, 4 + size).toString("utf8"));
    buffered = buffered.subarray(4 + size);
  }
  assert.equal(buffered.length, 0);
  return out;
}

function framed(
  socket: Socket,
  handlers: LinkHandlers,
  wire: Wire | null,
): LinkConnection {
  let buffered = Buffer.alloc(0);
  socket.on("data", (chunk) => {
    wire?.in.push(Buffer.from(chunk));
    buffered = Buffer.concat([buffered, chunk]);
    while (buffered.length >= 4) {
      const size = buffered.readUInt32BE(0);
      if (buffered.length < 4 + size) {
        break;
      }
      handlers.frame(buffered.subarray(4, 4 + size).toString("utf8"));
      buffered = buffered.subarray(4 + size);
    }
  });
  socket.on("error", () => {});
  socket.on("close", () => handlers.closed());
  return {
    send(frame) {
      if (socket.writableNeedDrain || socket.destroyed) {
        return false;
      }
      const body = Buffer.from(frame, "utf8");
      const header = Buffer.alloc(4);
      header.writeUInt32BE(body.length);
      const bytes = Buffer.concat([header, body]);
      wire?.out.push(bytes);
      socket.write(bytes);
      return true;
    },
    close() {
      socket.destroy();
    },
  };
}

function dialer(path: string, wire: Wire | null): Link {
  return {
    connect: (handlers) =>
      new Promise((resolve, reject) => {
        const socket = createConnection(path);
        const refused = (error: Error) => reject(error);
        socket.once("error", refused);
        socket.once("connect", () => {
          socket.off("error", refused);
          resolve(framed(socket, handlers, wire));
        });
      }),
  };
}

export function unixLink(path: string): Link {
  return dialer(path, null);
}

export type PeerCarrier = {
  listen: Link;
  dial: Link;
  wire: Wire;
  drop(): void;
  close(): void;
};

export async function peerCarrier(): Promise<PeerCarrier> {
  const dir = mkdtempSync(join(tmpdir(), "ghostx-peer-"));
  const path = join(dir, "peer.sock");
  const accepted: Socket[] = [];
  const waiting: ((socket: Socket) => void)[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    const take = waiting.shift();
    if (take) {
      take(socket);
    } else {
      accepted.push(socket);
    }
  });
  server.listen(path);
  await once(server, "listening");
  const wire: Wire = { out: [], in: [] };
  const drop = () => {
    for (const socket of sockets) {
      socket.destroy();
    }
    accepted.length = 0;
  };
  return track<PeerCarrier>({
    listen: {
      connect: (handlers) =>
        new Promise((resolve) => {
          const take = (socket: Socket) =>
            resolve(framed(socket, handlers, null));
          const socket = accepted.shift();
          if (socket) {
            take(socket);
          } else {
            waiting.push(take);
          }
        }),
    },
    dial: dialer(path, wire),
    wire,
    drop,
    close: () => {
      drop();
      waiting.length = 0;
      server.close();
      rmSync(dir, { recursive: true, force: true });
    },
  });
}

export function useCleanup(): void {
  afterEach(() => {
    for (const item of closables) {
      item.close();
    }
    closables.clear();
  });
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

export type MemoryStore = ReturnType<typeof memoryStore>;

export type Inbound = { id: string; from: string; body: string | null };

export function memoryReceiver() {
  const inbox: Inbound[] = [];
  const receipts: Receipt[] = [];
  const stored = new Set<string>();
  let failing = false;
  const receiver: Receiver = {
    has: (from, id) => stored.has(`${from}/${id}`),
    accept: async ({ from, id, body }) => {
      await Promise.resolve();
      if (failing) {
        return false;
      }
      if (!stored.has(`${from}/${id}`)) {
        stored.add(`${from}/${id}`);
        inbox.push({ id, from, body });
      }
      return true;
    },
    reject: ({ from, id }) => {
      inbox.push({ id, from, body: null });
    },
    settle: async (receipt) => {
      await Promise.resolve();
      if (failing) {
        return false;
      }
      receipts.push(receipt);
      return true;
    },
  };
  return {
    receiver,
    inbox,
    receipts,
    fail: (value: boolean) => {
      failing = value;
    },
  };
}

export async function secureDevice(
  port: number,
  options: {
    store?: MemoryStore;
    wait?: boolean;
    drop?: string[];
    inbox?: boolean;
    link?: string;
    now?: () => number;
    transport?: TransportKind;
  } = {},
) {
  const store = options.store ?? memoryStore();
  const {
    vault,
    keys,
    integrity,
    storage,
    prekeys,
    pairs,
    trust,
    history,
    devices,
    outbox,
  } = await openDevice(store, options.link);
  const transport: Transport = track(
    options.transport === "local"
      ? new LocalTransport(unixLink(localSocket(port)))
      : new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
  );
  const sent: string[] = [];
  const received: string[] = [];
  const frames: string[] = [];
  const listeners: ((data: string) => void)[] = [];
  const dropped = new Set<string>(options.drop ?? []);
  const delayed = new Set<string>();
  const buffered: string[] = [];
  const typeOf = (data: string) => {
    try {
      return (JSON.parse(data) as { type?: unknown }).type;
    } catch {
      return null;
    }
  };
  const transmit = transport.send.bind(transport);
  transport.send = (data: string) => {
    sent.push(data);
    frames.push(data);
    return transmit(data);
  };
  transport.onData((data) => {
    received.push(data);
    frames.push(data);
  });
  const onData = transport.onData.bind(transport);
  transport.onData = (listener: (data: string) => void) => {
    listeners.push(listener);
    return onData((data) => {
      const type = typeOf(data);
      if (typeof type === "string" && dropped.has(type)) {
        return;
      }
      if (typeof type === "string" && delayed.has(type)) {
        if (listener === listeners[0]) {
          buffered.push(data);
        }
        return;
      }
      listener(data);
    });
  };
  const client = track(new Client(transport));
  const auth = new Authenticator(client, keys, devices);
  const relay = new ServerRelay(client);
  const rosters = new Rosters(relay, trust);
  const pairing = new Pairing(relay, keys, rosters, prekeys, pairs);
  const messenger = new Messenger(
    relay,
    auth,
    keys.identity,
    pairing,
    rosters,
    outbox,
    options.now,
  );
  const sink = memoryReceiver();
  const states: MessengerState[] = [];
  if (options.inbox !== false) {
    messenger.receive(sink.receiver);
  }
  messenger.onState((state) => states.push(state));
  let stopped = false;
  const shutdown = async () => {
    if (stopped) {
      return;
    }
    stopped = true;
    pairing.stop();
    messenger.stop();
    auth.stop();
    client.close();
    await Promise.all([pairs.close(), trust.close(), history.close()]);
  };
  track({ close: () => void shutdown() });
  auth.start();
  messenger.start();
  pairing.start(messenger);
  client.open();
  await waitFor(client, "connected");
  if (options.wait !== false) {
    const deadline = Date.now() + 5000;
    while (!(messenger.state.active && pairing.published)) {
      assert.ok(Date.now() < deadline, "device never became ready");
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }
  return {
    id: keys.identity,
    deviceId: keys.deviceId,
    created: vault.created,
    devices,
    rosters,
    store,
    keys,
    integrity,
    storage,
    prekeys,
    pairs,
    outbox,
    trust,
    history,
    client,
    auth,
    pairing,
    messenger,
    inbox: sink.inbox,
    receipts: sink.receipts,
    failStorage: sink.fail,
    states,
    sent,
    received,
    frames,
    deliver: (data: string) => listeners.forEach((listener) => listener(data)),
    hold: (value: boolean) => {
      if (value) {
        dropped.add("message");
      } else {
        dropped.delete("message");
      }
    },
    drop: (types: string[]) => {
      dropped.clear();
      types.forEach((type) => dropped.add(type));
    },
    delay: (types: string[]) => {
      types.forEach((type) => delayed.add(type));
    },
    release: () => {
      delayed.clear();
      const pending = buffered.splice(0);
      pending.forEach((data) =>
        listeners.forEach((listener) => listener(data)),
      );
    },
    shutdown,
  };
}

export type SecureDevice = Awaited<ReturnType<typeof secureDevice>>;

async function openDevice(store: MemoryStore, link?: string) {
  let vault = await loadVault(store);
  if (vault.status === "empty") {
    vault = link ? await linkVault(store, link) : await createVault(store);
  }
  assert.equal(vault.status, "ready");
  const { keys, integrity, storage } = vault as Unlocked;
  const prekeys = await PrekeyStore.open(store, keys, integrity);
  assert.ok(prekeys);
  const [pairs, trust, history, devices, outbox] = await Promise.all([
    Pairs.open(store, integrity, storage, keys.identity),
    Trust.open(store, integrity),
    History.open(store, keys, integrity, storage),
    Devices.open(store, keys),
    Outbox.open(store, storage),
  ]);
  assert.ok(devices);
  return {
    vault: vault as Unlocked,
    keys,
    integrity,
    storage,
    prekeys,
    pairs,
    trust,
    history,
    devices,
    outbox,
  };
}

export async function peerDevice(
  link: Link | null,
  options: {
    store?: MemoryStore;
    root?: string;
    now?: () => number;
    timeout?: number;
    requestTimeout?: number;
    frames?: number;
    open?: boolean;
  } = {},
) {
  const store = options.store ?? memoryStore();
  const material = await openDevice(store, options.root);
  const { keys, prekeys, pairs, trust, history, devices, outbox } = material;
  const transport = track(new LocalTransport(link, { timeout: 2000 }));
  const endpoint = new PeerEndpoint(transport, {
    keys,
    devices,
    trust,
    prekeys,
    timeout: options.timeout,
    requestTimeout: options.requestTimeout,
    frames: options.frames,
  });
  const rosters = new Rosters(endpoint, trust);
  const pairing = new Pairing(endpoint, keys, rosters, prekeys, pairs);
  const messenger = new Messenger(
    endpoint,
    endpoint,
    keys.identity,
    pairing,
    rosters,
    outbox,
    options.now,
  );
  const sink = memoryReceiver();
  messenger.receive(sink.receiver);
  let stopped = false;
  const shutdown = async () => {
    if (stopped) {
      return;
    }
    stopped = true;
    pairing.stop();
    messenger.stop();
    endpoint.close();
    await Promise.all([pairs.close(), trust.close(), history.close()]);
  };
  track({ close: () => void shutdown() });
  messenger.start();
  pairing.start(messenger);
  if (options.open !== false) {
    endpoint.open();
  }
  return {
    ...material,
    id: keys.identity,
    deviceId: keys.deviceId,
    store,
    transport,
    endpoint,
    rosters,
    pairing,
    messenger,
    inbox: sink.inbox,
    receipts: sink.receipts,
    failStorage: sink.fail,
    shutdown,
  };
}

export type PeerDevice = Awaited<ReturnType<typeof peerDevice>>;

export async function linkedDevice(
  port: number,
  root: SecureDevice,
  options: {
    store?: MemoryStore;
    inbox?: boolean;
    transport?: TransportKind;
  } = {},
): Promise<SecureDevice> {
  const device = await secureDevice(port, {
    ...options,
    link: root.id,
    wait: false,
  });
  const deadline = Date.now() + 5000;
  while (device.auth.state !== "pending") {
    assert.ok(Date.now() < deadline, "linking device never became pending");
    await sleep(5);
  }
  const request = await device.devices.linkRequest();
  assert.ok(request);
  const result = await root.devices.authorize(root.client, request);
  assert.ok(result.ok, JSON.stringify(result));
  while (!(device.messenger.state.active && device.pairing.published)) {
    assert.ok(Date.now() < deadline + 5000, "linked device never became ready");
    await sleep(5);
  }
  return device;
}
