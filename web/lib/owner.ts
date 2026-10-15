import { Devices } from "./devices.ts";
import { History } from "./history.ts";
import { Outbox } from "./outbox.ts";
import { Pairs } from "./pairs.ts";
import { PrekeyStore } from "./prekeys.ts";
import type { KeyValueStore } from "./storage.ts";
import { Trust } from "./trust.ts";
import {
  type Keys,
  type VaultState,
  createVault,
  linkVault,
  loadVault,
} from "./vault.ts";

export type LocalSession = {
  keys: Keys;
  devices: Devices;
  history: History;
  trust: Trust;
  prekeys: PrekeyStore | null;
  pairs: Pairs;
  outbox: Outbox;
  created: boolean;
};

export type LocalState =
  | { status: "loading" }
  | { status: "waiting" }
  | { status: "unsupported" }
  | { status: "unavailable" }
  | { status: "corrupted" }
  | { status: "empty" }
  | ({ status: "ready" } & LocalSession);

export type Setup =
  { kind: "create" } | { kind: "link"; identity: string } | null;

export type LoadedDevice = {
  local: Exclude<LocalState, { status: "loading" | "waiting" | "unsupported" }>;
  close: () => Promise<void>;
};

function release(keys: Keys): void {
  keys.root?.release();
  keys.device.release();
  keys.exchange.release();
}

export async function closeLocal(session: LocalSession): Promise<void> {
  await Promise.all([
    session.history.close(),
    session.trust.close(),
    session.pairs.close(),
  ]);
  release(session.keys);
}

export async function loadDevice(
  store: KeyValueStore,
  options: { setup?: Setup; reset?: boolean } = {},
): Promise<LoadedDevice> {
  const closeStore = async () => store.close();
  try {
    if (options.reset) {
      await store.clear();
    }
    let vault: VaultState = await loadVault(store);
    const setup = options.setup ?? null;
    if (vault.status === "empty" && setup) {
      vault =
        setup.kind === "create"
          ? await createVault(store)
          : await linkVault(store, setup.identity);
    }
    if (vault.status !== "ready") {
      return { local: vault, close: closeStore };
    }
    const [history, trust, prekeys, pairs, devices, outbox] =
      await Promise.allSettled([
        History.open(store, vault.keys, vault.integrity, vault.storage),
        Trust.open(store, vault.integrity),
        PrekeyStore.open(store, vault.keys, vault.integrity),
        Pairs.open(store, vault.integrity, vault.storage, vault.keys.identity),
        Devices.open(store, vault.keys),
        Outbox.open(store, vault.storage),
      ]);
    if (
      history.status === "rejected" ||
      trust.status === "rejected" ||
      prekeys.status === "rejected" ||
      pairs.status === "rejected" ||
      devices.status === "rejected" ||
      outbox.status === "rejected"
    ) {
      await Promise.allSettled(
        [history, trust, pairs].map((opened) =>
          opened.status === "fulfilled" ? opened.value.close() : undefined,
        ),
      );
      release(vault.keys);
      throw new Error("local stores could not be opened");
    }
    const session = {
      keys: vault.keys,
      devices: devices.value as Devices,
      history: history.value,
      trust: trust.value,
      prekeys: prekeys.value,
      pairs: pairs.value,
      outbox: outbox.value,
      created: vault.created,
    };
    if (!devices.value) {
      await closeLocal(session);
      return { local: { status: "corrupted" }, close: closeStore };
    }
    return {
      local: { status: "ready", ...session },
      close: async () => {
        await closeLocal(session);
        await closeStore();
      },
    };
  } catch {
    await closeStore();
    return { local: { status: "unavailable" }, close: async () => {} };
  }
}
