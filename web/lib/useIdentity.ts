import { useCallback, useEffect, useRef, useState } from "react";
import { Devices } from "./devices.ts";
import { History } from "./history.ts";
import { Outbox } from "./outbox.ts";
import { Pairs } from "./pairs.ts";
import { PrekeyStore } from "./prekeys.ts";
import { openIndexedStore } from "./storage.ts";
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
  | { status: "unavailable" }
  | { status: "corrupted" }
  | { status: "empty" }
  | ({ status: "ready" } & LocalSession);

type Setup = { kind: "create" } | { kind: "link"; identity: string } | null;

export function useIdentity(): {
  local: LocalState;
  reset: () => void;
  create: () => void;
  link: (identity: string) => void;
} {
  const [local, setLocal] = useState<LocalState>({ status: "loading" });
  const [epoch, setEpoch] = useState(0);
  const resetting = useRef(false);
  const setup = useRef<Setup>(null);
  const settled = useRef<Promise<void>>(Promise.resolve());

  useEffect(() => {
    let active = true;
    let ready: LocalSession | null = null;
    let close: () => void = () => {};
    const previous = settled.current;

    const task = (async () => {
      await previous;
      if (!active) {
        return;
      }
      const store = await openIndexedStore();
      close = () => store.close();
      if (resetting.current) {
        resetting.current = false;
        await store.clear();
      }
      if (!active) {
        close();
        return;
      }
      let vault: VaultState = await loadVault(store);
      const requested = setup.current;
      setup.current = null;
      if (vault.status === "empty" && requested) {
        vault =
          requested.kind === "create"
            ? await createVault(store)
            : await linkVault(store, requested.identity);
      }
      if (vault.status !== "ready") {
        if (active) {
          setLocal(vault);
        }
        return;
      }
      const [history, trust, prekeys, pairs, devices, outbox] =
        await Promise.all([
          History.open(store, vault.keys, vault.integrity, vault.storage),
          Trust.open(store, vault.integrity),
          PrekeyStore.open(store, vault.keys, vault.integrity),
          Pairs.open(
            store,
            vault.integrity,
            vault.storage,
            vault.keys.identity,
          ),
          Devices.open(store, vault.keys),
          Outbox.open(store, vault.storage),
        ]);
      if (!devices) {
        if (active) {
          setLocal({ status: "corrupted" });
        }
        return;
      }
      const session = {
        keys: vault.keys,
        devices,
        history,
        trust,
        prekeys,
        pairs,
        outbox,
        created: vault.created,
      };
      if (active) {
        ready = session;
        setLocal({ status: "ready", ...session });
        return;
      }
      await Promise.all([history.close(), trust.close(), pairs.close()]);
      vault.keys.root?.release();
      vault.keys.device.release();
      vault.keys.exchange.release();
      close();
    })().catch(() => {
      if (active) {
        setLocal({ status: "unavailable" });
      }
    });
    settled.current = task;

    return () => {
      active = false;
      const session = ready;
      settled.current = task.then(async () => {
        if (session) {
          await Promise.all([
            session.history.close(),
            session.trust.close(),
            session.pairs.close(),
          ]);
          session.keys.root?.release();
          session.keys.device.release();
          session.keys.exchange.release();
        }
        close();
      });
      setLocal({ status: "loading" });
    };
  }, [epoch]);

  const reset = useCallback(() => {
    resetting.current = true;
    setEpoch((value) => value + 1);
  }, []);

  const create = useCallback(() => {
    setup.current = { kind: "create" };
    setEpoch((value) => value + 1);
  }, []);

  const link = useCallback((identity: string) => {
    setup.current = { kind: "link", identity };
    setEpoch((value) => value + 1);
  }, []);

  return { local, reset, create, link };
}
