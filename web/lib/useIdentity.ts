import { useCallback, useEffect, useRef, useState } from "react";
import { History } from "./history.ts";
import { openIndexedStore } from "./storage.ts";
import { Trust } from "./trust.ts";
import { type Keys, loadVault } from "./vault.ts";

export type LocalSession = {
  keys: Keys;
  history: History;
  trust: Trust;
  created: boolean;
};

export type LocalState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "corrupted" }
  | ({ status: "ready" } & LocalSession);

export function useIdentity(): { local: LocalState; reset: () => void } {
  const [local, setLocal] = useState<LocalState>({ status: "loading" });
  const [epoch, setEpoch] = useState(0);
  const resetting = useRef(false);
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
      const vault = await loadVault(store);
      if (vault.status === "corrupted") {
        if (active) {
          setLocal(vault);
        }
        return;
      }
      const [history, trust] = await Promise.all([
        History.open(store, vault.keys, vault.integrity, vault.storage),
        Trust.open(store, vault.integrity),
      ]);
      const session = {
        keys: vault.keys,
        history,
        trust,
        created: vault.created,
      };
      if (active) {
        ready = session;
        setLocal({ status: "ready", ...session });
        return;
      }
      await Promise.all([history.close(), trust.close()]);
      vault.keys.identity.release();
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
          await Promise.all([session.history.close(), session.trust.close()]);
          session.keys.identity.release();
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

  return { local, reset };
}
