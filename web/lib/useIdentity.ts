import { useCallback, useEffect, useRef, useState } from "react";
import { requestDeviceLock } from "./lock.ts";
import {
  type LoadedDevice,
  type LocalState,
  type Setup,
  loadDevice,
} from "./owner.ts";
import { openIndexedStore } from "./storage.ts";

export type { LocalSession, LocalState } from "./owner.ts";

type Ownership = "requesting" | "waiting" | "owned" | "unsupported";

export function useIdentity(): {
  local: LocalState;
  reset: () => void;
  create: () => void;
  link: (identity: string) => void;
} {
  const [ownership, setOwnership] = useState<Ownership>("requesting");
  const [local, setLocal] = useState<LocalState>({ status: "loading" });
  const [failed, setFailed] = useState(false);
  const [epoch, setEpoch] = useState(0);
  const resetting = useRef(false);
  const setup = useRef<Setup>(null);
  const settled = useRef<Promise<void>>(Promise.resolve());

  useEffect(() => {
    if (failed) {
      return;
    }
    const controller = new AbortController();
    let active = true;
    const lock = requestDeviceLock(controller.signal, () => {
      if (active) {
        setOwnership("waiting");
      }
    }).then(
      (release) => {
        if (active) {
          setOwnership("owned");
        }
        return release;
      },
      () => {
        if (active) {
          setOwnership("unsupported");
        }
        return null;
      },
    );
    return () => {
      active = false;
      controller.abort();
      setOwnership("requesting");
      void Promise.resolve()
        .then(() => settled.current)
        .then(() => lock)
        .then((release) => release?.());
    };
  }, [failed]);

  const owned = ownership === "owned";

  useEffect(() => {
    if (!owned) {
      return;
    }
    let active = true;
    const previous = settled.current;
    const task = (async (): Promise<LoadedDevice | null> => {
      await previous;
      if (!active) {
        return null;
      }
      const store = await openIndexedStore();
      const reset = resetting.current;
      resetting.current = false;
      const requested = setup.current;
      setup.current = null;
      const loaded = await loadDevice(store, { setup: requested, reset });
      if (active) {
        setLocal(loaded.local);
        if (loaded.local.status === "unavailable") {
          setFailed(true);
        }
      }
      return loaded;
    })().catch((): null => {
      if (active) {
        setFailed(true);
      }
      return null;
    });
    settled.current = task.then(() => {});

    return () => {
      active = false;
      settled.current = task.then((loaded) => loaded?.close());
      setLocal({ status: "loading" });
    };
  }, [owned, epoch]);

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

  const state: LocalState = failed
    ? { status: "unavailable" }
    : ownership === "waiting"
      ? { status: "waiting" }
      : ownership === "unsupported"
        ? { status: "unsupported" }
        : local;
  return { local: state, reset, create, link };
}
