export type StoreName = "vault" | "messages" | "trust" | "pairs" | "outbox";

export type Entry = { key: string; value: unknown };

export interface KeyValueStore {
  get(store: StoreName, key: string): Promise<unknown>;
  getAll(store: StoreName): Promise<Entry[]>;
  put(store: StoreName, key: string, value: unknown): Promise<void>;
  add(store: StoreName, key: string, value: unknown): Promise<boolean>;
  swap(
    store: StoreName,
    key: string,
    matches: (current: unknown) => boolean,
    value: unknown,
  ): Promise<boolean>;
  delete(store: StoreName, keys: readonly string[]): Promise<void>;
  clear(): Promise<void>;
  close(): void;
}

const databaseName = "ghostx";
const databaseVersion = 4;
const stores: readonly StoreName[] = [
  "vault",
  "messages",
  "trust",
  "pairs",
  "outbox",
];

function done(request: IDBRequest): Promise<unknown> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function committed(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}

export function openIndexedStore(): Promise<KeyValueStore> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("unavailable"));
      return;
    }
    const request = indexedDB.open(databaseName, databaseVersion);
    request.onupgradeneeded = () => {
      for (const name of stores) {
        if (!request.result.objectStoreNames.contains(name)) {
          request.result.createObjectStore(name);
        }
      }
    };
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("blocked"));
    request.onsuccess = () => {
      request.result.onversionchange = () => request.result.close();
      resolve(indexedStore(request.result));
    };
  });
}

function indexedStore(db: IDBDatabase): KeyValueStore {
  const transaction = (names: StoreName[], mode: IDBTransactionMode) =>
    db.transaction(names, mode);

  return {
    async get(store, key) {
      return done(transaction([store], "readonly").objectStore(store).get(key));
    },
    async getAll(store) {
      const objects = transaction([store], "readonly").objectStore(store);
      const [keys, values] = (await Promise.all([
        done(objects.getAllKeys()),
        done(objects.getAll()),
      ])) as [IDBValidKey[], unknown[]];
      return keys.map((key, i) => ({ key: String(key), value: values[i] }));
    },
    async put(store, key, value) {
      const tx = transaction([store], "readwrite");
      tx.objectStore(store).put(value, key);
      await committed(tx);
    },
    async add(store, key, value) {
      const tx = transaction([store], "readwrite");
      const request = tx.objectStore(store).add(value, key);
      request.onerror = (event) => event.preventDefault();
      try {
        await committed(tx);
        return true;
      } catch {
        return false;
      }
    },
    async swap(store, key, matches, value) {
      const tx = transaction([store], "readwrite");
      const objects = tx.objectStore(store);
      let swapped = false;
      const request = objects.get(key);
      request.onsuccess = () => {
        if (matches(request.result)) {
          objects.put(value, key);
          swapped = true;
        }
      };
      await committed(tx);
      return swapped;
    },
    async delete(store, keys) {
      const tx = transaction([store], "readwrite");
      const objects = tx.objectStore(store);
      for (const key of keys) {
        objects.delete(key);
      }
      await committed(tx);
    },
    async clear() {
      const tx = transaction([...stores], "readwrite");
      for (const name of stores) {
        tx.objectStore(name).clear();
      }
      await committed(tx);
    },
    close() {
      db.close();
    },
  };
}
