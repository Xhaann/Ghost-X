import { useEffect, useState } from "react";
import { ExchangeKey } from "./encryption.ts";
import { IdentityKey } from "./identity.ts";

export type Keys = { identity: IdentityKey; exchange: ExchangeKey };

export function useIdentity(): Keys | null {
  const [keys, setKeys] = useState<Keys | null>(null);

  useEffect(() => {
    let active = true;
    let generated: Keys | null = null;

    Promise.all([IdentityKey.generate(), ExchangeKey.generate()]).then(
      ([identity, exchange]) => {
        generated = { identity, exchange };
        if (active) {
          setKeys(generated);
        } else {
          identity.release();
          exchange.release();
        }
      },
      () => {
        if (active) {
          setKeys(null);
        }
      },
    );

    return () => {
      active = false;
      generated?.identity.release();
      generated?.exchange.release();
      setKeys(null);
    };
  }, []);

  return keys;
}
