import { useEffect, useState } from "react";
import { IdentityKey } from "./identity.ts";

export function useIdentity(): IdentityKey | null {
  const [key, setKey] = useState<IdentityKey | null>(null);

  useEffect(() => {
    let active = true;
    let generated: IdentityKey | null = null;

    IdentityKey.generate().then(
      (key) => {
        generated = key;
        if (active) {
          setKey(key);
        } else {
          key.release();
        }
      },
      () => {
        if (active) {
          setKey(null);
        }
      },
    );

    return () => {
      active = false;
      generated?.release();
      setKey(null);
    };
  }, []);

  return key;
}
