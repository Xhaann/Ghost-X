"use client";

import type { Client } from "@/lib/client.ts";
import { useIdentity } from "@/lib/useIdentity.ts";
import { useProof } from "@/lib/useProof.ts";

export default function Identity({
  client,
  connected,
}: {
  client: Client | null;
  connected: boolean;
}) {
  const key = useIdentity();
  const { prove, proven, pending } = useProof(client, key);

  return (
    <section>
      <p>
        Identity <code>{key ? key.identity : "Generating"}</code>
      </p>
      <button
        type="button"
        onClick={prove}
        disabled={!key || !connected || pending}
      >
        Verify identity
      </button>
      {proven !== null && (
        <output>{proven ? "Identity verified" : "Verification failed"}</output>
      )}
    </section>
  );
}
