"use client";

import type { AuthState } from "@/lib/auth.ts";
import type { Client } from "@/lib/client.ts";
import { useAuth } from "@/lib/useAuth.ts";
import { useIdentity } from "@/lib/useIdentity.ts";

const labels: Record<AuthState, string> = {
  unauthenticated: "Unauthenticated",
  authenticating: "Authenticating",
  authenticated: "Authenticated",
  failed: "Authentication failed",
};

export default function Identity({ client }: { client: Client | null }) {
  const key = useIdentity();
  const state = useAuth(client, key);

  return (
    <section>
      <p>
        Identity <code>{key ? key.identity : "Generating"}</code>
      </p>
      <p data-auth={state}>{labels[state]}</p>
    </section>
  );
}
