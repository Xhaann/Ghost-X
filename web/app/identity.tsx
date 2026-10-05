"use client";

import type { AuthState } from "@/lib/auth.ts";
import type { Client } from "@/lib/client.ts";
import { useAuth } from "@/lib/useAuth.ts";
import { useIdentity } from "@/lib/useIdentity.ts";
import { useWhoami } from "@/lib/useWhoami.ts";

const labels: Record<AuthState, string> = {
  unauthenticated: "Unauthenticated",
  authenticating: "Authenticating",
  authenticated: "Authenticated",
  failed: "Authentication failed",
};

export default function Identity({ client }: { client: Client | null }) {
  const key = useIdentity();
  const state = useAuth(client, key);
  const { query, result } = useWhoami(client, state);

  return (
    <section>
      <p>
        Identity <code>{key ? key.identity : "Generating"}</code>
      </p>
      <p data-auth={state}>{labels[state]}</p>
      <button
        type="button"
        onClick={query}
        disabled={state !== "authenticated"}
      >
        Who am I
      </button>
      {result && (
        <output data-whoami>
          {result.ok
            ? `Server identity ${result.identity}`
            : result.required
              ? "Authentication required"
              : "Request failed"}
        </output>
      )}
    </section>
  );
}
