"use client";

import type { AuthState } from "@/lib/auth.ts";
import type { Client } from "@/lib/client.ts";
import type { PresenceState } from "@/lib/presence.ts";
import { useAuth } from "@/lib/useAuth.ts";
import { useIdentity } from "@/lib/useIdentity.ts";
import { usePresence } from "@/lib/usePresence.ts";
import { useWhoami } from "@/lib/useWhoami.ts";
import Messages from "./messages";

const labels: Record<AuthState, string> = {
  unauthenticated: "Unauthenticated",
  authenticating: "Authenticating",
  authenticated: "Authenticated",
  failed: "Authentication failed",
};

function presenceLabel(presence: PresenceState, self: string | undefined) {
  if (presence.status === "pending") {
    return "Establishing presence";
  }
  if (
    presence.status === "active" &&
    self &&
    presence.identities.includes(self)
  ) {
    return "Present";
  }
  return "Presence not established";
}

export default function Identity({ client }: { client: Client | null }) {
  const keys = useIdentity();
  const key = keys?.identity ?? null;
  const { state, authenticator } = useAuth(client, key);
  const presence = usePresence(client, authenticator);
  const { query, result } = useWhoami(client, state);
  const others = presence.identities.filter((id) => id !== key?.identity);

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
      {state === "authenticated" && (
        <>
          <p data-presence={presence.status}>
            {presenceLabel(presence, key?.identity)}
          </p>
          {presence.status === "active" &&
            (others.length === 0 ? (
              <p data-others="0">No other identities present</p>
            ) : (
              <ul data-others={others.length}>
                {others.map((id) => (
                  <li key={id}>
                    <code>{id}</code>
                  </li>
                ))}
              </ul>
            ))}
        </>
      )}
      <Messages client={client} authenticator={authenticator} keys={keys} />
    </section>
  );
}
