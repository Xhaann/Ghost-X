"use client";

import type { AuthState } from "@/lib/auth.ts";
import type { Client } from "@/lib/client.ts";
import type { PresenceState } from "@/lib/presence.ts";
import { useAuth } from "@/lib/useAuth.ts";
import { type LocalState, useIdentity } from "@/lib/useIdentity.ts";
import { usePresence } from "@/lib/usePresence.ts";
import { useWhoami } from "@/lib/useWhoami.ts";
import { useEffect, useState } from "react";
import { type Fingerprint, fingerprint } from "@/lib/fingerprint.ts";
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

const localLabels: Record<Exclude<LocalState["status"], "ready">, string> = {
  loading: "Loading",
  unavailable: "Local storage unavailable",
  corrupted: "Stored identity could not be restored",
};

function Reset({ onReset }: { onReset: () => void }) {
  const [confirming, setConfirming] = useState(false);
  if (!confirming) {
    return (
      <button type="button" onClick={() => setConfirming(true)}>
        Reset local data
      </button>
    );
  }
  return (
    <p data-reset>
      Delete this identity, its keys, and its message history from this browser?{" "}
      <button
        type="button"
        onClick={() => {
          setConfirming(false);
          onReset();
        }}
      >
        Delete
      </button>{" "}
      <button type="button" onClick={() => setConfirming(false)}>
        Cancel
      </button>
    </p>
  );
}

function OwnFingerprint({
  identity,
  exchangeKey,
}: {
  identity: string;
  exchangeKey: string;
}) {
  const [print, setPrint] = useState<Fingerprint | null>(null);

  useEffect(() => {
    let active = true;
    fingerprint(identity, exchangeKey).then((value) => {
      if (active) {
        setPrint(value);
      }
    });
    return () => {
      active = false;
      setPrint(null);
    };
  }, [identity, exchangeKey]);

  return print ? (
    <p>
      Your fingerprint <code data-own-fingerprint>{print.digits}</code>
    </p>
  ) : null;
}

export default function Identity({ client }: { client: Client | null }) {
  const { local, reset } = useIdentity();
  const session = local.status === "ready" ? local : null;
  const key = session?.keys.identity ?? null;
  const { state, authenticator } = useAuth(client, key);
  const presence = usePresence(client, authenticator);
  const { query, result } = useWhoami(client, state);
  const others = presence.identities.filter((id) => id !== key?.identity);

  return (
    <section>
      {session ? (
        <p>
          Identity <code>{session.keys.identity.identity}</code>{" "}
          <span data-origin={session.created ? "created" : "restored"}>
            {session.created ? "New identity" : "Restored identity"}
          </span>
        </p>
      ) : (
        <p data-local={local.status}>
          {localLabels[local.status as keyof typeof localLabels]}
        </p>
      )}
      {session && (
        <OwnFingerprint
          identity={session.keys.identity.identity}
          exchangeKey={session.keys.exchange.publicKey}
        />
      )}
      {(session || local.status === "corrupted") && <Reset onReset={reset} />}
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
      <Messages
        client={client}
        authenticator={authenticator}
        session={session}
      />
    </section>
  );
}
