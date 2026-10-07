"use client";

import type { AuthState } from "@/lib/auth.ts";
import type { Client } from "@/lib/client.ts";
import type { PresenceState } from "@/lib/presence.ts";
import { useAuth } from "@/lib/useAuth.ts";
import { type LocalState, useIdentity } from "@/lib/useIdentity.ts";
import { usePresence } from "@/lib/usePresence.ts";
import { useWhoami } from "@/lib/useWhoami.ts";
import { type FormEvent, useState } from "react";
import { isIdentity } from "@/lib/identity.ts";
import DevicePanel from "./devices";
import Messages from "./messages";

const labels: Record<AuthState, string> = {
  unauthenticated: "Unauthenticated",
  authenticating: "Authenticating",
  authenticated: "Authenticated",
  failed: "Authentication failed",
  pending: "Waiting for this device to be authorized",
  revoked: "This device is no longer authorized",
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
  empty: "No identity on this device",
};

function Setup({
  onCreate,
  onLink,
}: {
  onCreate: () => void;
  onLink: (identity: string) => void;
}) {
  const [identity, setIdentity] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = identity.trim();
    if (!isIdentity(value)) {
      setNotice("Invalid identity");
      return;
    }
    onLink(value);
  };
  return (
    <div data-setup>
      <button type="button" onClick={onCreate}>
        Create a new identity
      </button>
      <form onSubmit={submit}>
        <label>
          Link this device to an existing identity{" "}
          <input
            aria-label="Identity to link"
            value={identity}
            onChange={(event) => setIdentity(event.target.value)}
          />
        </label>{" "}
        <button type="submit">Link device</button>
      </form>
      {notice && <output>{notice}</output>}
    </div>
  );
}

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

export default function Identity({ client }: { client: Client | null }) {
  const { local, reset, create, link } = useIdentity();
  const session = local.status === "ready" ? local : null;
  const self = session?.keys.identity;
  const { state, authenticator } = useAuth(client, session);
  const presence = usePresence(client, authenticator);
  const { query, result } = useWhoami(client, state);
  const others = presence.identities.filter((id) => id !== self);

  return (
    <section>
      {session ? (
        <p>
          Identity <code data-identity>{session.keys.identity}</code>{" "}
          <span data-origin={session.created ? "created" : "restored"}>
            {session.created
              ? session.keys.root
                ? "New identity"
                : "New linked device"
              : "Restored identity"}
          </span>{" "}
          Device <code data-device-id>{session.keys.deviceId}</code>
        </p>
      ) : (
        <p data-local={local.status}>
          {localLabels[local.status as keyof typeof localLabels]}
        </p>
      )}
      {local.status === "empty" && <Setup onCreate={create} onLink={link} />}
      {session && (
        <DevicePanel
          client={client}
          devices={session.devices}
          identity={session.keys.identity}
          deviceId={session.keys.deviceId}
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
          <p data-presence={presence.status}>{presenceLabel(presence, self)}</p>
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
