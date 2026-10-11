"use client";

import { type FormEvent, useEffect, useState } from "react";
import type { Phase } from "@/lib/application.ts";
import type { AuthState } from "@/lib/auth.ts";
import { isIdentity } from "@/lib/identity.ts";
import type { PresenceState } from "@/lib/presence.ts";
import type { Session, SessionState, WhoamiResult } from "@/lib/session.ts";
import type { IdentityInfo } from "@/lib/useApplication.ts";
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

const phaseLabels: Record<Exclude<Phase["phase"], "ready">, string> = {
  initializing: "Loading",
  no_identity: "No identity on this device",
  fatal: "",
};

const fatalLabels: Record<
  Extract<Phase, { phase: "fatal" }>["reason"],
  string
> = {
  storage_unavailable: "Local storage unavailable",
  corrupted: "Stored identity could not be restored",
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

export default function Identity({
  phase,
  identity,
  session,
  state,
  create,
  link,
  reset,
}: {
  phase: Phase;
  identity: IdentityInfo | null;
  session: Session | null;
  state: SessionState | null;
  create: () => void;
  link: (identity: string) => void;
  reset: () => void;
}) {
  const [result, setResult] = useState<WhoamiResult | null>(null);
  const auth: AuthState = state?.auth ?? "unauthenticated";
  const presence: PresenceState = state?.presence ?? {
    status: "inactive",
    identities: [],
  };
  const self = identity?.identity;
  const others = presence.identities.filter((id) => id !== self);

  useEffect(() => {
    setResult(null);
  }, [session, auth]);

  const query = () => {
    if (!session) {
      return;
    }
    void session.whoami().then((value) => {
      if (!session.disposed) {
        setResult(value);
      }
    });
  };

  return (
    <section>
      {identity ? (
        <p>
          Identity <code data-identity>{identity.identity}</code>{" "}
          <span data-origin={identity.created ? "created" : "restored"}>
            {identity.created
              ? identity.linked
                ? "New linked device"
                : "New identity"
              : "Restored identity"}
          </span>{" "}
          Device <code data-device-id>{identity.deviceId}</code>
        </p>
      ) : (
        <p data-local={phase.phase === "fatal" ? phase.reason : phase.phase}>
          {phase.phase === "fatal"
            ? fatalLabels[phase.reason]
            : phase.phase !== "ready" && phaseLabels[phase.phase]}
        </p>
      )}
      {phase.phase === "no_identity" && (
        <Setup onCreate={create} onLink={link} />
      )}
      {identity && (
        <DevicePanel
          admin={session?.admin ?? null}
          devices={identity.devices}
          identity={identity.identity}
          deviceId={identity.deviceId}
        />
      )}
      {(identity ||
        (phase.phase === "fatal" && phase.reason === "corrupted")) && (
        <Reset onReset={reset} />
      )}
      {identity && (
        <>
          <p data-auth={auth}>{labels[auth]}</p>
          {state?.kind === "websocket" && (
            <button
              type="button"
              onClick={query}
              disabled={auth !== "authenticated"}
            >
              Who am I
            </button>
          )}
          {result && (
            <output data-whoami>
              {result.ok
                ? `Server identity ${result.identity}`
                : result.required
                  ? "Authentication required"
                  : "Request failed"}
            </output>
          )}
          {auth === "authenticated" && state?.kind === "websocket" && (
            <>
              <p data-presence={presence.status}>
                {presenceLabel(presence, self)}
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
          {state?.peer && (
            <p data-peer={state.peer.identity}>
              Directly linked to <code>{state.peer.identity}</code>{" "}
              {state.authorization?.basis === "confirmed"
                ? "with a device list last confirmed by the server"
                : "with a device list the server has not confirmed; revocations this device has not received cannot be detected"}
            </p>
          )}
        </>
      )}
      <Messages session={session} state={state} />
    </section>
  );
}
