"use client";

import { useEffect, useState } from "react";
import type { Availability } from "@/lib/application.ts";
import {
  authorizationView,
  connectionView,
  transportError,
  transportView,
} from "@/lib/present.ts";
import type {
  PingResult,
  Session,
  SessionState,
  WhoamiResult,
} from "@/lib/session.ts";
import type { TransportKind } from "@/lib/transport.ts";
import { Notice, Pill, ViewNotice } from "./ui";

const kinds: TransportKind[] = ["websocket", "local"];

function Diagnostics({ session }: { session: Session }) {
  const [ping, setPing] = useState<PingResult | null>(null);
  const [whoami, setWhoami] = useState<WhoamiResult | null>(null);

  useEffect(() => {
    setPing(null);
    setWhoami(null);
  }, [session]);

  return (
    <details>
      <summary>Diagnostics</summary>
      <div className="stack-small">
        <div className="row">
          <button
            type="button"
            className="button"
            onClick={() =>
              void session.ping().then((value) => {
                if (!session.disposed) {
                  setPing(value);
                }
              })
            }
          >
            Measure round trip
          </button>
          <span role="status" className="small">
            {ping &&
              (ping.ok
                ? `Round trip ${ping.roundTrip} ms`
                : "No reply from the server")}
          </span>
        </div>
        <div className="row">
          <button
            type="button"
            className="button"
            onClick={() =>
              void session.whoami().then((value) => {
                if (!session.disposed) {
                  setWhoami(value);
                }
              })
            }
          >
            Ask the server who I am
          </button>
          <span role="status" className="small" data-whoami>
            {whoami &&
              (whoami.ok
                ? "The server sees this identity"
                : whoami.required
                  ? "Not authenticated with the server"
                  : "No reply from the server")}
          </span>
        </div>
      </div>
    </details>
  );
}

export default function Connection({
  kind,
  availability,
  session,
  state,
  select,
}: {
  kind: TransportKind;
  availability: Record<TransportKind, Availability>;
  session: Session | null;
  state: SessionState | null;
  select: (kind: TransportKind) => void;
}) {
  const others =
    state?.presence.status === "active" ? state.presence.identities.length : 0;

  return (
    <section className="panel stack" aria-labelledby="transport-title">
      <div className="stack-small">
        <h2 id="transport-title">Transport</h2>
        <p className="muted small prose">
          Choose how this device communicates. Ghost X only uses the transport
          you select; if it cannot connect, it reports that instead of switching
          to another one. Messages are end-to-end encrypted either way.
        </p>
      </div>
      <div
        className="choices choices-2"
        role="group"
        aria-label="Transport"
        data-transport={kind}
      >
        {kinds.map((option) => {
          const view = transportView(option, availability[option]);
          return (
            <button
              key={option}
              type="button"
              className="choice"
              aria-pressed={kind === option}
              data-availability={availability[option]}
              data-kind={option}
              disabled={!session}
              onClick={() => select(option)}
            >
              <span className="choice-title">
                {view.name}
                <span className="row">
                  {kind === option && (
                    <span className="pill tone-progress">Selected</span>
                  )}
                  <Pill view={view} />
                </span>
              </span>
              <span className="small muted">{view.detail}</span>
            </button>
          );
        })}
      </div>
      {state && (
        <div className="stack-small">
          <div data-transport-state={state.transport}>
            <ViewNotice
              view={connectionView(state.connection)}
              urgent={
                state.connection.status === "revoked" ||
                state.connection.status === "rejected"
              }
            />
          </div>
          {state.error && (
            <p className="small muted" data-transport-error={state.error}>
              {transportError(state.error)} Ghost X does not fall back to
              another transport.
            </p>
          )}
          {state.authorization && (
            <ViewNotice view={authorizationView(state.authorization)} />
          )}
          {state.kind === "websocket" &&
            state.connection.status === "authenticated" && (
              <details data-presence={state.presence.status}>
                <summary>
                  {state.presence.status === "active"
                    ? `${others} ${others === 1 ? "identity" : "identities"} online, including you`
                    : "Presence is being established"}
                </summary>
                {state.presence.status === "active" && (
                  <ul className="stack-small">
                    {state.presence.identities.map((id) => (
                      <li key={id}>
                        <code>{id}</code>
                      </li>
                    ))}
                  </ul>
                )}
              </details>
            )}
          {state.kind === "local" &&
            state.connection.status === "unavailable" && (
              <Notice tone="neutral">
                <p>
                  To keep messaging, select Internet. Your conversations and
                  keys stay on this device either way.
                </p>
              </Notice>
            )}
          {session && state.kind === "websocket" && (
            <Diagnostics session={session} />
          )}
        </div>
      )}
    </section>
  );
}
