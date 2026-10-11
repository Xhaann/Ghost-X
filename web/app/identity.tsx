"use client";

import { type FormEvent, useState } from "react";
import type { Phase } from "@/lib/application.ts";
import { linkError, phaseView } from "@/lib/present.ts";
import type { IdentityInfo } from "@/lib/useApplication.ts";
import { Confirm, Field, Identifier, ViewNotice } from "./ui";

function Setup({
  create,
  link,
}: {
  create: () => void;
  link: (identity: string) => void;
}) {
  const [identity, setIdentity] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const problem = linkError(identity);
    setError(problem);
    if (!problem) {
      setBusy(true);
      link(identity.trim());
    }
  };

  return (
    <div className="stack" data-local="no_identity">
      <div className="stack-small">
        <h2>Set up this device</h2>
        <p className="muted prose">
          Ghost X identities are cryptographic keys created and kept on your
          device. There is no account, password or recovery service: if this
          device&apos;s data is lost, so is this identity.
        </p>
      </div>
      <div className="choices choices-2">
        <section className="choice" aria-labelledby="create-title">
          <h3 id="create-title" className="choice-title">
            New identity
          </h3>
          <p className="muted small">
            Create a fresh identity. This device becomes the one that can
            authorize your other devices.
          </p>
          <button
            type="button"
            className="button button-primary"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              create();
            }}
          >
            Create a new identity
          </button>
        </section>
        <section className="choice" aria-labelledby="link-title">
          <h3 id="link-title" className="choice-title">
            Add to an existing identity
          </h3>
          <form className="stack-small" onSubmit={submit} noValidate>
            <Field
              label="Identity to join"
              hint="Copy it from the Connection section on the device that created the identity."
              error={error}
            >
              {(props) => (
                <input
                  {...props}
                  className="input mono"
                  autoComplete="off"
                  spellCheck={false}
                  value={identity}
                  onChange={(event) => setIdentity(event.target.value)}
                />
              )}
            </Field>
            <button type="submit" className="button" disabled={busy}>
              Link this device
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}

export function Onboarding({
  phase,
  create,
  link,
  reset,
}: {
  phase: Phase;
  create: () => void;
  link: (identity: string) => void;
  reset: () => void;
}) {
  const view = phaseView(phase);
  return (
    <div className="onboarding stack">
      {phase.phase === "no_identity" ? (
        <Setup create={create} link={link} />
      ) : (
        view && (
          <div
            className="stack"
            data-local={phase.phase === "fatal" ? phase.reason : phase.phase}
          >
            <ViewNotice view={view} urgent={phase.phase === "fatal"} />
            {phase.phase === "fatal" && phase.reason === "corrupted" && (
              <Confirm
                action="Reset local data"
                question="Delete the unreadable identity and its history from this browser? This cannot be undone."
                confirm="Delete local data"
                onConfirm={reset}
              />
            )}
          </div>
        )
      )}
    </div>
  );
}

export function IdentityCard({
  identity,
  reset,
}: {
  identity: IdentityInfo;
  reset: () => void;
}) {
  return (
    <section className="panel stack" aria-labelledby="identity-title">
      <div className="stack-small">
        <h2 id="identity-title">This identity</h2>
        <p
          className="muted small"
          data-origin={identity.created ? "created" : "restored"}
        >
          {identity.linked
            ? "This device is linked to the identity below."
            : "This device created the identity below and can manage its devices."}
        </p>
      </div>
      <div className="stack-small" data-identity-panel>
        <span className="field-label">Identity</span>
        <Identifier value={identity.identity} label="Identity" />
        <p className="small muted prose">
          Share this with people who want to message you. It is public; your
          private keys never leave this device.
        </p>
      </div>
      <div className="stack-small">
        <span className="field-label">This device</span>
        <code className="identifier" data-device-id>
          {identity.deviceId}
        </code>
      </div>
      <Confirm
        action="Reset local data"
        question="Delete this identity, its keys and its message history from this browser? Other devices keep their copies. This cannot be undone."
        confirm="Delete local data"
        onConfirm={reset}
      />
    </section>
  );
}
