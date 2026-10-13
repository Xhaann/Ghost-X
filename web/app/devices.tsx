"use client";

import { type FormEvent, useEffect, useState } from "react";
import type { Connection } from "@/lib/application.ts";
import {
  type DeviceEntry,
  type Roster,
  deviceFingerprint,
  rosterFingerprint,
  verifyLinkRequest,
} from "@/lib/device.ts";
import type { AuthorizeResult, Devices } from "@/lib/devices.ts";
import type { Fingerprint as Print } from "@/lib/fingerprint.ts";
import { maxDevices } from "@/lib/protocol.ts";
import type { DeviceAdmin } from "@/lib/session.ts";
import { Confirm, Field, Fingerprint, Identifier, Notice } from "./ui";

type Failure = Extract<AuthorizeResult, { ok: false }>["reason"];

const failures: Record<Failure, string> = {
  not_root: "Only the device that created this identity can manage devices.",
  invalid_request: "The link code is invalid or has expired.",
  other_identity: "The link code belongs to another identity.",
  already_authorized: "This device is already authorized.",
  device_limit: `This identity already has the maximum of ${maxDevices} devices.`,
  not_published:
    "The server did not accept the updated device list. Check the connection and try again.",
};

type Outcome = { ok: boolean; message: string } | null;

function useRoster(devices: Devices): Roster | null {
  const [roster, setRoster] = useState<Roster | null>(devices.roster);
  useEffect(() => {
    setRoster(devices.roster);
    return devices.onChange(setRoster);
  }, [devices]);
  return roster;
}

function usePrint(
  compute: (() => Promise<Print | null>) | null,
  key: string,
): Print | null {
  const [print, setPrint] = useState<Print | null>(null);
  useEffect(() => {
    let active = true;
    setPrint(null);
    if (compute) {
      void compute().then((value) => {
        if (active) {
          setPrint(value);
        }
      });
    }
    return () => {
      active = false;
    };
  }, [key]);
  return print;
}

function useDevicePrint(identity: string, device: DeviceEntry | null) {
  return usePrint(
    device ? () => deviceFingerprint(identity, device) : null,
    device ? `${identity}${device.id}${device.signing}${device.exchange}` : "",
  );
}

function OutcomeNotice({ outcome }: { outcome: Outcome }) {
  if (!outcome) {
    return null;
  }
  return (
    <Notice
      tone={outcome.ok ? "success" : "danger"}
      symbol={outcome.ok ? "✓" : "!"}
      urgent={!outcome.ok}
    >
      <p data-device-notice>{outcome.message}</p>
    </Notice>
  );
}

function Pending({
  devices,
  identity,
}: {
  devices: Devices;
  identity: string;
}) {
  const [code, setCode] = useState<string | null>(null);
  const [round, setRound] = useState(0);
  const print = useDevicePrint(identity, devices.own);

  useEffect(() => {
    let active = true;
    void devices.linkRequest().then((value) => {
      if (active) {
        setCode(value);
      }
    });
    return () => {
      active = false;
    };
  }, [devices, round]);

  return (
    <section
      className="panel stack"
      data-device-status="pending"
      aria-labelledby="pending-title"
    >
      <div className="stack-small">
        <h2 id="pending-title">Waiting to be authorized</h2>
        <p className="muted prose">
          This device has joined the identity but cannot message yet. On the
          device that created the identity, open Devices, enter this link code
          and check that the fingerprint below matches before authorizing.
        </p>
      </div>
      {code ? (
        <div data-link-code={code}>
          <Identifier value={code} label="Link code" />
        </div>
      ) : (
        <p className="muted">Preparing a link code…</p>
      )}
      {print && (
        <div className="stack-small">
          <span className="field-label">This device&apos;s fingerprint</span>
          <div data-own-device>
            <Fingerprint
              digits={print.digits}
              label="This device's fingerprint"
            />
          </div>
        </div>
      )}
      <p className="small muted">Link codes expire after ten minutes.</p>
      <div>
        <button
          type="button"
          className="button"
          onClick={() => setRound((value) => value + 1)}
        >
          Create a new link code
        </button>
      </div>
    </section>
  );
}

function Authorize({
  admin,
  identity,
}: {
  admin: DeviceAdmin;
  identity: string;
}) {
  const [code, setCode] = useState("");
  const [device, setDevice] = useState<DeviceEntry | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome>(null);
  const [busy, setBusy] = useState(false);
  const print = useDevicePrint(identity, device);

  const check = async (event: FormEvent) => {
    event.preventDefault();
    setOutcome(null);
    const parsed = await verifyLinkRequest(
      code.trim(),
      Math.floor(Date.now() / 1000),
    );
    if (!parsed || parsed.identity !== identity) {
      setDevice(null);
      setError(parsed ? failures.other_identity : failures.invalid_request);
      return;
    }
    setError(null);
    setDevice(parsed.device);
  };

  const confirm = async () => {
    setBusy(true);
    const result = await admin.authorize(code.trim());
    setBusy(false);
    setDevice(null);
    setCode("");
    setOutcome(
      result.ok
        ? {
            ok: true,
            message: "Device authorized. It can now send and receive messages.",
          }
        : { ok: false, message: failures[result.reason] },
    );
  };

  return (
    <section className="panel stack" aria-labelledby="authorize-title">
      <h2 id="authorize-title">Authorize a new device</h2>
      <form className="stack-small" onSubmit={check} data-authorize noValidate>
        <Field
          label="Link code"
          hint="Shown on the new device after it joins this identity."
          error={error}
        >
          {(props) => (
            <input
              {...props}
              className="input mono"
              autoComplete="off"
              spellCheck={false}
              value={code}
              onChange={(event) => {
                setCode(event.target.value);
                setDevice(null);
              }}
            />
          )}
        </Field>
        <div>
          <button type="submit" className="button" disabled={!code.trim()}>
            Check link code
          </button>
        </div>
      </form>
      {device && print && (
        <div className="stack-small" data-link-confirm>
          <p className="prose">
            Compare this fingerprint with the one shown on the new device.
            Authorize only if every group matches.
          </p>
          <div data-link-fingerprint>
            <Fingerprint digits={print.digits} label="New device fingerprint" />
          </div>
          <div className="row">
            <button
              type="button"
              className="button button-primary"
              disabled={busy}
              onClick={confirm}
            >
              {busy ? "Authorizing…" : "Fingerprints match, authorize"}
            </button>
            <button
              type="button"
              className="button"
              onClick={() => setDevice(null)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      <OutcomeNotice outcome={outcome} />
    </section>
  );
}

function DeviceRow({
  identity,
  device,
  current,
  onRevoke,
}: {
  identity: string;
  device: DeviceEntry;
  current: boolean;
  onRevoke: (() => void) | null;
}) {
  const print = useDevicePrint(identity, device);
  return (
    <li
      className="device"
      data-device={device.id}
      data-current={current ? "true" : undefined}
    >
      <div className="row between">
        <div className="device-field">
          <span className="field-label small">Device ID</span>
          <code>{device.id}</code>
        </div>
        {current && <span className="pill tone-progress">This device</span>}
      </div>
      {print && (
        <div className="device-field" data-device-fingerprint>
          <span className="field-label small">Fingerprint</span>
          <Fingerprint
            digits={print.digits}
            label={`Fingerprint of device ${device.id}`}
          />
        </div>
      )}
      {onRevoke && (
        <div>
          <Confirm
            action="Revoke"
            question={`Revoke device ${device.id}? It will no longer receive new messages or be able to send as this identity. Contacts learn about the revocation when they next fetch your device list.`}
            confirm="Revoke device"
            onConfirm={onRevoke}
          />
        </div>
      )}
    </li>
  );
}

export default function DevicePanel({
  admin,
  devices,
  identity,
  deviceId,
  connection,
}: {
  admin: DeviceAdmin | null;
  devices: Devices;
  identity: string;
  deviceId: string;
  connection: Connection | null;
}) {
  const roster = useRoster(devices);
  const print = usePrint(
    roster ? () => rosterFingerprint(roster) : null,
    roster ? `${roster.identity}${roster.version}${roster.signature}` : "",
  );
  const [outcome, setOutcome] = useState<Outcome>(null);

  if (devices.status === "revoked" || connection?.status === "revoked") {
    return (
      <section className="panel stack" data-device-status="revoked">
        <h2>This device was removed</h2>
        <Notice tone="danger" symbol="!" urgent>
          <p>
            This device is no longer authorized for its identity and cannot send
            or receive messages. To use Ghost X here again, reset local data in
            the Connection section and set up this device again.
          </p>
        </Notice>
      </section>
    );
  }
  if (devices.status === "pending" || !roster) {
    return <Pending devices={devices} identity={identity} />;
  }

  const revoke = (id: string) => async () => {
    if (!admin) {
      return;
    }
    setOutcome(null);
    const result = await admin.revoke(id);
    setOutcome(
      result.ok
        ? { ok: true, message: "Device revoked." }
        : { ok: false, message: failures[result.reason] },
    );
  };

  return (
    <div className="columns">
      <section
        className="panel stack"
        data-device-status="authorized"
        data-devices={roster.devices.length}
        aria-labelledby="devices-title"
      >
        <div className="stack-small">
          <h2 id="devices-title">Authorized devices</h2>
          <p className="muted small prose">
            {devices.canManage
              ? `This device created the identity and can authorize or revoke up to ${maxDevices} devices.`
              : "Devices are managed on the device that created this identity."}
          </p>
        </div>
        {print && (
          <div className="stack-small">
            <span className="field-label">Identity fingerprint</span>
            <p className="small muted prose">
              Contacts compare this to verify you. It changes whenever a device
              is added or removed.
            </p>
            <div data-own-fingerprint>
              <Fingerprint digits={print.digits} label="Identity fingerprint" />
            </div>
          </div>
        )}
        <ul className="device-list">
          {roster.devices.map((device) => (
            <DeviceRow
              key={device.id}
              identity={identity}
              device={device}
              current={device.id === deviceId}
              onRevoke={
                admin && device.id !== deviceId ? revoke(device.id) : null
              }
            />
          ))}
        </ul>
        <OutcomeNotice outcome={outcome} />
        {devices.canManage && !admin && (
          <Notice tone="neutral" symbol="○">
            <p data-device-admin="unavailable">
              Authorizing and revoking devices requires the Internet transport,
              because the server publishes the updated device list.
            </p>
          </Notice>
        )}
      </section>
      {admin && <Authorize admin={admin} identity={identity} />}
    </div>
  );
}
