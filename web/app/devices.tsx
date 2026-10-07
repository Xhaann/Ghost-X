"use client";

import { type FormEvent, useEffect, useState } from "react";
import type { Client } from "@/lib/client.ts";
import {
  type DeviceEntry,
  type Roster,
  deviceFingerprint,
  rosterFingerprint,
  verifyLinkRequest,
} from "@/lib/device.ts";
import type { AuthorizeResult, Devices } from "@/lib/devices.ts";
import type { Fingerprint } from "@/lib/fingerprint.ts";

type Failure = Extract<AuthorizeResult, { ok: false }>["reason"];

const failures: Record<Failure, string> = {
  not_root: "Only the device that created this identity can manage devices",
  invalid_request: "The link code is invalid or has expired",
  other_identity: "The link code belongs to another identity",
  already_authorized: "This device is already authorized",
  device_limit: "This identity already has the maximum number of devices",
  not_published: "The server did not accept the updated device list",
};

function useRoster(devices: Devices): Roster | null {
  const [roster, setRoster] = useState<Roster | null>(devices.roster);
  useEffect(() => {
    setRoster(devices.roster);
    return devices.onChange(setRoster);
  }, [devices]);
  return roster;
}

function useDeviceDigits(identity: string, device: DeviceEntry | null) {
  const [print, setPrint] = useState<Fingerprint | null>(null);
  const key = device ? `${device.id}${device.signing}${device.exchange}` : "";
  useEffect(() => {
    let active = true;
    setPrint(null);
    if (device) {
      void deviceFingerprint(identity, device).then((value) => {
        if (active) {
          setPrint(value);
        }
      });
    }
    return () => {
      active = false;
    };
  }, [identity, key]);
  return print;
}

function useRosterDigits(roster: Roster | null) {
  const [print, setPrint] = useState<Fingerprint | null>(null);
  const key = roster
    ? `${roster.identity}${roster.version}${roster.signature}`
    : "";
  useEffect(() => {
    let active = true;
    setPrint(null);
    if (roster) {
      void rosterFingerprint(roster).then((value) => {
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
  const print = useDeviceDigits(identity, device);
  return (
    <li data-device={device.id} data-current={current ? "true" : undefined}>
      <code>{device.id}</code>{" "}
      {print && <code data-device-fingerprint>{print.digits}</code>}{" "}
      {current && <span>This device</span>}
      {onRevoke && (
        <button type="button" onClick={onRevoke}>
          Revoke
        </button>
      )}
    </li>
  );
}

function LinkCode({
  devices,
  identity,
}: {
  devices: Devices;
  identity: string;
}) {
  const [code, setCode] = useState<string | null>(null);
  const print = useDeviceDigits(identity, devices.own);
  const generate = () => {
    void devices.linkRequest().then(setCode);
  };
  useEffect(generate, [devices]);
  return (
    <div data-device-status="pending">
      <p>
        This device is waiting to be authorized. On the device that created this
        identity, enter this link code and confirm the device fingerprint.
      </p>
      {code && <code data-link-code>{code}</code>}
      {print && (
        <p>
          Device fingerprint <code data-own-device>{print.digits}</code>
        </p>
      )}
      <button type="button" onClick={generate}>
        New link code
      </button>
    </div>
  );
}

function Authorize({
  client,
  devices,
  identity,
}: {
  client: Client;
  devices: Devices;
  identity: string;
}) {
  const [code, setCode] = useState("");
  const [device, setDevice] = useState<DeviceEntry | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const print = useDeviceDigits(identity, device);

  const check = async (event: FormEvent) => {
    event.preventDefault();
    const parsed = await verifyLinkRequest(code, Math.floor(Date.now() / 1000));
    if (!parsed || parsed.identity !== identity) {
      setDevice(null);
      setNotice(parsed ? failures.other_identity : failures.invalid_request);
      return;
    }
    setNotice(null);
    setDevice(parsed.device);
  };

  const confirm = async () => {
    const result = await devices.authorize(client, code);
    setDevice(null);
    setCode("");
    setNotice(result.ok ? "Device authorized" : failures[result.reason]);
  };

  return (
    <form onSubmit={check} data-authorize>
      <label>
        Link code{" "}
        <input
          aria-label="Link code"
          value={code}
          onChange={(event) => setCode(event.target.value)}
        />
      </label>{" "}
      <button type="submit">Check link code</button>
      {device && print && (
        <p data-link-confirm>
          New device fingerprint{" "}
          <code data-link-fingerprint>{print.digits}</code>{" "}
          <button type="button" onClick={confirm}>
            Authorize device
          </button>
        </p>
      )}
      {notice && <output data-device-notice>{notice}</output>}
    </form>
  );
}

export default function DevicePanel({
  client,
  devices,
  identity,
  deviceId,
}: {
  client: Client | null;
  devices: Devices;
  identity: string;
  deviceId: string;
}) {
  const roster = useRoster(devices);
  const print = useRosterDigits(roster);
  const [notice, setNotice] = useState<string | null>(null);

  if (devices.status === "revoked") {
    return (
      <p data-device-status="revoked">
        This device has been removed from its identity. Reset local data to
        create a new device.
      </p>
    );
  }
  if (devices.status === "pending" || !roster) {
    return <LinkCode devices={devices} identity={identity} />;
  }
  const revoke = (id: string) => async () => {
    if (!client) {
      return;
    }
    const result = await devices.revoke(client, id);
    setNotice(result.ok ? "Device revoked" : failures[result.reason]);
  };
  return (
    <div data-device-status="authorized" data-devices={roster.devices.length}>
      {print && (
        <p>
          Your fingerprint <code data-own-fingerprint>{print.digits}</code>
        </p>
      )}
      <p>
        Authorized devices{" "}
        {devices.canManage
          ? "(this device can manage devices)"
          : "(manage devices on the device that created this identity)"}
      </p>
      <ul>
        {roster.devices.map((device) => (
          <DeviceRow
            key={device.id}
            identity={identity}
            device={device}
            current={device.id === deviceId}
            onRevoke={
              devices.canManage && client && device.id !== deviceId
                ? revoke(device.id)
                : null
            }
          />
        ))}
      </ul>
      {devices.canManage && client && (
        <Authorize client={client} devices={devices} identity={identity} />
      )}
      {notice && <output data-device-notice>{notice}</output>}
    </div>
  );
}
