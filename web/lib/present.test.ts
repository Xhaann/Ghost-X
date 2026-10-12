import assert from "node:assert/strict";
import { test } from "node:test";
import type { Connection } from "./application.ts";
import { encodeBase64Url } from "./base64.ts";
import type { ConversationMessage, DeliveryState } from "./conversations.ts";
import {
  type View,
  authorizationView,
  composerState,
  connectionImpact,
  connectionView,
  conversationPreview,
  conversationTrust,
  deliveryView,
  groupDigits,
  linkError,
  pairingView,
  phaseView,
  presenceOf,
  reachabilityView,
  recipientError,
  rejectionMessage,
  sections,
  shortIdentifier,
  transportError,
  transportView,
  trustView,
  undecryptable,
} from "./present.ts";
import { maxBodySize } from "./protocol.ts";
import type { TransportError } from "./transport.ts";
import type { TrustState } from "./trust.ts";

const deliveries: DeliveryState[] = [
  "sending",
  "pending",
  "queued",
  "delivered",
  "expired",
  "unavailable",
  "failed",
];

const connections: Connection[] = [
  { status: "unavailable" },
  { status: "connecting" },
  { status: "reconnecting" },
  { status: "disconnected", reason: null },
  { status: "disconnected", reason: "lost" },
  { status: "authenticating" },
  { status: "authenticated" },
  { status: "rejected" },
  { status: "pending" },
  { status: "revoked" },
];

const trusts: TrustState[] = [
  "verified",
  "unverified",
  "changed",
  "unavailable",
];

function everyView(): View[] {
  return [
    ...deliveries.map(deliveryView),
    ...connections.map(connectionView),
    ...trusts.map(trustView),
    ...(["online", "offline", "unknown"] as const).map(reachabilityView),
    transportView("websocket", "available"),
    transportView("websocket", "unavailable"),
    transportView("local", "available"),
    transportView("local", "unavailable"),
    authorizationView({ roster: 1, basis: "confirmed", confirmed: null }),
    authorizationView({ roster: 1, basis: "unconfirmed", confirmed: null }),
    undecryptable,
    ...(
      [
        "pending",
        "established",
        "unavailable",
        "invalid_bundle",
        "failed",
      ] as const
    ).map((s) => pairingView(s)!),
    phaseView({ phase: "initializing" })!,
    phaseView({ phase: "fatal", reason: "storage_unavailable" })!,
    phaseView({ phase: "fatal", reason: "corrupted" })!,
    phaseView({ phase: "waiting" })!,
    phaseView({ phase: "fatal", reason: "unsupported" })!,
  ];
}

test("every state has a label, an explanation and a non-colour symbol", () => {
  for (const view of everyView()) {
    assert.ok(view.label.length > 0);
    assert.ok(view.detail.length > 0);
    assert.ok(view.symbol.length > 0, `${view.label} needs a symbol`);
  }
});

test("no view claims unsupported transports, guarantees or receipts", () => {
  for (const view of everyView()) {
    const text = `${view.label} ${view.detail}`;
    assert.doesNotMatch(
      text,
      /bluetooth|\bble\b|webrtc|read receipt|typing|guarantee/i,
    );
  }
});

test("only a confirmation from the recipient's device reads as delivered", () => {
  for (const state of deliveries) {
    const view = deliveryView(state);
    const claims = /^delivered$/i.test(view.label) || view.tone === "success";
    assert.equal(claims, state === "delivered", state);
  }
  assert.notEqual(deliveryView("pending").label, deliveryView("queued").label);
  assert.match(deliveryView("pending").detail, /stored here/);
  assert.match(deliveryView("queued").detail, /has not confirmed/);
  for (const failure of ["expired", "unavailable", "failed"] as const) {
    assert.equal(deliveryView(failure).tone, "danger");
  }
});

test("trust is only shown as verified after verification", () => {
  for (const state of trusts) {
    assert.equal(trustView(state).tone === "success", state === "verified");
    assert.equal(
      /verified$/i.test(trustView(state).label) &&
        !/not/i.test(trustView(state).label),
      state === "verified",
    );
  }
  assert.equal(trustView("changed").tone, "danger");
});

test("connection views separate connecting, connected and failure states", () => {
  assert.equal(connectionView({ status: "authenticated" }).tone, "success");
  for (const connection of connections) {
    if (connection.status !== "authenticated") {
      assert.notEqual(connectionView(connection).tone, "success");
    }
  }
  const errors: TransportError[] = [
    "unavailable",
    "failed",
    "lost",
    "timeout",
    "oversized",
    "malformed",
  ];
  for (const error of errors) {
    assert.ok(transportError(error).endsWith("."));
  }
});

test("connection impact only promises sending once a connection can resume it", () => {
  assert.equal(connectionImpact({ status: "authenticated" }), null);
  for (const connection of connections) {
    if (connection.status === "authenticated") {
      continue;
    }
    const impact = connectionImpact(connection);
    assert.ok(impact?.endsWith("."));
    const resumes = /waits for a connection/.test(impact ?? "");
    assert.equal(
      resumes,
      ["connecting", "reconnecting", "disconnected", "authenticating"].includes(
        connection.status,
      ),
      connection.status,
    );
  }
  assert.doesNotMatch(
    connectionImpact({ status: "revoked" })!,
    /history is available/,
  );
});

test("presence is unknown unless the server confirmed it", () => {
  const identity = encodeBase64Url(new Uint8Array(32));
  assert.equal(
    presenceOf({ status: "inactive", identities: [identity] }, identity),
    "unknown",
  );
  assert.equal(
    presenceOf({ status: "pending", identities: [identity] }, identity),
    "unknown",
  );
  assert.equal(
    presenceOf({ status: "active", identities: [identity] }, identity),
    "online",
  );
  assert.equal(
    presenceOf({ status: "active", identities: [] }, identity),
    "offline",
  );
});

test("the local link is described honestly in the browser", () => {
  const local = transportView("local", "unavailable");
  assert.equal(local.name, "Local link");
  assert.match(local.label, /not available/i);
  assert.match(local.detail, /will not fall back/i);
  assert.match(
    transportView("websocket", "unavailable").label,
    /not configured/i,
  );
  assert.equal(
    authorizationView({ roster: 2, basis: "unconfirmed", confirmed: null })
      .tone,
    "warning",
  );
  assert.match(
    authorizationView({
      roster: 2,
      basis: "confirmed",
      confirmed: { version: 2, at: 1 },
    }).detail,
    /not known here/,
  );
});

test("recipient and link identities are validated with actionable messages", () => {
  const self = encodeBase64Url(new Uint8Array(32).fill(1));
  const other = encodeBase64Url(new Uint8Array(32).fill(2));
  assert.match(recipientError("", self)!, /Enter/);
  assert.match(recipientError("   ", self)!, /Enter/);
  assert.match(recipientError("not-an-identity", self)!, /not a valid/);
  assert.match(recipientError(self, self)!, /your own/);
  assert.equal(recipientError(`  ${other}  `, self), null);
  assert.match(linkError("")!, /Enter/);
  assert.match(linkError("x")!, /not a valid/);
  assert.equal(linkError(other), null);
});

test("composer limits, rejections, identifiers and fingerprints are presented safely", () => {
  assert.deepEqual(composerState("hello"), {
    bytes: 5,
    max: maxBodySize,
    tooLarge: false,
    nearLimit: false,
  });
  assert.equal(composerState("é".repeat(maxBodySize / 2 + 1)).tooLarge, true);
  assert.equal(
    composerState("x".repeat(Math.ceil(maxBodySize * 0.9))).nearLimit,
    true,
  );
  for (const reason of [
    "no_conversation",
    "authentication_required",
    "invalid_payload",
    "message_too_large",
  ] as const) {
    assert.ok(rejectionMessage(reason).length > 0);
  }
  const id = encodeBase64Url(new Uint8Array(32).fill(7));
  assert.equal(shortIdentifier(id), `${id.slice(0, 8)}…${id.slice(-6)}`);
  assert.equal(shortIdentifier("short"), "short");
  assert.deepEqual(groupDigits("12345 67890  11111"), [
    "12345",
    "67890",
    "11111",
  ]);
  assert.deepEqual(
    sections.map((s) => s.id),
    ["messages", "devices", "connection"],
  );
  assert.equal(phaseView({ phase: "no_identity" }), null);
  assert.equal(phaseView({ phase: "ready" }), null);
  assert.equal(pairingView("none"), null);
  assert.equal(pairingView(null), null);
});

test("the conversation list labels trust in text and never as verified unless it is", () => {
  for (const state of trusts) {
    const label = conversationTrust(state);
    if (state === "verified" || state === "changed") {
      assert.deepEqual(label, trustView(state));
      assert.ok(label && label.label && label.symbol);
    } else {
      assert.equal(label, null);
    }
  }
  assert.equal(conversationTrust("unavailable")?.label, undefined);
  assert.equal(conversationTrust("changed")?.label, "Identity changed");
});

test("conversation previews are bounded and honest about undecryptable messages", () => {
  const base = { id: "m", from: "a", to: "b", sequence: 1 };
  const received = (body: string | null): ConversationMessage => ({
    ...base,
    direction: "received",
    body,
  });
  const sent: ConversationMessage = {
    ...base,
    direction: "sent",
    body: "hello",
    delivery: "queued",
  };
  assert.equal(conversationPreview(undefined), "No messages yet");
  assert.equal(conversationPreview(received(null)), "Could not be decrypted");
  assert.equal(conversationPreview(sent), "You: hello");
  const long = "x".repeat(5000);
  assert.equal(conversationPreview(received(long)), "x".repeat(60));
  assert.equal(conversationPreview({ ...sent, body: long }).length, 65);
});

test("a tab waiting for the device is told it has not loaded keys and is never shown as ready", () => {
  const waiting = phaseView({ phase: "waiting" })!;
  assert.equal(waiting.tone, "warning");
  assert.match(waiting.label, /another tab/);
  assert.match(waiting.detail, /has not loaded/);
  assert.match(waiting.detail, /automatically/);
  const unsupported = phaseView({ phase: "fatal", reason: "unsupported" })!;
  assert.equal(unsupported.tone, "danger");
  assert.match(unsupported.detail, /only one tab/);
  for (const view of [waiting, unsupported]) {
    assert.doesNotMatch(view.label, /ready|connected/i);
  }
});
