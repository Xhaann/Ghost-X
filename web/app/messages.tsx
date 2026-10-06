"use client";

import { type FormEvent, useState } from "react";
import type { Authenticator } from "@/lib/auth.ts";
import type { Client } from "@/lib/client.ts";
import type {
  Conversation,
  ConversationMessage,
  DeliveryState,
} from "@/lib/conversations.ts";
import { bodySize, maxBodySize } from "@/lib/protocol.ts";
import type { TrustState, TrustView } from "@/lib/trust.ts";
import { useConversations } from "@/lib/useConversations.ts";
import type { LocalSession } from "@/lib/useIdentity.ts";

const deliveryLabels: Record<DeliveryState, string> = {
  sending: "Sending",
  delivered: "Delivered",
  unavailable: "Not delivered: recipient unavailable",
  failed: "Not delivered",
};

const rejections: Record<string, string> = {
  no_conversation: "Select a conversation",
  authentication_required: "Not connected",
  invalid_payload: "Invalid message",
  message_too_large: "Message too large",
};

function status(message: ConversationMessage): string {
  if (message.direction === "sent") {
    return deliveryLabels[message.delivery];
  }
  return message.body === null ? "Could not be decrypted" : "Received";
}

const trustLabels: Record<TrustState, string> = {
  unavailable:
    "Verification cannot be checked: this identity's current key is not available",
  unverified:
    "Not verified: the server authenticated this identity, but you have not compared fingerprints",
  verified: "Verified: you confirmed this exact fingerprint",
  changed:
    "Identity key changed since you verified it. Compare the new fingerprint before relying on this conversation.",
};

function Verification({
  view,
  onVerify,
}: {
  view: TrustView;
  onVerify: (value: string) => Promise<boolean>;
}) {
  const [confirming, setConfirming] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const current = view.current;
  const pending = confirming !== null && current?.value === confirming;

  return (
    <div data-verification={view.state}>
      <p role={view.state === "changed" ? "alert" : undefined}>
        <strong>{trustLabels[view.state]}</strong>
      </p>
      {current && (
        <p>
          Fingerprint <code data-fingerprint>{current.digits}</code>
        </p>
      )}
      {view.state === "changed" && view.verified && (
        <p>
          Previously verified fingerprint{" "}
          <code data-previous>{view.verified.digits}</code>
        </p>
      )}
      {current &&
        (view.state === "unverified" || view.state === "changed") &&
        !pending && (
          <button
            type="button"
            onClick={() => {
              setFailed(false);
              setConfirming(current.value);
            }}
          >
            Verify identity
          </button>
        )}
      {pending && current && (
        <div data-confirm>
          <p>
            Ask the owner of this identity to read their fingerprint to you over
            a channel you trust, such as in person or a call. Confirm only if
            every digit matches:
          </p>
          <p>
            <code data-confirm-fingerprint>{current.digits}</code>
          </p>
          <button
            type="button"
            onClick={async () => {
              const value = confirming;
              setConfirming(null);
              setFailed(!(await onVerify(value)));
            }}
          >
            Fingerprints match
          </button>{" "}
          <button type="button" onClick={() => setConfirming(null)}>
            Cancel
          </button>
        </div>
      )}
      {failed && (
        <output data-verify-failed>
          Not verified: the fingerprint changed or could not be saved
        </output>
      )}
    </div>
  );
}

function ConversationList({
  conversations,
  active,
  onOpen,
  trustOf,
}: {
  conversations: readonly Conversation[];
  active: string | null;
  onOpen: (identity: string) => void;
  trustOf: (identity: string) => TrustState;
}) {
  if (conversations.length === 0) {
    return <p data-conversations="0">No conversations</p>;
  }
  return (
    <ul data-conversations={conversations.length}>
      {conversations.map((conversation) => (
        <li key={conversation.identity}>
          <button
            type="button"
            data-conversation={conversation.identity}
            aria-pressed={conversation.identity === active}
            onClick={() => onOpen(conversation.identity)}
          >
            <code>{conversation.identity}</code>
            {trustOf(conversation.identity) === "changed" && (
              <span data-changed>Identity changed</span>
            )}
            {conversation.unread > 0 && (
              <span data-unread={conversation.unread}>
                {conversation.unread} unread
              </span>
            )}
          </button>
        </li>
      ))}
    </ul>
  );
}

export default function Messages({
  client,
  authenticator,
  session,
}: {
  client: Client | null;
  authenticator: Authenticator | null;
  session: LocalSession | null;
}) {
  const { state, rejected, open, close, send, verification, trustOf, verify } =
    useConversations(client, authenticator, session);
  const [recipient, setRecipient] = useState("");
  const [body, setBody] = useState("");
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const active = state.conversations.find(
    (conversation) => conversation.identity === state.active,
  );
  const tooLarge = bodySize(body) > maxBodySize;

  const start = (event: FormEvent) => {
    event.preventDefault();
    setNotice(open(recipient.trim()) ? null : "Invalid identity");
    setRecipient("");
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (pending) {
      return;
    }
    const attempt = send(body);
    if (!attempt.accepted) {
      setNotice(rejections[attempt.reason]);
      return;
    }
    setNotice(null);
    setBody("");
    setPending(true);
    await attempt.delivery;
    setPending(false);
  };

  if (!session || !authenticator) {
    return null;
  }

  return (
    <section>
      <form onSubmit={start}>
        <input
          aria-label="Recipient identity"
          value={recipient}
          onChange={(event) => setRecipient(event.target.value)}
        />
        <button type="submit" disabled={!recipient.trim()}>
          Open conversation
        </button>
      </form>
      <ConversationList
        conversations={state.conversations}
        active={state.active}
        onOpen={(identity) => open(identity)}
        trustOf={trustOf}
      />
      {rejected > 0 && (
        <p data-rejected={rejected}>
          {rejected === 1
            ? "1 stored message could not be restored"
            : `${rejected} stored messages could not be restored`}
        </p>
      )}
      {notice && <output data-notice>{notice}</output>}
      {active ? (
        <article data-active={active.identity}>
          <p>
            Conversation with <code>{active.identity}</code>
          </p>
          <p data-encryption>End-to-end encrypted to this identity</p>
          {verification && (
            <Verification
              key={verification.identity}
              view={verification}
              onVerify={verify}
            />
          )}
          <button type="button" onClick={close}>
            Close conversation
          </button>
          {active.messages.length === 0 ? (
            <p data-messages="0">No messages yet</p>
          ) : (
            <ol data-messages={active.messages.length}>
              {active.messages.map((message) => (
                <li
                  key={message.id}
                  data-direction={message.direction}
                  data-delivery={
                    message.direction === "sent" ? message.delivery : undefined
                  }
                >
                  {message.body !== null && <p>{message.body}</p>}
                  <small>{status(message)}</small>
                </li>
              ))}
            </ol>
          )}
          <form onSubmit={submit}>
            <textarea
              aria-label="Message"
              value={body}
              onChange={(event) => setBody(event.target.value)}
            />
            {tooLarge && <small>Message too large</small>}
            <button
              type="submit"
              disabled={!state.connected || pending || !body || tooLarge}
            >
              Send
            </button>
          </form>
        </article>
      ) : (
        state.conversations.length > 0 && (
          <p data-selection>Select a conversation</p>
        )
      )}
    </section>
  );
}
