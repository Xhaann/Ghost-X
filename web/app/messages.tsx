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
import { useConversations } from "@/lib/useConversations.ts";

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
  return message.direction === "sent"
    ? deliveryLabels[message.delivery]
    : "Received";
}

function ConversationList({
  conversations,
  active,
  onOpen,
}: {
  conversations: readonly Conversation[];
  active: string | null;
  onOpen: (identity: string) => void;
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
  self,
}: {
  client: Client | null;
  authenticator: Authenticator | null;
  self: string | null;
}) {
  const { state, open, close, send } = useConversations(
    client,
    authenticator,
    self,
  );
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

  if (!self || !authenticator) {
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
      />
      {notice && <output data-notice>{notice}</output>}
      {active ? (
        <article data-active={active.identity}>
          <p>
            Conversation with <code>{active.identity}</code>
          </p>
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
                  <p>{message.body}</p>
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
