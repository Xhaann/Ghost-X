"use client";

import { type FormEvent, useEffect, useState } from "react";
import type { Authenticator } from "@/lib/auth.ts";
import type { Client } from "@/lib/client.ts";
import type { SendResult } from "@/lib/messenger.ts";
import { useMessenger } from "@/lib/useMessenger.ts";

const reasons: Record<string, string> = {
  recipient_unavailable: "Recipient unavailable",
  message_too_large: "Message too large",
  invalid_payload: "Invalid recipient or message",
  authentication_required: "Authentication required",
  not_sent: "Not sent",
};

function describe(result: SendResult): string {
  return result.ok
    ? "Delivered"
    : (reasons[result.reason] ?? "Delivery failed");
}

export default function Messages({
  client,
  authenticator,
}: {
  client: Client | null;
  authenticator: Authenticator | null;
}) {
  const { state, send } = useMessenger(client, authenticator);
  const [to, setTo] = useState("");
  const [body, setBody] = useState("");
  const [result, setResult] = useState<SendResult | null>(null);
  const [sending, setSending] = useState(false);

  useEffect(() => {
    setResult(null);
  }, [state.active]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSending(true);
    const outcome = await send(to.trim(), body);
    setSending(false);
    setResult(outcome);
    if (outcome.ok) {
      setBody("");
    }
  };

  if (!state.active) {
    return null;
  }

  return (
    <section>
      <form onSubmit={submit}>
        <input
          aria-label="Recipient identity"
          value={to}
          onChange={(event) => setTo(event.target.value)}
        />
        <textarea
          aria-label="Message"
          value={body}
          onChange={(event) => setBody(event.target.value)}
        />
        <button type="submit" disabled={sending || !to.trim() || !body}>
          Send
        </button>
      </form>
      {result && <output data-send>{describe(result)}</output>}
      {state.received.length === 0 ? (
        <p data-received="0">No messages received</p>
      ) : (
        <ul data-received={state.received.length}>
          {state.received.map((message) => (
            <li key={message.sequence}>
              <code>{message.from}</code>
              <p>{message.body}</p>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
