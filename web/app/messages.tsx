"use client";

import {
  type FormEvent,
  type KeyboardEvent,
  useEffect,
  useId,
  useRef,
  useState,
} from "react";
import type { Conversation, ConversationMessage } from "@/lib/conversations.ts";
import {
  type Section,
  composerState,
  connectionNotice,
  connectionView,
  conversationPreview,
  conversationTrust,
  deliveryExplanation,
  deliveryView,
  filterConversations,
  pairingView,
  presenceOf,
  reachabilityView,
  recipientError,
  rejectionMessage,
  shortIdentifier,
  trustView,
  undecryptable,
} from "@/lib/present.ts";
import type { Session, SessionState } from "@/lib/session.ts";
import type { TrustState, TrustView } from "@/lib/trust.ts";
import { Field, Fingerprint, Notice, Pill, ViewNotice } from "./ui";

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

  if (view.state === "verified" && current) {
    return (
      <details data-verification={view.state}>
        <summary>Verified fingerprint</summary>
        <Fingerprint digits={current.digits} label="Verified fingerprint" />
      </details>
    );
  }

  return (
    <div className="stack-small" data-verification={view.state}>
      {view.state === "changed" && (
        <ViewNotice view={trustView("changed")} urgent />
      )}
      {view.state === "unavailable" && (
        <div className="notice-compact">
          <ViewNotice view={trustView("unavailable")} />
        </div>
      )}
      {view.state === "changed" && view.verified && (
        <details>
          <summary>Previously verified fingerprint</summary>
          <Fingerprint
            digits={view.verified.digits}
            label="Previously verified fingerprint"
          />
        </details>
      )}
      {current && !pending && (
        <div className="row">
          <button
            type="button"
            className="button"
            onClick={() => {
              setFailed(false);
              setConfirming(current.value);
            }}
          >
            Verify identity
          </button>
          <span className="small muted">
            Compare fingerprints to confirm who holds this identity.
          </span>
        </div>
      )}
      {pending && current && (
        <div className="panel stack-small" data-confirm>
          <p className="prose">
            Ask the owner of this identity to read their fingerprint to you over
            a channel you trust, such as in person or on a call. Confirm only if
            every group matches.
          </p>
          <Fingerprint digits={current.digits} label="Fingerprint to compare" />
          <div className="row">
            <button
              type="button"
              className="button button-primary"
              onClick={async () => {
                const value = confirming;
                setConfirming(null);
                setFailed(!(await onVerify(value)));
              }}
            >
              Fingerprints match
            </button>
            <button
              type="button"
              className="button"
              onClick={() => setConfirming(null)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {failed && (
        <Notice tone="danger" symbol="!">
          <p data-verify-failed>
            Not verified: the fingerprint changed or could not be saved.
          </p>
        </Notice>
      )}
    </div>
  );
}

function MessageItem({ message }: { message: ConversationMessage }) {
  const view =
    message.direction === "sent"
      ? deliveryView(message.delivery)
      : message.body === null
        ? undecryptable
        : null;
  const explanation =
    message.direction === "sent"
      ? deliveryExplanation(message.delivery)
      : message.body === null
        ? undecryptable.detail
        : null;
  return (
    <li
      className={`message message-${message.direction}`}
      data-direction={message.direction}
      data-delivery={
        message.direction === "sent" ? message.delivery : undefined
      }
    >
      <span className="visually-hidden">
        {message.direction === "sent" ? "You:" : "Them:"}
      </span>
      {message.body !== null && <p className="message-body">{message.body}</p>}
      {view && (
        <span
          className={`message-status tone-${view.tone}`}
          title={view.detail}
        >
          <span aria-hidden="true">{view.symbol} </span>
          {view.label}
        </span>
      )}
      {explanation && (
        <span className="message-explanation" data-explanation>
          {explanation}
        </span>
      )}
    </li>
  );
}

function ConversationButton({
  conversation,
  active,
  trust,
  onOpen,
}: {
  conversation: Conversation;
  active: boolean;
  trust: TrustState;
  onOpen: () => void;
}) {
  const label = conversationTrust(trust);
  return (
    <button
      type="button"
      className="conversation"
      data-conversation={conversation.identity}
      aria-current={active ? "true" : undefined}
      onClick={onOpen}
    >
      <span className="row between conversation-head">
        <span className="conversation-identity">
          <span className="visually-hidden">Conversation with </span>
          <code>{shortIdentifier(conversation.identity)}</code>
        </span>
        {conversation.unread > 0 && (
          <span className="nav-count" data-unread={conversation.unread}>
            {conversation.unread}
            <span className="visually-hidden"> unread</span>
          </span>
        )}
      </span>
      <span className="conversation-summary small">
        {label && (
          <span
            className={`conversation-trust tone-${label.tone}`}
            data-changed={trust === "changed" ? "" : undefined}
          >
            <span aria-hidden="true">{label.symbol} </span>
            {label.label}
          </span>
        )}
        <span className="conversation-preview muted">
          {conversationPreview(conversation.messages.at(-1))}
        </span>
      </span>
    </button>
  );
}

function ConversationSearch({
  query,
  onChange,
  shown,
  total,
}: {
  query: string;
  onChange: (query: string) => void;
  shown: number;
  total: number;
}) {
  const input = useRef<HTMLInputElement | null>(null);
  return (
    <div className="search" role="search">
      <Field
        label="Search conversations"
        hint="Filters the conversations on this device by identity or by the latest message preview shown."
      >
        {(props) => (
          <div className="search-row">
            <input
              {...props}
              ref={input}
              type="search"
              className="input"
              autoComplete="off"
              spellCheck={false}
              value={query}
              onChange={(event) => onChange(event.target.value)}
            />
            {query && (
              <button
                type="button"
                className="button button-small"
                onClick={() => {
                  onChange("");
                  input.current?.focus();
                }}
              >
                Clear search
              </button>
            )}
          </div>
        )}
      </Field>
      <p className="search-count small muted" role="status">
        {query.trim()
          ? `${shown} of ${total} ${total === 1 ? "conversation" : "conversations"}`
          : ""}
      </p>
    </div>
  );
}

function ConnectionBanner({
  state,
  goTo,
}: {
  state: SessionState;
  goTo: (section: Section) => void;
}) {
  const [open, setOpen] = useState(false);
  const details = useId();
  const view = connectionView(state.connection);
  const notice = connectionNotice(state.connection, state.error);
  const line = (text: string) =>
    text === notice.lastError ? (
      <p
        key={text}
        className="small muted"
        data-banner-error={state.error ?? undefined}
      >
        {text}
      </p>
    ) : (
      <p key={text} className="small">
        {text}
      </p>
    );
  return (
    <div className="banner" data-banner={state.connection.status}>
      <Notice tone={view.tone} symbol={view.symbol} silent>
        <div className="banner-text">
          <p className="banner-status">
            <strong>{view.label}</strong>{" "}
            <span className="muted" data-banner-transport={state.kind}>
              <span aria-hidden="true">· </span>
              <span className="visually-hidden">Transport: </span>
              {state.kind === "websocket" ? "Internet" : "Local link"}
            </span>
          </p>
          {notice.summary && line(notice.summary)}
          {notice.details.length > 0 && (
            <>
              <button
                type="button"
                className="banner-toggle"
                aria-expanded={open}
                aria-controls={details}
                onClick={() => setOpen((value) => !value)}
              >
                {open ? "Hide connection details" : "Show connection details"}
              </button>
              <div id={details} className="banner-details" data-open={open}>
                {notice.details.map(line)}
              </div>
            </>
          )}
        </div>
        <button
          type="button"
          className="button button-small"
          onClick={() => goTo("connection")}
        >
          Open connection settings
        </button>
      </Notice>
    </div>
  );
}

function NewConversation({
  session,
  self,
}: {
  session: Session;
  self: string;
}) {
  const [recipient, setRecipient] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const problem = recipientError(recipient, self);
    setError(problem);
    if (problem) {
      return;
    }
    if (session.open(recipient.trim())) {
      setRecipient("");
    } else {
      setError("Conversations open once messaging has started.");
    }
  };

  return (
    <form className="stack-small" onSubmit={submit} noValidate>
      <Field
        label="Recipient identity"
        hint="Paste the 43-character identity of the person you want to message."
        error={error}
      >
        {(props) => (
          <input
            {...props}
            className="input mono"
            autoComplete="off"
            spellCheck={false}
            value={recipient}
            onChange={(event) => setRecipient(event.target.value)}
          />
        )}
      </Field>
      <button type="submit" className="button button-primary">
        Open conversation
      </button>
    </form>
  );
}

function Composer({
  session,
  connected,
  changed,
  focusKey,
}: {
  session: Session;
  connected: boolean;
  changed: boolean;
  focusKey: string;
}) {
  const [body, setBody] = useState("");
  const [sending, setSending] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const field = useRef<HTMLTextAreaElement | null>(null);
  const composer = composerState(body);

  useEffect(() => {
    setNotice(null);
    field.current?.focus();
  }, [focusKey]);

  const send = async () => {
    if (sending || !body || composer.tooLarge) {
      return;
    }
    const attempt = session.send(body);
    if (!attempt.accepted) {
      setNotice(rejectionMessage(attempt.reason));
      return;
    }
    setNotice(null);
    setBody("");
    setSending(true);
    await attempt.delivery;
    setSending(false);
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    void send();
  };

  const keys = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (
      event.key === "Enter" &&
      !event.shiftKey &&
      !event.nativeEvent.isComposing
    ) {
      event.preventDefault();
      void send();
    }
  };

  return (
    <form className="composer" onSubmit={submit}>
      {changed && (
        <Notice tone="danger" symbol="!">
          <p>
            This identity changed since you verified it. Verify again before
            sending anything sensitive.
          </p>
        </Notice>
      )}
      <Field
        label="Message"
        hint={
          connected
            ? "Enter sends, Shift+Enter adds a new line."
            : "Messages can be sent once connected."
        }
        error={
          composer.tooLarge
            ? `Too long: ${composer.bytes} of ${composer.max} bytes.`
            : null
        }
      >
        {(props) => (
          <textarea
            {...props}
            ref={field}
            className="textarea"
            rows={3}
            value={body}
            onChange={(event) => setBody(event.target.value)}
            onKeyDown={keys}
          />
        )}
      </Field>
      <div className="row between composer-actions">
        <span className="small muted" aria-live="polite">
          {composer.nearLimit && !composer.tooLarge
            ? `${composer.bytes} of ${composer.max} bytes`
            : ""}
        </span>
        <button
          type="submit"
          className="button button-primary"
          disabled={!connected || sending || !body || composer.tooLarge}
        >
          {sending ? "Sending…" : "Send"}
        </button>
      </div>
      {notice && (
        <p className="field-error" role="alert" data-notice>
          {notice}
        </p>
      )}
    </form>
  );
}

export default function Messages({
  session,
  state,
  self,
  goTo,
}: {
  session: Session | null;
  state: SessionState | null;
  self: string;
  goTo: (section: Section) => void;
}) {
  const log = useRef<HTMLOListElement | null>(null);
  const listHeading = useRef<HTMLHeadingElement | null>(null);
  const returning = useRef(false);
  const [query, setQuery] = useState("");
  const conversations = state?.conversations;
  const active = conversations?.conversations.find(
    (conversation) => conversation.identity === conversations.active,
  );
  const count = active?.messages.length ?? 0;

  useEffect(() => {
    const element = log.current;
    if (element) {
      element.scrollTop = element.scrollHeight;
    }
  }, [count, active?.identity]);

  useEffect(() => {
    if (!active && returning.current) {
      returning.current = false;
      listHeading.current?.focus();
    }
  }, [active]);

  if (!session || !state || !conversations || state.messaging === "starting") {
    return (
      <Notice tone="progress" symbol="…">
        <p data-messaging="starting">Starting secure messaging…</p>
      </Notice>
    );
  }

  if (state.messaging === "unavailable") {
    return (
      <Notice tone="danger" symbol="!" urgent>
        <p data-messaging="unavailable">
          Encrypted messaging could not start on this device because its message
          keys or history could not be loaded.
        </p>
      </Notice>
    );
  }

  const connected = conversations.connected;
  const trust = (identity: string): TrustState =>
    state.changed.includes(identity) ? "changed" : session.trustOf(identity);
  const back = () => {
    returning.current = true;
    session.close();
  };
  const shown = filterConversations(conversations.conversations, query);

  return (
    <div className="workspace">
      {!connected && state.messaging === "ready" && (
        <ConnectionBanner state={state} goTo={goTo} />
      )}
      {state.rejected > 0 && (
        <Notice tone="warning" symbol="!">
          <p data-rejected={state.rejected}>
            {state.rejected === 1
              ? "1 stored message failed its integrity check and is not shown."
              : `${state.rejected} stored messages failed their integrity checks and are not shown.`}
          </p>
        </Notice>
      )}
      <div className="messages" data-view={active ? "thread" : "list"}>
        <section
          className="messages-list panel"
          aria-labelledby="conversations-title"
        >
          <div className="messages-list-header">
            <h2 id="conversations-title" ref={listHeading} tabIndex={-1}>
              Conversations
            </h2>
            <NewConversation session={session} self={self} />
          </div>
          {conversations.conversations.length > 0 && (
            <ConversationSearch
              query={query}
              onChange={setQuery}
              shown={shown.length}
              total={conversations.conversations.length}
            />
          )}
          {conversations.conversations.length === 0 ? (
            <p className="muted small empty-hint" data-conversations="0">
              No conversations yet. Open one with someone&apos;s identity above.
            </p>
          ) : shown.length === 0 ? (
            <p className="muted small empty-hint" data-search-empty>
              No conversations match &ldquo;{query.trim()}&rdquo;. Search covers
              identities and the latest message preview shown for each
              conversation.
            </p>
          ) : (
            <ul
              className="conversation-list"
              data-conversations={conversations.conversations.length}
              data-shown={shown.length}
            >
              {shown.map((conversation) => (
                <li key={conversation.identity}>
                  <ConversationButton
                    conversation={conversation}
                    active={conversation.identity === conversations.active}
                    trust={trust(conversation.identity)}
                    onOpen={() => session.open(conversation.identity)}
                  />
                </li>
              ))}
            </ul>
          )}
        </section>
        {active ? (
          <section
            className="thread panel"
            aria-labelledby="thread-title"
            data-active={active.identity}
          >
            <button
              type="button"
              className="button button-quiet back"
              onClick={back}
            >
              ← Back to conversations
            </button>
            <div className="thread-header">
              <div className="thread-title">
                <h2 id="thread-title">
                  <span className="visually-hidden">Conversation with </span>
                  <code>{shortIdentifier(active.identity)}</code>
                </h2>
                <details>
                  <summary>Full identity</summary>
                  <code className="identifier">{active.identity}</code>
                </details>
              </div>
              <dl className="thread-meta">
                <div>
                  <dt>Identity</dt>
                  <dd>
                    <Pill view={trustView(trust(active.identity))} />
                  </dd>
                </div>
                {state.kind === "websocket" && (
                  <div>
                    <dt>Presence</dt>
                    <dd>
                      <Pill
                        view={reachabilityView(
                          presenceOf(state.presence, active.identity),
                        )}
                      />
                    </dd>
                  </div>
                )}
                {pairingView(state.pairing) && (
                  <div data-pairing={state.pairing}>
                    <dt>Session</dt>
                    <dd>
                      <Pill view={pairingView(state.pairing)!} />
                    </dd>
                  </div>
                )}
              </dl>
              <p className="small muted" data-encryption>
                Messages are end-to-end encrypted to this identity&apos;s
                authorized devices.
              </p>
              {state.verification && (
                <Verification
                  key={state.verification.identity}
                  view={state.verification}
                  onVerify={(value) => session.verify(value)}
                />
              )}
            </div>
            {active.messages.length === 0 ? (
              <div className="log log-empty">
                <p className="muted small" data-messages="0">
                  No messages yet.
                </p>
              </div>
            ) : (
              <ol
                ref={log}
                className="log"
                role="log"
                aria-label="Messages"
                data-messages={active.messages.length}
                tabIndex={0}
              >
                {active.messages.map((message) => (
                  <MessageItem key={message.id} message={message} />
                ))}
              </ol>
            )}
            <Composer
              session={session}
              connected={connected}
              changed={trust(active.identity) === "changed"}
              focusKey={active.identity}
            />
          </section>
        ) : (
          <section className="thread thread-empty panel">
            <p className="muted" data-selection>
              {conversations.conversations.length > 0
                ? "Choose a conversation to read and reply."
                : "Open a conversation with someone's identity to start messaging."}
            </p>
          </section>
        )}
      </div>
    </div>
  );
}
