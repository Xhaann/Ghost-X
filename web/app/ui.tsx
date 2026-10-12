"use client";

import { type ReactNode, useEffect, useId, useRef, useState } from "react";
import { type Tone, type View, groupDigits } from "@/lib/present.ts";

export function Pill({ view, live }: { view: View; live?: boolean }) {
  return (
    <span
      className={`pill tone-${view.tone}`}
      title={view.detail}
      role={live ? "status" : undefined}
    >
      <span className="pill-symbol" aria-hidden="true">
        {view.symbol}
      </span>
      {view.label}
    </span>
  );
}

export function Notice({
  tone,
  title,
  children,
  urgent,
  silent,
  symbol,
}: {
  tone: Tone;
  title?: string;
  children?: ReactNode;
  urgent?: boolean;
  silent?: boolean;
  symbol?: string;
}) {
  return (
    <div
      className={`notice tone-${tone}`}
      role={urgent ? "alert" : silent ? undefined : "status"}
    >
      {symbol && (
        <span className="notice-symbol" aria-hidden="true">
          {symbol}
        </span>
      )}
      <div className="notice-body stack-small">
        {title && <strong>{title}</strong>}
        {children}
      </div>
    </div>
  );
}

export function ViewNotice({ view, urgent }: { view: View; urgent?: boolean }) {
  return (
    <Notice
      tone={view.tone}
      title={view.label}
      symbol={view.symbol}
      urgent={urgent}
    >
      <p>{view.detail}</p>
    </Notice>
  );
}

export function Identifier({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(
    () => () => {
      if (timer.current) {
        clearTimeout(timer.current);
      }
    },
    [],
  );

  const copy = () => {
    if (!navigator.clipboard) {
      return;
    }
    navigator.clipboard.writeText(value).then(
      () => {
        setCopied(true);
        if (timer.current) {
          clearTimeout(timer.current);
        }
        timer.current = setTimeout(() => setCopied(false), 2000);
      },
      () => setCopied(false),
    );
  };

  return (
    <div className="stack-small">
      <code className="identifier" aria-label={label}>
        {value}
      </code>
      <div className="row">
        <button type="button" className="button button-small" onClick={copy}>
          Copy {label.toLowerCase()}
        </button>
        <span className="small muted" role="status">
          {copied ? "Copied" : ""}
        </span>
      </div>
    </div>
  );
}

export function Fingerprint({
  digits,
  label,
}: {
  digits: string;
  label: string;
}) {
  return (
    <div className="fingerprint" role="group" aria-label={label}>
      {groupDigits(digits).map((group, index) => (
        <span key={index}>{group}</span>
      ))}
    </div>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string | null;
  children: (props: {
    id: string;
    "aria-describedby"?: string;
    "aria-invalid"?: boolean;
  }) => ReactNode;
}) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const described = [hint ? hintId : null, error ? errorId : null]
    .filter(Boolean)
    .join(" ");
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      {children({
        id,
        "aria-describedby": described || undefined,
        "aria-invalid": error ? true : undefined,
      })}
      {hint && (
        <span id={hintId} className="small muted">
          {hint}
        </span>
      )}
      {error && (
        <span id={errorId} className="field-error">
          {error}
        </span>
      )}
    </div>
  );
}

export function Confirm({
  action,
  question,
  confirm,
  onConfirm,
  disabled,
}: {
  action: string;
  question: string;
  confirm: string;
  onConfirm: () => void;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const cancel = useRef<HTMLButtonElement | null>(null);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const opened = useRef(false);

  useEffect(() => {
    if (open) {
      cancel.current?.focus();
      opened.current = true;
    } else if (opened.current) {
      trigger.current?.focus();
    }
  }, [open]);

  if (!open) {
    return (
      <button
        ref={trigger}
        type="button"
        className="button button-danger"
        disabled={disabled}
        onClick={() => setOpen(true)}
      >
        {action}
      </button>
    );
  }
  return (
    <div
      className="notice tone-danger"
      role="group"
      aria-label={question}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          setOpen(false);
        }
      }}
    >
      <div className="notice-body stack-small">
        <p>{question}</p>
        <div className="row">
          <button
            type="button"
            className="button button-danger-solid"
            onClick={() => {
              opened.current = false;
              setOpen(false);
              onConfirm();
            }}
          >
            {confirm}
          </button>
          <button
            ref={cancel}
            type="button"
            className="button"
            onClick={() => setOpen(false)}
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  );
}
