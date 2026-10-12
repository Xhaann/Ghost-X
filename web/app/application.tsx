"use client";

import { useEffect, useState } from "react";
import { type Section, connectionView, sections } from "@/lib/present.ts";
import { useApplication } from "@/lib/useApplication.ts";
import DevicePanel from "./devices";
import { IdentityCard, Onboarding } from "./identity";
import Messages from "./messages";
import Connection from "./status";
import { Pill } from "./ui";

export default function Application({ url }: { url: string | undefined }) {
  const app = useApplication(url);
  const [section, setSection] = useState<Section>("messages");
  const identity = app.identity;

  useEffect(() => {
    setSection("messages");
  }, [identity?.identity]);

  const unread =
    app.state?.conversations.conversations.reduce(
      (total, conversation) => total + conversation.unread,
      0,
    ) ?? 0;

  const workspace = identity !== null && section === "messages";

  return (
    <div className={workspace ? "shell shell-workspace" : "shell"}>
      <a className="skip" href="#main">
        Skip to content
      </a>
      <header className="topbar">
        <div className="topbar-inner">
          <h1 className="brand">Ghost X</h1>
          {identity && (
            <nav className="nav" aria-label="Sections">
              {sections.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="nav-item"
                  aria-current={section === item.id ? "page" : undefined}
                  onClick={() => setSection(item.id)}
                >
                  {item.label}
                  {item.id === "messages" && unread > 0 && (
                    <span className="nav-count">
                      {unread}
                      <span className="visually-hidden"> unread</span>
                    </span>
                  )}
                </button>
              ))}
            </nav>
          )}
          {identity && app.state && (
            <div
              className="topbar-status"
              data-connection={app.state.connection.status}
            >
              <span className="small muted">
                {app.kind === "websocket" ? "Internet" : "Local link"}
              </span>
              <Pill view={connectionView(app.state.connection)} live />
            </div>
          )}
        </div>
      </header>
      <main id="main" className="content" tabIndex={-1}>
        {!identity ? (
          <Onboarding
            phase={app.phase}
            create={app.create}
            link={app.link}
            reset={app.reset}
          />
        ) : section === "messages" ? (
          <Messages
            session={app.session}
            state={app.state}
            self={identity.identity}
            goTo={setSection}
          />
        ) : section === "devices" ? (
          <DevicePanel
            admin={app.session?.admin ?? null}
            devices={identity.devices}
            identity={identity.identity}
            deviceId={identity.deviceId}
            connection={app.state?.connection ?? null}
          />
        ) : (
          <div className="columns">
            <Connection
              kind={app.kind}
              availability={app.availability}
              session={app.session}
              state={app.state}
              select={app.select}
            />
            <IdentityCard identity={identity} reset={app.reset} />
          </div>
        )}
      </main>
    </div>
  );
}
