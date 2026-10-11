"use client";

import { useApplication } from "@/lib/useApplication.ts";
import Identity from "./identity";
import Status from "./status";

export default function Application({ url }: { url: string | undefined }) {
  const app = useApplication(url);

  return (
    <>
      <Status
        kind={app.kind}
        availability={app.availability}
        session={app.session}
        state={app.state}
        select={app.select}
      />
      <Identity
        phase={app.phase}
        identity={app.identity}
        session={app.session}
        state={app.state}
        create={app.create}
        link={app.link}
        reset={app.reset}
      />
    </>
  );
}
