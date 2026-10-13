import assert from "node:assert/strict";
import { test } from "node:test";
import { pairAddress } from "./pairs.ts";
import { poolSize } from "./prekeys.ts";
import {
  freePort,
  linkedDevice,
  peerCarrier,
  peerDevice,
  secureDevice,
  sleep,
  startServer,
  useServer,
} from "./testing.ts";

useServer();

async function until(predicate: () => boolean, what: string): Promise<void> {
  const deadline = Date.now() + 8000;
  while (!predicate()) {
    if (Date.now() > deadline) {
      throw new Error(`timed out waiting for ${what}`);
    }
    await sleep(5);
  }
}

function published(frames: string[]): number[] {
  return frames
    .map(
      (f) =>
        JSON.parse(f) as {
          type: string;
          payload: { onetime?: { id: number }[] };
        },
    )
    .filter((f) => f.type === "prekeys")
    .flatMap((f) => (f.payload.onetime ?? []).map((p) => p.id));
}

test("a one-time prekey handed out on a direct link is never also owned by the server", async () => {
  const port = await freePort();
  await startServer(port);
  const b = await secureDevice(port);
  const serverPool = published(b.sent);
  assert.equal(serverPool.length, poolSize);

  const carrier = await peerCarrier();
  const a = await peerDevice(carrier.listen);
  const direct = await peerDevice(carrier.dial, { store: b.store });
  await until(
    () =>
      a.endpoint.state === "authenticated" &&
      direct.endpoint.state === "authenticated",
    "direct session",
  );
  const consumed: (number | null)[] = [];
  const initiate = a.endpoint.initiate.bind(a.endpoint);
  a.endpoint.initiate = (initiation) => {
    consumed.push(initiation.onetime);
    return initiate(initiation);
  };
  assert.ok((await a.messenger.send(b.id, "direct first")).ok);
  await until(
    () => direct.inbox.some((m) => m.body === "direct first"),
    "direct",
  );
  assert.equal(consumed.length, 1);
  const used = consumed[0];
  assert.ok(used !== null, "the direct link offers a one-time prekey");
  assert.ok(
    !serverPool.includes(used),
    "the direct link never hands out a prekey published to the server",
  );

  const drain = await secureDevice(port);
  const ahead = serverPool.includes(used) ? serverPool.indexOf(used) : 0;
  for (let i = 0; i < ahead; i++) {
    const reply = await drain.client.request({
      type: "bundle",
      payload: { identity: b.id },
    });
    assert.ok(reply?.type === "bundle" && reply.payload.bundles[0].onetime);
  }
  const c = await secureDevice(port);
  const sent = await c.messenger.send(b.id, "through the server");
  assert.deepEqual(sent, { ok: true, devices: 1, pending: 0 });
  await until(
    () => b.inbox.some((m) => m.body === "through the server"),
    "server-mediated establishment with the last published prekey",
  );
  assert.equal(c.pairs.state(pairAddress(b.id, b.deviceId)), "established");
});

test("an authoritative sync confirms the basis and a server-learned revocation is enforced directly", async () => {
  const port = await freePort();
  await startServer(port);
  const b1 = await secureDevice(port);
  const b2 = await linkedDevice(port, b1);
  const a = await secureDevice(port);
  assert.ok(await a.messenger.lookup(b1.id));
  assert.equal(a.trust.confirmation(b1.id)?.version, 2);
  await a.shutdown();

  const carrier = await peerCarrier();
  const direct = await peerDevice(carrier.listen, { store: a.store });
  const linked = await peerDevice(carrier.dial, { store: b2.store });
  await until(
    () =>
      direct.endpoint.state === "authenticated" &&
      linked.endpoint.state === "authenticated",
    "direct session",
  );
  assert.equal(direct.endpoint.authorization?.basis, "confirmed");
  assert.equal(direct.endpoint.authorization?.roster, 2);
  linked.endpoint.close();
  await direct.shutdown();

  assert.ok((await b1.devices.revoke(b1.client, b2.deviceId)).ok);
  const online = await secureDevice(port, { store: a.store });
  assert.ok(await online.messenger.lookup(b1.id));
  assert.equal(online.trust.pinned(b1.id), 3);
  assert.equal(online.trust.confirmation(b1.id)?.version, 3);
  await online.shutdown();

  const offline = await peerDevice(carrier.listen, { store: a.store });
  const revoked = await peerDevice(carrier.dial, { store: b2.store });
  await until(
    () => offline.endpoint.state === "failed",
    "revoked device rejected",
  );
  assert.equal(offline.endpoint.failure, "stale");
  await until(
    () => revoked.transport.state !== "connected",
    "revoked device disconnected",
  );
  assert.notEqual(revoked.endpoint.state, "authenticated");
  assert.deepEqual(await revoked.messenger.send(a.id, "after revocation"), {
    ok: false,
    reason: "authentication_required",
  });
});
