import assert from "node:assert/strict";
import { test } from "node:test";
import { decodeBase64Url } from "./base64.ts";
import { Client } from "./client.ts";
import { IdentityKey } from "./identity.ts";
import { proofMessage, proveIdentity } from "./proof.ts";
import { WebSocketTransport } from "./socket.ts";
import { freePort, startServer, track, useServer, waitFor } from "./testing.ts";

useServer();

async function connected(port: number): Promise<Client> {
  const client = track(
    new Client(
      track(
        new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, { minDelay: 50 }),
      ),
    ),
  );
  client.open();
  await waitFor(client, "connected");
  return client;
}

async function challenge(client: Client): Promise<Uint8Array> {
  const reply = await client.request({ type: "challenge", payload: {} });
  assert.ok(reply?.type === "challenge");
  const nonce = decodeBase64Url(reply.payload.nonce, 32);
  assert.ok(nonce);
  return nonce;
}

test("builds a deterministic domain-separated proof message", () => {
  const nonce = Uint8Array.from({ length: 32 }, (_, i) => i);
  const message = proofMessage(nonce);

  assert.equal(
    new TextDecoder().decode(message.slice(0, 25)),
    "ghostx/identity/proof/v1\0",
  );
  assert.deepEqual(message.slice(25), nonce);
  assert.deepEqual(proofMessage(nonce), message);
});

test("proves an identity to the server", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const key = await IdentityKey.generate();

  assert.equal(await proveIdentity(client, key), true);
  assert.equal(await proveIdentity(client, key), true);
});

test("proves independent identities concurrently", async () => {
  const port = await freePort();
  await startServer(port);
  const clients = await Promise.all([connected(port), connected(port)]);
  const keys = await Promise.all([
    IdentityKey.generate(),
    IdentityKey.generate(),
  ]);

  const results = await Promise.all(
    clients.map((client, i) => proveIdentity(client, keys[i])),
  );

  assert.deepEqual(results, [true, true]);
});

test("fails without a connection", async () => {
  const port = await freePort();
  const client = track(
    new Client(track(new WebSocketTransport(`ws://127.0.0.1:${port}/ws`))),
  );
  const key = await IdentityKey.generate();

  assert.equal(await proveIdentity(client, key), false);
});

test("fails with a released key", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const key = await IdentityKey.generate();
  key.release();

  assert.equal(await proveIdentity(client, key), false);
});

test("server rejects a signature from another key", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const [key, other] = await Promise.all([
    IdentityKey.generate(),
    IdentityKey.generate(),
  ]);

  const nonce = await challenge(client);
  const signature = await other.sign(proofMessage(nonce));
  assert.ok(signature);
  const reply = await client.request({
    type: "prove",
    payload: { identity: key.identity, signature },
  });

  assert.deepEqual(reply?.payload, { code: "invalid_proof" });
});

test("server rejects a replayed proof", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const key = await IdentityKey.generate();

  const nonce = await challenge(client);
  const signature = await key.sign(proofMessage(nonce));
  assert.ok(signature);
  const payload = { identity: key.identity, signature };

  const first = await client.request({ type: "prove", payload });
  const second = await client.request({ type: "prove", payload });

  assert.equal(first?.type, "proven");
  assert.deepEqual(second?.payload, { code: "invalid_proof" });
});

test("server rejects a malformed identity", async () => {
  const port = await freePort();
  await startServer(port);
  const client = await connected(port);
  const key = await IdentityKey.generate();

  const nonce = await challenge(client);
  const signature = await key.sign(proofMessage(nonce));
  assert.ok(signature);
  const reply = await client.request({
    type: "prove",
    payload: { identity: key.identity + "A", signature },
  });

  assert.deepEqual(reply?.payload, { code: "invalid_payload" });
  assert.equal(client.state, "connected");
});
