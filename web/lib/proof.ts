import type { Client } from "./client.ts";
import { decodeBase64Url } from "./base64.ts";
import type { IdentityKey } from "./identity.ts";
import { nonceSize } from "./protocol.ts";

const context = new TextEncoder().encode("ghostx/identity/proof/v1\0");

export function proofMessage(nonce: Uint8Array): Uint8Array<ArrayBuffer> {
  const message = new Uint8Array(context.length + nonce.length);
  message.set(context);
  message.set(nonce, context.length);
  return message;
}

export async function proveIdentity(
  client: Client,
  key: IdentityKey,
): Promise<boolean> {
  const challenge = await client.request({ type: "challenge", payload: {} });
  if (challenge?.type !== "challenge") {
    return false;
  }
  const nonce = decodeBase64Url(challenge.payload.nonce, nonceSize);
  if (!nonce) {
    return false;
  }
  const signature = await key.sign(proofMessage(nonce));
  if (!signature) {
    return false;
  }
  const reply = await client.request({
    type: "prove",
    payload: { identity: key.identity, signature },
  });
  return reply?.type === "proven" && reply.payload.identity === key.identity;
}
