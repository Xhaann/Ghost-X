import { decodeBase64Url, encodeBase64Url } from "./base64.ts";

const algorithm = { name: "Ed25519" };
const publicKeySize = 32;
const signatureSize = 64;

export function parseIdentity(text: unknown): Uint8Array<ArrayBuffer> | null {
  return decodeBase64Url(text, publicKeySize);
}

export function isIdentity(text: unknown): text is string {
  return parseIdentity(text) !== null;
}

export class IdentityKey {
  readonly identity: string;
  #privateKey: CryptoKey | null;

  private constructor(identity: string, privateKey: CryptoKey) {
    this.identity = identity;
    this.#privateKey = privateKey;
  }

  static async generate(): Promise<IdentityKey> {
    const pair = (await crypto.subtle.generateKey(algorithm, false, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    const raw = await crypto.subtle.exportKey("raw", pair.publicKey);
    return new IdentityKey(
      encodeBase64Url(new Uint8Array(raw)),
      pair.privateKey,
    );
  }

  get released(): boolean {
    return this.#privateKey === null;
  }

  async sign(data: Uint8Array<ArrayBuffer>): Promise<string | null> {
    const privateKey = this.#privateKey;
    if (!privateKey) {
      return null;
    }
    const signature = await crypto.subtle.sign(algorithm, privateKey, data);
    return encodeBase64Url(new Uint8Array(signature));
  }

  release(): void {
    this.#privateKey = null;
  }
}

export async function verify(
  identity: unknown,
  data: Uint8Array<ArrayBuffer>,
  signature: unknown,
): Promise<boolean> {
  const key = parseIdentity(identity);
  const sig = decodeBase64Url(signature, signatureSize);
  if (!key || !sig) {
    return false;
  }
  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      key,
      algorithm,
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(algorithm, publicKey, sig, data);
  } catch {
    return false;
  }
}
