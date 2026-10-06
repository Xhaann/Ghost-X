import {
  decodeBase64Url,
  decodeBase64UrlRange,
  encodeBase64Url,
} from "./base64.ts";
import { isCanonicalExchangeKey } from "./fingerprint.ts";
import { type IdentityKey, parseIdentity, verify } from "./identity.ts";
import {
  exchangeKeySize,
  ivSize,
  maxCiphertextSize,
  minCiphertextSize,
  saltSize,
} from "./protocol.ts";

const exchange = { name: "X25519" };
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const keyContext = encoder.encode("ghostx/encryption/key/v1\0");
const messageContext = encoder.encode("ghostx/message/v1\0");

export type KeyBundle = { identity: string; key: string; signature: string };

export type Sealed = { salt: string; iv: string; ciphertext: string };

export type Parties = {
  id: string;
  from: string;
  to: string;
  fromKey: Uint8Array<ArrayBuffer>;
  toKey: Uint8Array<ArrayBuffer>;
};

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

export function keyBindingMessage(
  identity: string,
  key: Uint8Array,
): Uint8Array<ArrayBuffer> {
  return concat(keyContext, encoder.encode(identity), key);
}

function identities(parties: Parties): [Uint8Array, Uint8Array] | null {
  const from = parseIdentity(parties.from);
  const to = parseIdentity(parties.to);
  return from && to ? [from, to] : null;
}

export function associatedData(
  parties: Parties,
): Uint8Array<ArrayBuffer> | null {
  const ids = identities(parties);
  const id = encoder.encode(parties.id);
  if (!ids || id.length === 0 || id.length > 64) {
    return null;
  }
  return concat(messageContext, Uint8Array.of(id.length), id, ids[0], ids[1]);
}

function derivationInfo(parties: Parties): Uint8Array<ArrayBuffer> | null {
  const ids = identities(parties);
  if (
    !ids ||
    parties.fromKey.length !== exchangeKeySize ||
    parties.toKey.length !== exchangeKeySize
  ) {
    return null;
  }
  return concat(messageContext, ids[0], ids[1], parties.fromKey, parties.toKey);
}

export async function verifyBundle(
  bundle: KeyBundle,
): Promise<Uint8Array<ArrayBuffer> | null> {
  const key = decodeBase64Url(bundle.key, exchangeKeySize);
  if (!key || !isCanonicalExchangeKey(key)) {
    return null;
  }
  const valid = await verify(
    bundle.identity,
    keyBindingMessage(bundle.identity, key),
    bundle.signature,
  );
  return valid ? key : null;
}

export class ExchangeKey {
  readonly publicKey: string;
  readonly #publicRaw: Uint8Array<ArrayBuffer>;
  #privateKey: CryptoKey | null;

  private constructor(
    publicRaw: Uint8Array<ArrayBuffer>,
    privateKey: CryptoKey,
  ) {
    this.#publicRaw = publicRaw;
    this.publicKey = encodeBase64Url(publicRaw);
    this.#privateKey = privateKey;
  }

  static async generate(): Promise<ExchangeKey> {
    return (await ExchangeKey.create()).key;
  }

  static async create(): Promise<{
    key: ExchangeKey;
    privateKey: CryptoKey;
  }> {
    const pair = (await crypto.subtle.generateKey(exchange, false, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const raw = new Uint8Array(
      await crypto.subtle.exportKey("raw", pair.publicKey),
    );
    return {
      key: new ExchangeKey(raw, pair.privateKey),
      privateKey: pair.privateKey,
    };
  }

  static async restore(
    publicKey: unknown,
    privateKey: unknown,
  ): Promise<ExchangeKey | null> {
    const raw = decodeBase64Url(publicKey, exchangeKeySize);
    if (
      !raw ||
      !(privateKey instanceof CryptoKey) ||
      privateKey.type !== "private" ||
      privateKey.extractable ||
      privateKey.algorithm.name !== exchange.name ||
      !privateKey.usages.includes("deriveBits")
    ) {
      return null;
    }
    try {
      const probe = (await crypto.subtle.generateKey(exchange, false, [
        "deriveBits",
      ])) as CryptoKeyPair;
      const own = await crypto.subtle.importKey(
        "raw",
        raw,
        exchange,
        false,
        [],
      );
      const forward = new Uint8Array(
        await crypto.subtle.deriveBits(
          { name: "X25519", public: probe.publicKey },
          privateKey,
          256,
        ),
      );
      const backward = new Uint8Array(
        await crypto.subtle.deriveBits(
          { name: "X25519", public: own },
          probe.privateKey,
          256,
        ),
      );
      return same(forward, backward) ? new ExchangeKey(raw, privateKey) : null;
    } catch {
      return null;
    }
  }

  get publicRaw(): Uint8Array<ArrayBuffer> {
    return this.#publicRaw.slice();
  }

  get released(): boolean {
    return this.#privateKey === null;
  }

  release(): void {
    this.#privateKey = null;
  }

  async bind(identity: IdentityKey): Promise<KeyBundle | null> {
    const signature = await identity.sign(
      keyBindingMessage(identity.identity, this.#publicRaw),
    );
    return signature
      ? { identity: identity.identity, key: this.publicKey, signature }
      : null;
  }

  async agree(
    peer: Uint8Array<ArrayBuffer>,
  ): Promise<Uint8Array<ArrayBuffer> | null> {
    const privateKey = this.#privateKey;
    if (!privateKey || peer.length !== exchangeKeySize) {
      return null;
    }
    try {
      const peerKey = await crypto.subtle.importKey(
        "raw",
        peer,
        exchange,
        false,
        [],
      );
      return new Uint8Array(
        await crypto.subtle.deriveBits(
          { name: "X25519", public: peerKey },
          privateKey,
          256,
        ),
      );
    } catch {
      return null;
    }
  }

  async openLegacy(parties: Parties, sealed: Sealed): Promise<string | null> {
    if (same(parties.toKey, this.#publicRaw)) {
      return this.#decrypt(parties, parties.fromKey, sealed);
    }
    if (same(parties.fromKey, this.#publicRaw)) {
      return this.#decrypt(parties, parties.toKey, sealed);
    }
    return null;
  }

  async #decrypt(
    parties: Parties,
    peer: Uint8Array<ArrayBuffer>,
    sealed: Sealed,
  ): Promise<string | null> {
    try {
      const salt = decodeBase64Url(sealed.salt, saltSize);
      const iv = decodeBase64Url(sealed.iv, ivSize);
      const ciphertext = decodeBase64UrlRange(
        sealed.ciphertext,
        minCiphertextSize,
        maxCiphertextSize,
      );
      const additionalData = associatedData(parties);
      if (!salt || !iv || !ciphertext || !additionalData) {
        return null;
      }
      const key = await this.#messageKey(parties, peer, salt, "decrypt");
      if (!key) {
        return null;
      }
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData },
        key,
        ciphertext,
      );
      return decoder.decode(plaintext);
    } catch {
      return null;
    }
  }

  async #messageKey(
    parties: Parties,
    peer: Uint8Array<ArrayBuffer>,
    salt: Uint8Array<ArrayBuffer>,
    usage: "encrypt" | "decrypt",
  ): Promise<CryptoKey | null> {
    const privateKey = this.#privateKey;
    const info = derivationInfo(parties);
    if (!privateKey || !info) {
      return null;
    }
    const peerKey = await crypto.subtle.importKey(
      "raw",
      peer,
      exchange,
      false,
      [],
    );
    const shared = await crypto.subtle.deriveBits(
      { name: "X25519", public: peerKey },
      privateKey,
      256,
    );
    const material = await crypto.subtle.importKey(
      "raw",
      shared,
      "HKDF",
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      [usage],
    );
  }
}
