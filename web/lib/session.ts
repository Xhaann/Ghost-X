import {
  decodeBase64Url,
  decodeBase64UrlRange,
  encodeBase64Url,
} from "./base64.ts";
import type { ExchangeKey } from "./encryption.ts";
import { isCanonicalExchangeKey } from "./fingerprint.ts";
import { type IdentityKey, parseIdentity, verify } from "./identity.ts";
import {
  type WireEnvelope,
  type WireSession,
  exchangeKeySize,
  isEpoch,
  ivSize,
  maxCiphertextSize,
  maxEpoch,
  minCiphertextSize,
  saltSize,
  sessionIdSize,
} from "./protocol.ts";

const exchange = { name: "X25519" };
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const sessionContext = encoder.encode("ghostx/session/v1\0");
const messageContext = encoder.encode("ghostx/message/v2\0");

export type SessionBundle = WireSession;

export type Envelope = WireEnvelope;

export type Side = {
  identity: string;
  staticKey: Uint8Array<ArrayBuffer>;
  session: string;
  epoch: number;
  ephemeral: Uint8Array<ArrayBuffer>;
};

export type Transcript = { id: string; from: Side; to: Side };

export type Sealed = { salt: string; iv: string; ciphertext: string };

type EpochKey = {
  epoch: number;
  publicRaw: Uint8Array<ArrayBuffer>;
  privateKey: CryptoKey;
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

function u32(value: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

function sideParts(side: Side): {
  identity: Uint8Array<ArrayBuffer>;
  session: Uint8Array<ArrayBuffer>;
} | null {
  const identity = parseIdentity(side.identity);
  const session = decodeBase64Url(side.session, sessionIdSize);
  if (
    !identity ||
    !session ||
    !isEpoch(side.epoch) ||
    side.staticKey.length !== exchangeKeySize ||
    side.ephemeral.length !== exchangeKeySize
  ) {
    return null;
  }
  return { identity, session };
}

export function sessionBindingMessage(
  identity: string,
  staticKey: Uint8Array,
  session: string,
  epoch: number,
  key: Uint8Array,
): Uint8Array<ArrayBuffer> | null {
  const owner = parseIdentity(identity);
  const id = decodeBase64Url(session, sessionIdSize);
  if (
    !owner ||
    !id ||
    !isEpoch(epoch) ||
    staticKey.length !== exchangeKeySize ||
    key.length !== exchangeKeySize
  ) {
    return null;
  }
  return concat(sessionContext, owner, staticKey, id, u32(epoch), key);
}

export function derivationInfo(t: Transcript): Uint8Array<ArrayBuffer> | null {
  const from = sideParts(t.from);
  const to = sideParts(t.to);
  if (!from || !to) {
    return null;
  }
  return concat(
    messageContext,
    from.identity,
    to.identity,
    t.from.staticKey,
    t.to.staticKey,
    from.session,
    u32(t.from.epoch),
    t.from.ephemeral,
    to.session,
    u32(t.to.epoch),
    t.to.ephemeral,
  );
}

export function associatedData(t: Transcript): Uint8Array<ArrayBuffer> | null {
  const from = sideParts(t.from);
  const to = sideParts(t.to);
  const id = encoder.encode(t.id);
  if (!from || !to || id.length === 0 || id.length > 64) {
    return null;
  }
  return concat(
    messageContext,
    Uint8Array.of(id.length),
    id,
    from.identity,
    to.identity,
    from.session,
    u32(t.from.epoch),
    to.session,
    u32(t.to.epoch),
  );
}

export async function verifySession(
  identity: string,
  staticKey: Uint8Array,
  bundle: SessionBundle,
): Promise<Uint8Array<ArrayBuffer> | null> {
  const key = decodeBase64Url(bundle.key, exchangeKeySize);
  if (!key || !isCanonicalExchangeKey(key)) {
    return null;
  }
  const message = sessionBindingMessage(
    identity,
    staticKey,
    bundle.session,
    bundle.epoch,
    key,
  );
  if (!message) {
    return null;
  }
  return (await verify(identity, message, bundle.signature)) ? key : null;
}

async function messageKey(
  privateKey: CryptoKey,
  peer: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
  usage: "encrypt" | "decrypt",
): Promise<CryptoKey> {
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
  const material = await crypto.subtle.importKey("raw", shared, "HKDF", false, [
    "deriveKey",
  ]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

async function generate(epoch: number): Promise<EpochKey> {
  const pair = (await crypto.subtle.generateKey(exchange, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const publicRaw = new Uint8Array(
    await crypto.subtle.exportKey("raw", pair.publicKey),
  );
  return { epoch, publicRaw, privateKey: pair.privateKey };
}

export class SessionKeys {
  readonly session: string;
  #current: EpochKey | null;
  #previous: EpochKey | null = null;
  #pending: EpochKey | null = null;

  private constructor(session: string, current: EpochKey) {
    this.session = session;
    this.#current = current;
  }

  static async create(): Promise<SessionKeys> {
    const session = encodeBase64Url(
      crypto.getRandomValues(new Uint8Array(sessionIdSize)),
    );
    return new SessionKeys(session, await generate(0));
  }

  get destroyed(): boolean {
    return this.#current === null;
  }

  get current(): { epoch: number; key: Uint8Array<ArrayBuffer> } | null {
    const current = this.#current;
    return current
      ? { epoch: current.epoch, key: current.publicRaw.slice() }
      : null;
  }

  get epochs(): number[] {
    return [this.#previous, this.#current]
      .filter((key): key is EpochKey => key !== null)
      .map((key) => key.epoch);
  }

  async prepare(): Promise<number | null> {
    const current = this.#current;
    if (!current || current.epoch >= maxEpoch) {
      return null;
    }
    const pending = await generate(current.epoch + 1);
    if (this.#current !== current) {
      return null;
    }
    this.#pending = pending;
    return pending.epoch;
  }

  activate(epoch: number): boolean {
    const pending = this.#pending;
    const current = this.#current;
    if (!pending || !current || pending.epoch !== epoch) {
      return false;
    }
    this.#previous = current;
    this.#current = pending;
    this.#pending = null;
    return true;
  }

  discardPending(): void {
    this.#pending = null;
  }

  discardPrevious(): void {
    this.#previous = null;
  }

  destroy(): void {
    this.#current = null;
    this.#previous = null;
    this.#pending = null;
  }

  async bind(
    identity: IdentityKey,
    staticKey: ExchangeKey,
    which: "current" | "pending",
  ): Promise<SessionBundle | null> {
    const key = which === "current" ? this.#current : this.#pending;
    if (!key) {
      return null;
    }
    const message = sessionBindingMessage(
      identity.identity,
      staticKey.publicRaw,
      this.session,
      key.epoch,
      key.publicRaw,
    );
    const signature = message ? await identity.sign(message) : null;
    return signature
      ? {
          session: this.session,
          epoch: key.epoch,
          key: encodeBase64Url(key.publicRaw),
          signature,
        }
      : null;
  }

  async seal(t: Transcript, body: string): Promise<Sealed | null> {
    const own = [this.#current, this.#previous].find(
      (key) => key !== null && key.epoch === t.from.epoch,
    );
    if (
      !own ||
      t.from.session !== this.session ||
      !same(t.from.ephemeral, own.publicRaw)
    ) {
      return null;
    }
    try {
      const info = derivationInfo(t);
      const additionalData = associatedData(t);
      if (!info || !additionalData) {
        return null;
      }
      const salt = crypto.getRandomValues(new Uint8Array(saltSize));
      const iv = crypto.getRandomValues(new Uint8Array(ivSize));
      const key = await messageKey(
        own.privateKey,
        t.to.ephemeral,
        salt,
        info,
        "encrypt",
      );
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData },
        key,
        encoder.encode(body),
      );
      return {
        salt: encodeBase64Url(salt),
        iv: encodeBase64Url(iv),
        ciphertext: encodeBase64Url(new Uint8Array(ciphertext)),
      };
    } catch {
      return null;
    }
  }

  async open(t: Transcript, sealed: Sealed): Promise<string | null> {
    const own = [this.#current, this.#previous].find(
      (key) => key !== null && key.epoch === t.to.epoch,
    );
    if (
      !own ||
      t.to.session !== this.session ||
      !same(t.to.ephemeral, own.publicRaw)
    ) {
      return null;
    }
    try {
      const salt = decodeBase64Url(sealed.salt, saltSize);
      const iv = decodeBase64Url(sealed.iv, ivSize);
      const ciphertext = decodeBase64UrlRange(
        sealed.ciphertext,
        minCiphertextSize,
        maxCiphertextSize,
      );
      const info = derivationInfo(t);
      const additionalData = associatedData(t);
      if (!salt || !iv || !ciphertext || !info || !additionalData) {
        return null;
      }
      const key = await messageKey(
        own.privateKey,
        t.from.ephemeral,
        salt,
        info,
        "decrypt",
      );
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

  publicKeyOf(epoch: number): Uint8Array<ArrayBuffer> | null {
    const key = [this.#current, this.#previous].find(
      (k) => k !== null && k.epoch === epoch,
    );
    return key ? key.publicRaw.slice() : null;
  }
}
