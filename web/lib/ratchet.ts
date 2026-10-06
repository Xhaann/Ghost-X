import { decodeBase64Url, encodeBase64Url } from "./base64.ts";
import { isCanonicalExchangeKey } from "./fingerprint.ts";
import { parseIdentity } from "./identity.ts";
import { exchangeKeySize, ratchetHeaderSize } from "./protocol.ts";

export const ratchetVersion = 1;
export const maxSkip = 100;
export const maxSkipped = 200;
export const headerSize = ratchetHeaderSize;

const encoder = new TextEncoder();
const rootInfo = encoder.encode("ghostx/ratchet/v1/root\0");
const messageInfo = encoder.encode("ghostx/ratchet/v1/message\0");
const adContext = encoder.encode("ghostx/ratchet/v1\0");
const messageConstant = Uint8Array.of(0x01);
const chainConstant = Uint8Array.of(0x02);
const exchange = { name: "X25519" };

export type Role = "initiator" | "responder";

export type Binding = {
  initiator: string;
  responder: string;
  session: string;
  role: Role;
};

export type RatchetKeyPair = {
  publicKey: Uint8Array<ArrayBuffer>;
  privateKey: CryptoKey;
};

export type Chain = { key: Uint8Array<ArrayBuffer>; n: number };

export type SkippedKey = {
  ratchet: string;
  n: number;
  key: Uint8Array<ArrayBuffer>;
};

export type RatchetState = {
  binding: Binding;
  root: Uint8Array<ArrayBuffer>;
  sending: Chain | null;
  receiving: Chain | null;
  previous: number;
  own: RatchetKeyPair;
  peer: Uint8Array<ArrayBuffer> | null;
  skipped: readonly SkippedKey[];
};

export type Header = {
  session: string;
  ratchet: Uint8Array<ArrayBuffer>;
  previous: number;
  n: number;
};

export type Generate = () => Promise<RatchetKeyPair>;

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

export async function generateRatchetKey(): Promise<RatchetKeyPair> {
  const pair = (await crypto.subtle.generateKey(exchange, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  return {
    publicKey: new Uint8Array(
      await crypto.subtle.exportKey("raw", pair.publicKey),
    ),
    privateKey: pair.privateKey,
  };
}

async function dh(
  privateKey: CryptoKey,
  peer: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey("raw", peer, exchange, false, []);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "X25519", public: key },
      privateKey,
      256,
    ),
  );
}

async function hkdf(
  ikm: Uint8Array<ArrayBuffer>,
  salt: Uint8Array<ArrayBuffer>,
  info: Uint8Array<ArrayBuffer>,
  bytes: number,
): Promise<Uint8Array<ArrayBuffer>> {
  const material = await crypto.subtle.importKey("raw", ikm, "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info },
      material,
      bytes * 8,
    ),
  );
}

async function hmac(
  key: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const imported = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, data));
}

export async function kdfRoot(
  root: Uint8Array<ArrayBuffer>,
  dhOutput: Uint8Array<ArrayBuffer>,
): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
  const out = await hkdf(dhOutput, root, rootInfo, 64);
  return [out.slice(0, 32), out.slice(32)];
}

export async function kdfChain(
  chain: Uint8Array<ArrayBuffer>,
): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
  const [next, message] = await Promise.all([
    hmac(chain, chainConstant),
    hmac(chain, messageConstant),
  ]);
  return [next, message];
}

export function encodeHeader(header: Header): Uint8Array<ArrayBuffer> | null {
  const session = decodeBase64Url(header.session, 16);
  if (!session || header.ratchet.length !== exchangeKeySize) {
    return null;
  }
  return concat(
    Uint8Array.of(ratchetVersion),
    session,
    header.ratchet,
    u32(header.previous),
    u32(header.n),
  );
}

export function decodeHeader(message: Uint8Array): Header | null {
  if (message.length < headerSize + 17 || message[0] !== ratchetVersion) {
    return null;
  }
  const view = new DataView(message.buffer, message.byteOffset);
  const ratchet = message.slice(17, 49);
  if (!isCanonicalExchangeKey(ratchet)) {
    return null;
  }
  return {
    session: encodeBase64Url(message.slice(1, 17)),
    ratchet,
    previous: view.getUint32(49),
    n: view.getUint32(53),
  };
}

export function associatedData(
  binding: Binding,
  sender: Role,
  header: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> | null {
  const initiator = parseIdentity(binding.initiator);
  const responder = parseIdentity(binding.responder);
  const session = decodeBase64Url(binding.session, 16);
  if (!initiator || !responder || !session) {
    return null;
  }
  return concat(
    adContext,
    initiator,
    responder,
    session,
    Uint8Array.of(sender === "initiator" ? 0 : 1),
    header,
  );
}

async function messageCipher(
  messageKey: Uint8Array<ArrayBuffer>,
  usage: "encrypt" | "decrypt",
): Promise<{ key: CryptoKey; iv: Uint8Array<ArrayBuffer> }> {
  const out = await hkdf(messageKey, new Uint8Array(32), messageInfo, 44);
  const key = await crypto.subtle.importKey(
    "raw",
    out.slice(0, 32),
    { name: "AES-GCM" },
    false,
    [usage],
  );
  return { key, iv: out.slice(32) };
}

export async function initiatorState(
  secret: Uint8Array<ArrayBuffer>,
  peer: Uint8Array<ArrayBuffer>,
  binding: Binding,
  own: RatchetKeyPair,
): Promise<RatchetState> {
  const [root, chain] = await kdfRoot(secret, await dh(own.privateKey, peer));
  return {
    binding,
    root,
    sending: { key: chain, n: 0 },
    receiving: null,
    previous: 0,
    own,
    peer,
    skipped: [],
  };
}

export async function responderState(
  secret: Uint8Array<ArrayBuffer>,
  own: RatchetKeyPair,
  peer: Uint8Array<ArrayBuffer>,
  binding: Binding,
  generate: Generate = generateRatchetKey,
): Promise<RatchetState> {
  return step(
    {
      binding,
      root: secret,
      sending: null,
      receiving: null,
      previous: 0,
      own,
      peer: null,
      skipped: [],
    },
    peer,
    generate,
  );
}

async function step(
  state: RatchetState,
  peer: Uint8Array<ArrayBuffer>,
  generate: Generate,
): Promise<RatchetState> {
  const [root1, receiving] = await kdfRoot(
    state.root,
    await dh(state.own.privateKey, peer),
  );
  const own = await generate();
  const [root2, sending] = await kdfRoot(root1, await dh(own.privateKey, peer));
  return {
    ...state,
    root: root2,
    previous: state.sending?.n ?? 0,
    sending: { key: sending, n: 0 },
    receiving: { key: receiving, n: 0 },
    own,
    peer,
  };
}

async function skip(
  state: RatchetState,
  until: number,
): Promise<RatchetState | null> {
  const receiving = state.receiving;
  if (!receiving || !state.peer) {
    return until === 0 ? state : null;
  }
  if (until < receiving.n) {
    return state;
  }
  if (until - receiving.n > maxSkip) {
    return null;
  }
  const ratchet = encodeBase64Url(state.peer);
  const skipped = [...state.skipped];
  let chain = receiving.key;
  let n = receiving.n;
  while (n < until) {
    const [next, key] = await kdfChain(chain);
    skipped.push({ ratchet, n, key });
    chain = next;
    n += 1;
  }
  return {
    ...state,
    receiving: { key: chain, n },
    skipped: skipped.slice(-maxSkipped),
  };
}

export async function ratchetEncrypt(
  state: RatchetState,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<{ state: RatchetState; message: Uint8Array<ArrayBuffer> } | null> {
  const sending = state.sending;
  if (!sending) {
    return null;
  }
  const [next, messageKey] = await kdfChain(sending.key);
  const header = encodeHeader({
    session: state.binding.session,
    ratchet: state.own.publicKey,
    previous: state.previous,
    n: sending.n,
  });
  const additionalData =
    header && associatedData(state.binding, state.binding.role, header);
  if (!header || !additionalData) {
    return null;
  }
  const { key, iv } = await messageCipher(messageKey, "encrypt");
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData },
      key,
      plaintext,
    ),
  );
  return {
    state: { ...state, sending: { key: next, n: sending.n + 1 } },
    message: concat(header, ciphertext),
  };
}

async function open(
  messageKey: Uint8Array<ArrayBuffer>,
  additionalData: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer> | null> {
  try {
    const { key, iv } = await messageCipher(messageKey, "decrypt");
    return new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData },
        key,
        ciphertext,
      ),
    );
  } catch {
    return null;
  }
}

export async function ratchetDecrypt(
  state: RatchetState,
  message: Uint8Array<ArrayBuffer>,
  generate: Generate = generateRatchetKey,
): Promise<{ state: RatchetState; plaintext: Uint8Array<ArrayBuffer> } | null> {
  try {
    const header = decodeHeader(message);
    if (!header || header.session !== state.binding.session) {
      return null;
    }
    const headerBytes = message.slice(0, headerSize);
    const ciphertext = message.slice(headerSize);
    const sender: Role =
      state.binding.role === "initiator" ? "responder" : "initiator";
    const additionalData = associatedData(state.binding, sender, headerBytes);
    if (!additionalData || same(header.ratchet, state.own.publicKey)) {
      return null;
    }
    const ratchet = encodeBase64Url(header.ratchet);
    const found = state.skipped.findIndex(
      (k) => k.ratchet === ratchet && k.n === header.n,
    );
    if (found >= 0) {
      const plaintext = await open(
        state.skipped[found].key,
        additionalData,
        ciphertext,
      );
      return plaintext
        ? {
            state: {
              ...state,
              skipped: state.skipped.filter((_, i) => i !== found),
            },
            plaintext,
          }
        : null;
    }
    let next: RatchetState | null = state;
    if (!state.peer || !same(header.ratchet, state.peer)) {
      next = await skip(state, header.previous);
      if (!next) {
        return null;
      }
      next = await step(next, header.ratchet, generate);
    } else if (state.receiving && header.n < state.receiving.n) {
      return null;
    }
    next = await skip(next, header.n);
    if (!next || !next.receiving) {
      return null;
    }
    const [chain, messageKey] = await kdfChain(next.receiving.key);
    const plaintext = await open(messageKey, additionalData, ciphertext);
    if (!plaintext) {
      return null;
    }
    return {
      state: {
        ...next,
        receiving: { key: chain, n: next.receiving.n + 1 },
      },
      plaintext,
    };
  } catch {
    return null;
  }
}
