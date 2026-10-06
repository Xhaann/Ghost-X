const alphabet = /^[A-Za-z0-9_-]*$/;

export function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

function encodedLength(size: number): number {
  return Math.ceil((size * 4) / 3);
}

function decode(text: string): Uint8Array<ArrayBuffer> | null {
  if (!alphabet.test(text)) {
    return null;
  }
  let binary: string;
  try {
    binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  return encodeBase64Url(bytes) === text ? bytes : null;
}

export function decodeBase64Url(
  text: unknown,
  size: number,
): Uint8Array<ArrayBuffer> | null {
  if (typeof text !== "string" || text.length !== encodedLength(size)) {
    return null;
  }
  const bytes = decode(text);
  return bytes && bytes.length === size ? bytes : null;
}

export function decodeBase64UrlRange(
  text: unknown,
  min: number,
  max: number,
): Uint8Array<ArrayBuffer> | null {
  if (
    typeof text !== "string" ||
    text.length < encodedLength(min) ||
    text.length > encodedLength(max)
  ) {
    return null;
  }
  const bytes = decode(text);
  return bytes && bytes.length >= min && bytes.length <= max ? bytes : null;
}
