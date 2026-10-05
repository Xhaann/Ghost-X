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

export function decodeBase64Url(
  text: unknown,
  size: number,
): Uint8Array<ArrayBuffer> | null {
  if (
    typeof text !== "string" ||
    text.length !== Math.ceil((size * 4) / 3) ||
    !alphabet.test(text)
  ) {
    return null;
  }

  let binary: string;
  try {
    binary = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  } catch {
    return null;
  }

  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
  if (bytes.length !== size || encodeBase64Url(bytes) !== text) {
    return null;
  }
  return bytes;
}
