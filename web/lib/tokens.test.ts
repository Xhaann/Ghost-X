import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const css = readFileSync(
  new URL("../app/globals.css", import.meta.url),
  "utf8",
);

function tokens(block: string): Record<string, string> {
  return Object.fromEntries(
    [...block.matchAll(/--([a-z-]+):\s*(#[0-9a-f]{6});/gi)].map((m) => [
      m[1],
      m[2].toLowerCase(),
    ]),
  );
}

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high + 0.05) / (low + 0.05);
}

const light = tokens(css.slice(0, css.indexOf("@media")));
const dark = {
  ...light,
  ...tokens(css.slice(css.indexOf("@media (prefers-color-scheme: dark)"))),
};
const themes = { light, dark };
const surfaces = ["surface", "surface-muted", "bg"];

test("both themes define every surface and boundary token", () => {
  for (const theme of Object.values(themes)) {
    for (const name of [...surfaces, "border-strong", "text", "text-muted"]) {
      assert.match(theme[name] ?? "", /^#[0-9a-f]{6}$/);
    }
  }
  assert.notEqual(light["border-strong"], dark["border-strong"]);
});

test("control boundaries reach 3:1 against every surface in both themes", () => {
  for (const [name, theme] of Object.entries(themes)) {
    for (const surface of surfaces) {
      const ratio = contrast(theme["border-strong"], theme[surface]);
      assert.ok(ratio >= 3, `${name} border-strong on ${surface}: ${ratio}`);
    }
  }
});

test("body and muted text reach 4.5:1 against every surface in both themes", () => {
  for (const [name, theme] of Object.entries(themes)) {
    for (const text of ["text", "text-muted"]) {
      for (const surface of surfaces) {
        const ratio = contrast(theme[text], theme[surface]);
        assert.ok(ratio >= 4.5, `${name} ${text} on ${surface}: ${ratio}`);
      }
    }
  }
});
