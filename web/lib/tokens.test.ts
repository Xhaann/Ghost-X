import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const css = readFileSync(
  new URL("../app/globals.css", import.meta.url),
  "utf8",
);

function block(source: string, start: number): string {
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < source.length; i++) {
    if (source[i] === "{") {
      depth += 1;
    } else if (source[i] === "}" && --depth === 0) {
      return source.slice(open + 1, i);
    }
  }
  throw new Error(`unterminated block at ${start}`);
}

function declarations(body: string): Record<string, string> {
  return Object.fromEntries(
    [...body.matchAll(/--([a-z-]+):\s*([^;]+);/gi)].map((m) => [
      m[1],
      m[2].trim(),
    ]),
  );
}

function resolve(
  declared: Record<string, string>,
  name: string,
  seen: readonly string[] = [],
): string | null {
  const value = declared[name];
  if (value === undefined || seen.includes(name)) {
    return null;
  }
  const reference = /^var\(--([a-z-]+)\)$/i.exec(value);
  if (reference) {
    return resolve(declared, reference[1], [...seen, name]);
  }
  return /^#[0-9a-f]{6}$/i.test(value) ? value.toLowerCase() : null;
}

function tokens(declared: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.keys(declared).flatMap((name) => {
      const value = resolve(declared, name);
      return value ? [[name, value]] : [];
    }),
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

const rootAt = css.indexOf(":root");
const schemeAt = css.indexOf("@media (prefers-color-scheme: dark)");
const schemeBody = block(css, schemeAt);
const lightDeclared = declarations(block(css, rootAt));
const darkDeclared = declarations(
  block(schemeBody, schemeBody.indexOf(":root")),
);
const light = tokens(lightDeclared);
const dark = tokens({ ...lightDeclared, ...darkDeclared });
const themes = { light, dark };
const surfaces = ["surface", "surface-muted", "bg"];
const tints = [
  "accent-soft",
  "progress-soft",
  "warning-soft",
  "danger-soft",
  "success-soft",
];
const statuses = ["success", "warning", "danger", "progress"];

function reaches(
  minimum: number,
  foregrounds: readonly string[],
  backgrounds: readonly string[],
): void {
  for (const [name, theme] of Object.entries(themes)) {
    for (const foreground of foregrounds) {
      for (const background of backgrounds) {
        const a = theme[foreground];
        const b = theme[background];
        assert.ok(a, `${name} ${foreground} does not resolve to a colour`);
        assert.ok(b, `${name} ${background} does not resolve to a colour`);
        const ratio = contrast(a, b);
        assert.ok(
          ratio >= minimum,
          `${name} ${foreground} on ${background}: ${ratio}`,
        );
      }
    }
  }
}

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

test("themes come only from the root block and the dark-scheme root block", () => {
  assert.ok(rootAt >= 0 && rootAt < css.indexOf("@media"));
  assert.ok(schemeAt > rootAt);
  assert.ok(schemeBody.includes(":root"));
  const sample =
    ":root { --a: #000000; } @media (prefers-color-scheme: dark) { :root { --a: #111111; } } .later { --a: #222222; }";
  const scheme = block(sample, sample.indexOf("@media"));
  assert.deepEqual(declarations(block(sample, 0)), { a: "#000000" });
  assert.deepEqual(declarations(block(scheme, scheme.indexOf(":root"))), {
    a: "#111111",
  });
});

test("token references resolve to colours within each theme", () => {
  assert.equal(light.field, light.surface);
  assert.equal(dark.field, dark.bg);
  assert.equal(resolve({ a: "var(--b)", b: "var(--a)" }, "a"), null);
});

test("every light colour token is redefined with a different dark value", () => {
  const colours = Object.keys(light);
  assert.ok(colours.length > 0);
  for (const name of colours) {
    assert.ok(name in darkDeclared, `dark theme does not redefine ${name}`);
    assert.notEqual(
      dark[name],
      light[name],
      `${name} is identical in both themes`,
    );
  }
});

test("control boundaries reach 3:1 against tinted backgrounds and input fields", () => {
  reaches(3, ["border-strong"], [...tints, "field"]);
});

test("accent and danger boundaries and fills reach 3:1 against the surfaces they sit on", () => {
  reaches(3, ["accent"], [...surfaces, ...tints]);
  reaches(3, ["danger"], [...surfaces, "danger-soft", "field"]);
});

test("text on accent and danger fills reaches 4.5:1", () => {
  reaches(4.5, ["accent-text"], ["accent"]);
  reaches(4.5, ["surface"], ["danger"]);
});

test("accent text reaches 4.5:1 against every surface", () => {
  reaches(4.5, ["accent"], surfaces);
});

test("body and muted text reach 4.5:1 on message bubbles and accent-soft", () => {
  reaches(4.5, ["text", "text-muted"], ["sent", "received", "accent-soft"]);
});

test("status text reaches 4.5:1 on its tinted background and on surfaces", () => {
  for (const status of statuses) {
    reaches(4.5, [status], [`${status}-soft`, "surface", "surface-muted"]);
    reaches(4.5, ["text"], [`${status}-soft`]);
  }
});
