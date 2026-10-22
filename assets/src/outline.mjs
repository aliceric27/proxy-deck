// Turns the text of the editable masters (assets/src/hero*.svg) into outlines, writing assets/hero*.svg,
// so the artwork looks the same everywhere instead of depending on the viewer's installed fonts.
//
//   cd assets/src; npm install; node outline.mjs <fonts dir>
//
// The fonts dir holds these OFL fonts (not in git):
//   Inter-Regular.ttf, Inter-SemiBold.ttf, Inter-Bold.ttf   https://github.com/rsms/inter/releases (v4.1, extras/ttf/)
//   NotoSansTC-Regular.otf, NotoSansTC-Medium.otf, NotoSansTC-Bold.otf
//                                                           https://github.com/notofonts/noto-cjk (Sans/SubsetOTF/TC/)
//   JetBrainsMono-Regular.ttf                               https://github.com/JetBrains/JetBrainsMono/releases (v2.304)
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import opentype from "opentype.js";
import { DOMParser, XMLSerializer } from "@xmldom/xmldom";

const fontsDir = process.argv[2];
if (!fontsDir) throw new Error("usage: node outline.mjs <fonts dir>");
const load = (f) => opentype.parse(readFileSync(join(fontsDir, f)).buffer);
const inter = { 400: load("Inter-Regular.ttf"), 600: load("Inter-SemiBold.ttf"), 700: load("Inter-Bold.ttf") };
const noto = { 400: load("NotoSansTC-Regular.otf"), 600: load("NotoSansTC-Medium.otf"), 700: load("NotoSansTC-Bold.otf") };
const mono = load("JetBrainsMono-Regular.ttf");

// The masters' CSS classes, which outrank presentation attributes.
const CLASS_PROPS = { caps: { "font-size": "12", "font-weight": "600", "letter-spacing": "2.4", fill: "#5f8187" } };
const INHERITED = ["font-size", "font-weight", "fill", "text-anchor", "letter-spacing"];

function props(el) {
  const chain = [];
  for (let n = el; n && n.nodeType === 1; n = n.parentNode) chain.unshift(n);
  const p = { "font-size": "16", "font-weight": "400", fill: "#000", "text-anchor": "start", "letter-spacing": "0", classes: new Set() };
  for (const n of chain) {
    const classes = (n.getAttribute("class") || "").split(/\s+/).filter(Boolean);
    classes.forEach((c) => p.classes.add(c));
    for (const k of INHERITED) if (n.hasAttribute(k)) p[k] = n.getAttribute(k);
    for (const c of classes) Object.assign(p, CLASS_PROPS[c]);
  }
  return p;
}

const isCjk = (ch) => /[⺀-鿿豈-﫿＀-￯　-〿]/.test(ch);

// One run of text at (x, y) → path data, laid out like a browser: per-font kerning, letter-spacing after every character.
function outline(text, x, y, p) {
  const size = Number(p["font-size"]);
  const spacing = Number(p["letter-spacing"]);
  const weight = Number(p["font-weight"]) >= 700 ? 700 : Number(p["font-weight"]) >= 600 ? 600 : 400;
  const pick = (ch) => {
    const f = p.classes.has("mono") ? mono : inter[weight];
    return isCjk(ch) || f.charToGlyphIndex(ch) === 0 ? noto[weight] : f;
  };
  const glyphs = [...text].map((ch) => ({ font: pick(ch), ch }));
  let width = 0;
  const placed = glyphs.map((g, i) => {
    const glyph = g.font.charToGlyph(g.ch);
    const scale = size / g.font.unitsPerEm;
    const at = width;
    width += glyph.advanceWidth * scale + spacing;
    const next = glyphs[i + 1];
    if (next && next.font === g.font) width += g.font.getKerningValue(glyph, next.font.charToGlyph(next.ch)) * scale;
    return { glyph, at };
  });
  const shift = p["text-anchor"] === "middle" ? -width / 2 : p["text-anchor"] === "end" ? -width : 0;
  return placed.map(({ glyph, at }) => glyph.getPath(x + shift + at, y, size).toPathData(2)).join("");
}

function convert(src, out) {
  const doc = new DOMParser().parseFromString(readFileSync(src, "utf8"), "image/svg+xml");
  for (const text of Array.from(doc.getElementsByTagName("text"))) {
    const runs = Array.from(text.getElementsByTagName("tspan"));
    const p = props(text);
    const d = (runs.length ? runs : [text])
      .map((r) => outline(r.textContent, Number(r.getAttribute("x")), Number(r.getAttribute("y")), r === text ? p : { ...p, ...props(r) }))
      .join("");
    const path = doc.createElementNS("http://www.w3.org/2000/svg", "path");
    path.setAttribute("d", d);
    path.setAttribute("fill", p.fill);
    text.parentNode.replaceChild(path, text);
  }
  // Font classes have nothing left to style.
  const style = doc.getElementsByTagName("style")[0];
  style.textContent = style.textContent.replace(/^[ \t]*\.(sans|mono|caps) \{[^}]*\}\n/gm, "");
  writeFileSync(out, new XMLSerializer().serializeToString(doc) + "\n");
}

convert("hero.svg", "../hero.svg");
convert("hero.zh-TW.svg", "../hero.zh-TW.svg");
