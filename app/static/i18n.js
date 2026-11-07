import { messages } from "./messages.js";

let language = "ru";
const templates = new WeakMap();
const aliases = new Map();
const normalizedAliases = new Map();
const normalized = (value) => value.trim().replace(/\s+/g, " ");
for (const [source, pair] of Object.entries(messages)) {
  aliases.set(source, pair);
  normalizedAliases.set(normalized(source), pair);
  for (const value of pair) if (!aliases.has(value)) aliases.set(value, pair);
  for (const value of pair)
    if (!normalizedAliases.has(normalized(value)))
      normalizedAliases.set(normalized(value), pair);
}

export const getLanguage = () => language;
export const locale = () => (language === "en" ? "en-US" : "ru-RU");

/** Profile language is authoritative; no cookies or browser storage are needed. */
export function setLanguage(value) {
  const next = value === "en" ? "en" : "ru";
  const changed = language !== next;
  language = next;
  if (typeof document !== "undefined") document.documentElement.lang = next;
  return changed;
}

export function t(source, values = {}) {
  const text = String(source ?? "");
  const pair = aliases.get(text) || normalizedAliases.get(normalized(text));
  const translated = pair ? pair[language === "en" ? 1 : 0] : text;
  return translated.replace(/\{(\w+)\}/g, (token, key) =>
    Object.hasOwn(values, key) ? String(values[key]) : token,
  );
}

const tokenPattern = /\uE000(\d+)\uE001/g;
const prefixTokens = /^(?:\s|\uE000\d+\uE001)*/;
const suffixTokens = /(?:\s|\uE000\d+\uE001)*$/;

function messageSegment(text, transform) {
  const prefix = text.match(prefixTokens)[0];
  const suffix = text.match(suffixTokens)[0];
  const end = text.length - suffix.length;
  if (end <= prefix.length) return text;
  const tokens = [];
  const source = normalized(
    text.slice(prefix.length, end).replace(tokenPattern, (token) => {
      tokens.push(token);
      return `{${tokens.length - 1}}`;
    }),
  );
  if (!/[\p{L}]/u.test(source)) return text;
  const result = transform(source)
    .trim()
    .replace(/\{(\d+)\}/g, (token, index) => tokens[index] ?? token);
  return prefix + result + suffix;
}

/** Translate only developer-authored text and accessible labels, never form values,
 * identifiers, URLs, CSS classes or interpolated configuration/host data. Shared
 * with the catalog coverage check so newly added UI text cannot be missed. */
export function translateTemplate(source, transform) {
  let cursor = 0;
  let output = "";
  while (cursor < source.length) {
    const start = source.indexOf("<", cursor);
    if (start < 0) {
      output += messageSegment(source.slice(cursor), transform);
      break;
    }
    if (!/^<\/?[a-zA-Z!]/.test(source.slice(start))) {
      output += messageSegment(source.slice(cursor), transform);
      break;
    }
    output += messageSegment(source.slice(cursor, start), transform);
    let quote = "";
    let end = start + 1;
    for (; end < source.length; end++) {
      const char = source[end];
      if (quote) {
        if (char === quote) quote = "";
      } else if (char === '"' || char === "'") quote = char;
      else if (char === ">") break;
    }
    const tag = source
      .slice(start, end + 1)
      .replace(
        /\b(title|aria-label|placeholder|alt)=("([^"]*)"|'([^']*)')/g,
        (match, name, quoted, double, single) => {
          const mark = quoted[0];
          const translated = messageSegment(double ?? single, (key) =>
            transform(key).replace(
              mark === '"' ? /"/g : /'/g,
              mark === '"' ? "&quot;" : "&#39;",
            ),
          );
          return `${name}=${mark}${translated}${mark}`;
        },
      );
    output += tag;
    cursor = end + 1;
  }
  return output;
}

/** Cached tagged templates leave already escaped interpolations untouched. */
export function html(strings, ...values) {
  let compiled = templates.get(strings);
  if (!compiled) {
    const source = strings.reduce(
      (text, part, index) =>
        text + (index ? `\uE000${index - 1}\uE001` : "") + part,
      "",
    );
    compiled = { source };
    templates.set(strings, compiled);
  }
  compiled[language] ??= translateTemplate(compiled.source, t);
  return compiled[language].replace(tokenPattern, (_, index) =>
    String(values[index]),
  );
}
