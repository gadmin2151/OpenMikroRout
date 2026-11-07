import { t } from "./i18n.js";
import { casefold } from "./casefold.js";

export const queryLimits = Object.freeze({
  leaves: 16,
  nodes: 31,
  depth: 4,
  bytes: 4096,
  value: 128,
});
export const queryOperators = Object.freeze({
  text: ["eq", "neq", "contains", "not_contains", "empty", "not_empty"],
  enum: ["eq", "neq", "in", "not_in", "empty", "not_empty"],
  ipv4: ["eq", "neq", "in", "not_in", "empty", "not_empty"],
  ports: [
    "eq",
    "neq",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
    "empty",
    "not_empty",
  ],
  number: ["eq", "neq", "gt", "gte", "lt", "lte", "empty", "not_empty"],
});
export const operatorsForField = (field) =>
  (field.operators || queryOperators[field.type] || []).filter((op) =>
    queryOperators[field.type]?.includes(op),
  );
const negative = { neq: "eq", not_contains: "contains", not_in: "in" };
const scalar = (value) => value != null && value !== "";
const valuesOf = (raw) =>
  (Array.isArray(raw) ? raw.flat() : [raw]).filter(scalar);
const size = (text) => new globalThis.TextEncoder().encode(text).length;
const fail = (key = "Завершите все условия расширенного фильтра.") => {
  throw new Error(t(key));
};
const members = (text) => text.split(",").map((part) => part.trim());
const decimalPattern = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$/;
const inputDecimalPattern = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;

function decimal(value, input = false) {
  let text = String(value);
  if (!input) {
    if (typeof value === "number" && !Number.isFinite(value)) return null;
    const match = /^([+-]?)(\d+)(?:\.(\d*))?e([+-]?\d+)$/i.exec(text);
    if (match) {
      const digits = match[2] + (match[3] || ""),
        point = match[2].length + Number(match[4]);
      text =
        match[1] +
        (point <= 0
          ? `0.${"0".repeat(-point)}${digits}`
          : point >= digits.length
            ? digits + "0".repeat(point - digits.length)
            : `${digits.slice(0, point)}.${digits.slice(point)}`);
    }
  }
  if (
    text.length > 1024 ||
    !(input ? inputDecimalPattern : decimalPattern).test(text)
  )
    return null;
  const sign = text.startsWith("-") ? -1n : 1n;
  const [whole, fraction = ""] = text.replace(/^[+-]/, "").split(".");
  return {
    digits: sign * BigInt((whole || "0") + fraction),
    scale: fraction.length,
  };
}
function compareDecimals(left, right) {
  const scale = Math.max(left.scale, right.scale);
  const a = left.digits * 10n ** BigInt(scale - left.scale),
    b = right.digits * 10n ** BigInt(scale - right.scale);
  return a < b ? -1 : a > b ? 1 : 0;
}
function address(text) {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) return null;
  const parts = text.split(".");
  if (
    parts.some(
      (part) => Number(part) > 255 || (part.length > 1 && part.startsWith("0")),
    )
  )
    return null;
  return parts.reduce((number, part) => number * 256 + Number(part), 0);
}
function network(raw) {
  const text = String(raw).trim();
  const range = text.split("-").map((part) => part.trim());
  if (range.length === 2) {
    const low = address(range[0]),
      high = address(range[1]);
    return low !== null && high !== null && low <= high ? [low, high] : null;
  }
  const parts = text.split("/"),
    host = address(parts[0]);
  const prefix =
    parts.length === 1
      ? 32
      : /^\d{1,2}$/.test(parts[1])
        ? Number(parts[1])
        : -1;
  if (host === null || parts.length > 2 || prefix < 0 || prefix > 32)
    return null;
  const block = 2 ** (32 - prefix),
    low = Math.floor(host / block) * block;
  return [low, low + block - 1];
}
function ports(raw) {
  const text = String(raw).trim().replaceAll(" ", "").replaceAll(":", "-");
  const result = [];
  let slots = 0;
  for (const item of members(text)) {
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(item);
    if (!match) return null;
    const low = Number(match[1]),
      high = Number(match[2] || match[1]);
    if (low < 1 || high > 65535 || low > high) return null;
    slots += match[2] ? 2 : 1;
    if (slots > 15) return null;
    result.push([low, high]);
  }
  return result;
}
const overlap = (left, right) => left[0] <= right[1] && right[0] <= left[1];
const relation = (order, op) =>
  ({
    eq: order === 0,
    gt: order > 0,
    gte: order >= 0,
    lt: order < 0,
    lte: order <= 0,
  })[op] || false;
const needsNormalization = (op) => !["empty", "not_empty"].includes(op);
function typedValue(field, op, value) {
  if (["empty", "not_empty"].includes(op)) return null;
  const positive = negative[op] || op;
  if (field.type === "number")
    return (
      decimal(value, true) || fail("Укажите корректное число без экспоненты.")
    );
  if (field.type === "ports") {
    const parsed = ports(value);
    if (
      !parsed ||
      parsed.length > 16 ||
      (["gt", "gte", "lt", "lte"].includes(positive) &&
        (parsed.length !== 1 || parsed[0][0] !== parsed[0][1]))
    )
      fail("Укажите порт 1–65535 или список диапазонов портов.");
    return parsed;
  }
  if (field.type === "ipv4") {
    const parts = members(value),
      parsed = parts.map(network);
    if (
      parts.length > 16 ||
      parsed.some((part) => !part) ||
      (positive === "eq" &&
        (parts.length !== 1 || parsed[0][0] !== parsed[0][1])) ||
      parts.some((part) => part.includes("-"))
    )
      fail("Укажите IPv4-адрес или список подсетей CIDR.");
    return parsed;
  }
  if (field.type === "enum") {
    const parts = positive === "in" ? members(value) : [value];
    if (parts.length > 16 || parts.some((part) => !part)) fail();
    const choices = (field.options || []).map((option) =>
      casefold(Array.isArray(option) ? option[0] : option),
    );
    if (parts.some((part) => !choices.includes(casefold(part))))
      fail("Выберите значение из списка поля.");
    return parts.map(casefold);
  }
  return casefold(value);
}

/** Canonical bounded data only: fields and operators always come from the scope schema. */
export function validateQueryExpression(expression, schema) {
  if (expression == null || expression === "") return null;
  let source = expression;
  if (typeof source === "string") {
    if (size(source) > queryLimits.bytes)
      fail("Расширенный фильтр превышает допустимый размер.");
    try {
      source = JSON.parse(source);
    } catch {
      fail("Некорректный формат расширенного фильтра.");
    }
    const stack = [];
    for (let index = 0; index < expression.length; index++) {
      const char = expression[index];
      if (char === '"') {
        const start = index;
        while (++index < expression.length) {
          if (expression[index] === "\\") index++;
          else if (expression[index] === '"') break;
        }
        if (
          expression
            .slice(index + 1)
            .trimStart()
            .startsWith(":")
        ) {
          const key = JSON.parse(expression.slice(start, index + 1)),
            keys = stack.at(-1);
          if (keys?.has(key)) fail("Некорректный формат расширенного фильтра.");
          keys?.add(key);
        }
      } else if (char === "{") stack.push(new Set());
      else if (char === "[") stack.push(null);
      else if (char === "}" || char === "]") stack.pop();
    }
  }
  let encoded;
  try {
    encoded = JSON.stringify(source);
  } catch {
    fail("Некорректный формат расширенного фильтра.");
  }
  if (size(encoded) > queryLimits.bytes)
    fail("Расширенный фильтр превышает допустимый размер.");
  const fields = new Map(schema.map((field) => [field.field, field]));
  let count = 0,
    leaves = 0;
  const walk = (node, depth) => {
    if (!node || typeof node !== "object" || Array.isArray(node)) fail();
    if (++count > queryLimits.nodes || depth > queryLimits.depth)
      fail("Слишком сложный расширенный фильтр: до 16 условий и 4 уровней.");
    if (node.kind === "group") {
      if (
        !["and", "or"].includes(node.join) ||
        !Array.isArray(node.children) ||
        Object.keys(node).some(
          (key) => !["kind", "join", "children"].includes(key),
        )
      )
        fail();
      if (!node.children.length) {
        if (depth === 1) return null;
        fail();
      }
      return {
        kind: "group",
        join: node.join,
        children: node.children.map((child) => walk(child, depth + 1)),
      };
    }
    const field = fields.get(node.field);
    if (
      node.kind !== "condition" ||
      !field ||
      !operatorsForField(field).includes(node.op) ||
      Object.keys(node).some(
        (key) => !["kind", "field", "op", "value"].includes(key),
      ) ||
      (node.value !== undefined && typeof node.value !== "string")
    )
      fail();
    if (++leaves > queryLimits.leaves)
      fail("Слишком сложный расширенный фильтр: до 16 условий и 4 уровней.");
    let value = (node.value || "").trim();
    if (Array.from(node.value || "").length > queryLimits.value)
      fail("Значение условия длиннее 128 символов.");
    if (["empty", "not_empty"].includes(node.op)) {
      if (value) fail();
    } else if (!value) fail();
    typedValue(field, node.op, value);
    if (needsNormalization(node.op)) {
      if (field.type === "ports")
        value = value.replaceAll(" ", "").replaceAll(":", "-");
      else if (field.type === "ipv4") {
        const ranges = typedValue(field, node.op, value);
        const host = (number) =>
          [24, 16, 8, 0]
            .map((shift) => Math.floor(number / 2 ** shift) % 256)
            .join(".");
        value = ["eq", "neq"].includes(node.op)
          ? host(ranges[0][0])
          : [
              ...new Set(
                ranges.map(
                  ([low, high]) =>
                    `${host(low)}/${32 - Math.log2(high - low + 1)}`,
                ),
              ),
            ].join(",");
      } else if (field.type === "enum") {
        const options = new Map(
          (field.options || []).map((option) => {
            const key = Array.isArray(option) ? option[0] : option;
            return [casefold(key), key];
          }),
        );
        value = [
          ...new Set(
            (["in", "not_in"].includes(node.op) ? members(value) : [value]).map(
              (part) => options.get(casefold(part)),
            ),
          ),
        ].join(",");
      }
    }
    return { kind: "condition", field: node.field, op: node.op, value };
  };
  const result = walk(source, 1);
  if (size(JSON.stringify(result)) > queryLimits.bytes)
    fail("Расширенный фильтр превышает допустимый размер.");
  return result;
}

/** Compile typed values once for a list pass; never evaluate user code or property paths. */
export function compileQueryExpression(expression, schema) {
  const ast = validateQueryExpression(expression, schema);
  if (!ast) return () => true;
  const fields = new Map(schema.map((field) => [field.field, field]));
  const compile = (node) => {
    if (node.kind === "group") {
      const children = node.children.map(compile);
      return node.join === "and"
        ? (row, cache) => children.every((test) => test(row, cache))
        : (row, cache) => children.some((test) => test(row, cache));
    }
    const field = fields.get(node.field),
      op = negative[node.op] || node.op,
      expected = typedValue(field, node.op, node.value);
    const test = (actual) => {
      if (field.type === "number") {
        const value = decimal(actual);
        return !!value && relation(compareDecimals(value, expected), op);
      }
      if (field.type === "ipv4") {
        const ranges = String(actual).split(",").map(network).filter(Boolean);
        return ranges.some((range) =>
          expected.some((target) => overlap(range, target)),
        );
      }
      if (field.type === "ports") {
        const ranges =
          typeof actual === "number" &&
          Number.isInteger(actual) &&
          actual >= 0 &&
          actual <= 65535
            ? [[actual, actual]]
            : ports(actual);
        if (!ranges) return false;
        return ["eq", "in"].includes(op)
          ? ranges.some((range) =>
              expected.some((target) => overlap(range, target)),
            )
          : ranges.some((range) =>
              relation(range[op.startsWith("gt") ? 1 : 0] - expected[0][0], op),
            );
      }
      const text = casefold(actual);
      if (field.type === "enum") return expected.includes(text);
      return op === "contains" ? text.includes(expected) : text === expected;
    };
    return (row, cache) => {
      if (!cache.has(field.field))
        cache.set(
          field.field,
          valuesOf(
            field.get
              ? field.get(row)
              : Object.hasOwn(row, field.field)
                ? row[field.field]
                : null,
          ),
        );
      const values = cache.get(field.field);
      if (node.op === "empty") return values.length === 0;
      if (node.op === "not_empty") return values.length > 0;
      const matched = values.some(test);
      return Object.hasOwn(negative, node.op) ? !matched : matched;
    };
  };
  const predicate = compile(ast);
  return (row) => predicate(row, new Map());
}

export const matchesQueryExpression = (row, expression, schema) =>
  compileQueryExpression(expression, schema)(row);
