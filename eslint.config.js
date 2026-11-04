import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    files: ["app/static/*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: Object.fromEntries(
        [
          "document",
          "window",
          "localStorage",
          "console",
          "fetch",
          "FormData",
          "Blob",
          "URL",
          "crypto",
          "AbortSignal",
          "AbortController",
          "queueMicrotask",
          "structuredClone",
          "setTimeout",
          "clearTimeout",
          "setInterval",
          "clearInterval",
        ].map((name) => [name, "readonly"]),
      ),
    },
    rules: { "no-unused-vars": ["error", { caughtErrors: "none" }] },
  },
];
