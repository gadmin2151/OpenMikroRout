import { t } from "./i18n.js";

const OUTPUT_BYTES = 32768;
const outputEncoder = new globalThis.TextEncoder();
const outputDecoder = new globalThis.TextDecoder();
/** Keep the latest UTF-8 bytes without cutting a multibyte character. */
export function diagnosticOutputTail(value) {
  const bytes = outputEncoder.encode(value);
  if (bytes.byteLength <= OUTPUT_BYTES) return value;
  let start = bytes.byteLength - OUTPUT_BYTES;
  while ((bytes[start] & 0xc0) === 0x80) start++;
  return outputDecoder.decode(bytes.subarray(start));
}

const MAX_FRAME_BYTES = 262144;
const MAX_FINITE_STREAM_BYTES = 1048576;

/** NDJSON frames stay bounded even for an explicitly continuous Ping. Text is
 * delivered as data; neither protocol fields nor output are inserted as HTML. */
export async function readDiagnosticStream(
  response,
  onEvent,
  signal,
  { continuous = false } = {},
) {
  if (
    !response.body ||
    !response.headers.get("content-type")?.startsWith("application/x-ndjson")
  )
    throw new Error(
      t("Сервер не поддерживает потоковый вывод. Обновите страницу."),
    );
  const reader = response.body.getReader();
  const decoder = new globalThis.TextDecoder("utf-8", { fatal: true });
  let buffer = "",
    frameBytes = 0,
    bytes = 0,
    ended = false,
    terminal = false,
    started = false;
  const invalid = () => new Error(t("Некорректный ответ диагностики."));
  const emit = (line) => {
    if (!line.trim()) return;
    const event = JSON.parse(line);
    if (
      !event ||
      terminal ||
      !["started", "output", "completed", "error"].includes(event.type) ||
      (event.type === "started" && started) ||
      (event.type === "output" && typeof event.text !== "string") ||
      (event.type === "completed" &&
        (!event.result || typeof event.result.output !== "string"))
    )
      throw invalid();
    if (event.type === "started") started = true;
    if (["completed", "error"].includes(event.type)) terminal = true;
    onEvent(event);
  };
  const abort = () => {
    // Cancel wakes a blocked reader immediately. The abort is the final outcome;
    // a transport cancellation error must not become an unhandled rejection.
    void reader.cancel().catch(() => {});
  };
  signal?.addEventListener("abort", abort, { once: true });
  try {
    while (true) {
      if (signal?.aborted) throw new Error(t("Диагностика отменена"));
      const { value, done } = await reader.read();
      if (signal?.aborted) throw new Error(t("Диагностика отменена"));
      if (done) {
        ended = true;
        break;
      }
      if (!(value instanceof Uint8Array)) throw invalid();
      if (!continuous) {
        bytes += value.byteLength;
        if (bytes > MAX_FINITE_STREAM_BYTES)
          throw new Error(t("Превышен лимит вывода диагностики."));
      }
      // Decode one bounded frame at a time: a large chunk containing many valid
      // Ping lines must not allocate an equally large temporary string.
      for (let offset = 0; offset < value.byteLength;) {
        const newline = value.indexOf(10, offset);
        const end = newline < 0 ? value.byteLength : newline;
        const part = value.subarray(offset, end);
        frameBytes += part.byteLength;
        if (frameBytes > MAX_FRAME_BYTES)
          throw new Error(t("Превышен лимит вывода диагностики."));
        buffer += decoder.decode(part, { stream: true });
        if (newline < 0) break;
        buffer += decoder.decode();
        emit(buffer);
        buffer = "";
        frameBytes = 0;
        offset = newline + 1;
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) emit(buffer);
    if (!terminal)
      throw new Error(t("Поток диагностики прерван. Повторите проверку."));
  } finally {
    signal?.removeEventListener("abort", abort);
    try {
      if (!ended) await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
}
