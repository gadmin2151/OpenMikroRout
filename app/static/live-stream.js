import { t } from "./i18n.js";

/** Bounded NDJSON transport. Text is delivered as data, never inserted as HTML. */
export async function readDiagnosticStream(response, onEvent, signal) {
  if (
    !response.body ||
    !response.headers.get("content-type")?.startsWith("application/x-ndjson")
  )
    throw new Error(
      t("Сервер не поддерживает потоковый вывод. Обновите страницу."),
    );
  const reader = response.body.getReader();
  const decoder = new globalThis.TextDecoder();
  let buffer = "",
    bytes = 0,
    ended = false;
  const emit = (line) => {
    if (!line.trim()) return;
    const event = JSON.parse(line);
    if (
      !event ||
      !["started", "output", "completed", "error"].includes(event.type)
    )
      throw new Error(t("Некорректный ответ диагностики."));
    onEvent(event);
  };
  try {
    while (true) {
      if (signal?.aborted) throw new Error(t("Диагностика отменена"));
      const { value, done } = await reader.read();
      if (signal?.aborted) throw new Error(t("Диагностика отменена"));
      if (done) {
        ended = true;
        break;
      }
      bytes += value.byteLength;
      if (bytes > 1_048_576)
        throw new Error(t("Превышен лимит вывода диагностики."));
      buffer += decoder.decode(value, { stream: true });
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        emit(buffer.slice(0, index));
        buffer = buffer.slice(index + 1);
      }
      if (buffer.length > 262144)
        throw new Error(t("Превышен лимит вывода диагностики."));
    }
    buffer += decoder.decode();
    if (buffer.trim()) emit(buffer);
  } finally {
    try {
      if (!ended) await reader.cancel();
    } finally {
      reader.releaseLock();
    }
  }
}
