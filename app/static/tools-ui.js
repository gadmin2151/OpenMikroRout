import { t, html } from "./i18n.js";
import { readDiagnosticStream, diagnosticOutputTail } from "./live-stream.js";
let result = null;
let active = null;
let liveOutput = "";
let liveMeta = "";
let input = { tool: "ping", target: "", port: "443" };
export function resetTools() {
  active?.abort();
  active = null;
  liveOutput = liveMeta = "";
  result = null;
  input = { tool: "ping", target: "", port: "443" };
}
const tools = [
  ["ping", t("Ping")],
  ["traceroute", t("Traceroute")],
  ["dns", t("DNS Lookup")],
  ["route", t("Route Lookup")],
  ["tcp", t("TCP Connect")],
];

export function handleToolsInput(event, ctx) {
  const form = event.target?.closest?.("#tools-form");
  if (!form) return false;
  const values = new FormData(form);
  input.tool = String(values.get("tool") || "ping");
  input.target = String(values.get("target") || "");
  if (values.has("port")) input.port = String(values.get("port"));
  const tcp = input.tool === "tcp";
  form.classList.toggle("is-tcp", tcp);
  form.querySelector(".tools-port").classList.toggle("hidden", !tcp);
  form.querySelector('[name="port"]').disabled = !tcp || !ctx.canWrite();
  return true;
}

export function renderTools(ctx) {
  const disabled = !ctx.canWrite() || ctx.offline || !!active;
  return html`<div class="feature-page tools-page"><div class="feature-heading"><div><h2>Network Tools</h2><p>Проверьте доступность, разрешение DNS и маршрут с самого роутера.</p></div>${ctx.icon("terminal")}</div><form id="tools-form" class="tools-form ${input.tool === "tcp" ? "is-tcp" : ""}"><label class="field"><span>Tool</span><select name="tool" ${disabled ? "disabled" : ""}>${tools.map(([id, label]) => html`<option value="${id}" ${input.tool === id ? "selected" : ""}>${t(label)}</option>`).join("")}</select></label><label class="field tools-target"><span>IPv4 / DNS name</span><input name="target" value="${ctx.e(input.target)}" placeholder="1.1.1.1 или vpn.example.com" maxlength="253" required ${disabled ? "disabled" : ""}></label><label class="field tools-port ${input.tool === "tcp" ? "" : "hidden"}"><span>TCP Port</span><input name="port" type="number" value="${ctx.e(input.port)}" min="1" max="65535" required ${disabled || input.tool !== "tcp" ? "disabled" : ""}><small>Используется только TCP Connect</small></label><div class="tools-live-actions"><button class="primary" data-action="tools-run" ${disabled ? "disabled" : ""}>${ctx.icon("activity")}Запустить</button><button type="button" data-action="tools-cancel" ${active ? "" : "hidden"}>Стоп</button></div></form><div class="tools-result"><div class="tools-result-heading"><strong>Результат</strong><span id="tools-result-meta" role="status" aria-live="polite">${liveMeta ? ctx.e(liveMeta) : result ? ctx.e(html`${result.tool.toUpperCase()} · ${result.elapsed_ms} мс · ${result.demo ? "DEMO" : result.success ? t("OK") : t("недоступно")}`) : t("Ping — до нажатия «Стоп» · остальные инструменты — до 20 секунд")}</span></div><pre id="tools-output" tabindex="0" aria-live="off" aria-label="Вывод сетевой диагностики">${liveOutput ? ctx.e(liveOutput) : result ? ctx.e(result.output || t("Ответ без данных.")) : t("Выберите инструмент и укажите адрес. Результат появится здесь.")}</pre></div><p class="feature-note">Ping работает до нажатия «Стоп». Traceroute: до 12 переходов. TCP Connect проверяет соединение без отправки данных. Для запуска нужна группа full. DNS использует системный резолвер роутера.</p></div>`;
}

function updateTools(ctx) {
  const form = document.querySelector("#tools-form");
  if (!form) return;
  const output = document.querySelector("#tools-output");
  const meta = document.querySelector("#tools-result-meta");
  if (output) {
    const follow =
      output.scrollHeight - output.scrollTop - output.clientHeight < 32;
    const text =
      liveOutput ||
      (active ? t("Ожидание ответа роутера") : result?.output || "");
    if (output.textContent !== text) output.textContent = text;
    if (follow) output.scrollTop = output.scrollHeight;
  }
  if (meta && meta.textContent !== liveMeta) meta.textContent = liveMeta;
  for (const control of form.querySelectorAll("input,select,button")) {
    if (control.dataset.action === "tools-cancel") {
      control.hidden = !active;
      control.disabled = false;
    } else
      control.disabled =
        !!active ||
        !ctx.canWrite() ||
        ctx.offline ||
        (control.name === "port" && input.tool !== "tcp");
  }
}

export async function handleToolsAction(button, ctx) {
  const action = button.dataset.action;
  if (!["tools-run", "tools-cancel"].includes(action)) return false;
  if (!ctx.canWrite())
    throw new Error(t("Для сетевой диагностики нужна группа full."));
  if (action === "tools-cancel") {
    active?.abort();
    return true;
  }
  if (active) return true;
  const form = document.querySelector("#tools-form");
  if (!form?.reportValidity()) return true;
  const data = new FormData(form);
  const tool = String(data.get("tool") || "");
  const continuous = tool === "ping";
  const generation = ctx.generation;
  const controller = new AbortController();
  active = controller;
  result = null;
  liveOutput = "";
  liveMeta = continuous
    ? t("Ping выполняется до остановки")
    : t("Выполняется диагностика…");
  updateTools(ctx);
  let finished = false;
  try {
    const response = await ctx.api("tools/stream", {
      method: "POST",
      responseType: "stream",
      signal: continuous
        ? controller.signal
        : AbortSignal.any([controller.signal, AbortSignal.timeout(30000)]),
      body: JSON.stringify({
        tool,
        ...(continuous ? { continuous: true } : {}),
        target: String(data.get("target") || "").trim(),
        port: data.has("port") ? Number(data.get("port")) : 443,
      }),
    });
    await readDiagnosticStream(
      response,
      (event) => {
        if (generation !== ctx.getGeneration() || active !== controller) {
          controller.abort();
          return;
        }
        if (finished) throw new Error(t("Некорректный ответ диагностики."));
        if (event.type === "output") {
          if (typeof event.text !== "string")
            throw new Error(t("Некорректный ответ диагностики."));
          liveOutput = diagnosticOutputTail(liveOutput + event.text);
        } else if (event.type === "completed") {
          if (!event.result || typeof event.result.output !== "string")
            throw new Error(t("Некорректный ответ диагностики."));
          result = {
            ...event.result,
            output: diagnosticOutputTail(event.result.output),
          };
          liveOutput = result.output;
          liveMeta = html`${result.tool.toUpperCase()} · ${result.elapsed_ms} мс · ${result.demo ? "DEMO" : result.success ? t("OK") : t("недоступно")}`;
          finished = true;
        } else if (event.type === "error") {
          throw new Error(
            typeof event.message === "string"
              ? event.message
              : t("Диагностика не завершена"),
          );
        }
        updateTools(ctx);
      },
      controller.signal,
      { continuous },
    );
    if (!finished && generation === ctx.getGeneration())
      throw new Error(t("Поток диагностики прерван. Повторите проверку."));
  } catch (error) {
    if (generation !== ctx.getGeneration() || active !== controller)
      return true;
    if (controller.signal.aborted) liveMeta = t("Диагностика отменена");
    else {
      liveMeta = t("Диагностика не завершена");
      liveOutput = diagnosticOutputTail(
        liveOutput + (liveOutput ? "\n" : "") + error.message,
      );
      throw error;
    }
  } finally {
    if (active === controller) {
      active = null;
      if (generation === ctx.getGeneration()) updateTools(ctx);
    }
  }
  return true;
}
