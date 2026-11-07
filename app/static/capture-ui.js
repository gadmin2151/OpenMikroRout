import { html, t } from "./i18n.js";
import { diagnosticOutputTail, readDiagnosticStream } from "./live-stream.js";

let status = null;
let statusError = "";
let statusRequest = null;
let statusController = null;
let active = null;
let epoch = 0;
let output = "";
let meta = "";
let error = "";
let paintTimer = null;
let renderedOptions = new WeakMap();
const defaults = () => ({
  interface: "any",
  protocol: "all",
  source: "",
  destination: "",
  port: "",
});
let input = defaults();

export function resetCapture() {
  epoch++;
  clearTimeout(paintTimer);
  paintTimer = null;
  active?.abort();
  statusController?.abort();
  active = statusController = statusRequest = status = null;
  statusError = output = meta = error = "";
  input = defaults();
  renderedOptions = new WeakMap();
}

function interfaces() {
  return [
    ...new Set(
      (status?.interfaces || []).filter((name) => typeof name === "string"),
    ),
  ];
}
function readiness(ctx) {
  if (!ctx.canWrite()) return t("Для захвата пакетов нужна группа full.");
  if (ctx.offline)
    return t("Нет связи с сервером. Повторите после подключения.");
  if (statusError) return statusError;
  if (!status) return t("Загрузка интерфейсов…");
  if (status.error) return status.error;
  if (!status.available) return t("Для захвата установите tcpdump на сервере.");
  if (!interfaces().includes(input.interface))
    return t("Выберите интерфейс захвата.");
  return "";
}
function interfaceOptions(ctx) {
  return html`<option value="">Выберите интерфейс захвата</option>${interfaces()
    .map(
      (name) =>
        html`<option value="${ctx.e(name)}" ${input.interface === name ? "selected" : ""}>${name === "any" ? t("Все интерфейсы (any)") : ctx.e(name)}</option>`,
    )
    .join("")}`;
}

export function renderCapture(ctx) {
  const disabled = !ctx.canWrite() || ctx.offline || !!active;
  const locked = disabled ? "disabled" : "";
  return html`<div class="feature-page capture-page"><div class="feature-heading"><div><h2>Packet Sniffer</h2><p>Наблюдение заголовков IPv4-пакетов на выбранном интерфейсе.</p></div>${ctx.icon("activity")}</div><div class="capture-readiness feature-note" id="capture-readiness" role="status">${ctx.e(readiness(ctx) || t("Готов к захвату пакетов"))}</div><form id="capture-form" class="form-grid capture-form"><label class="field"><span>Интерфейс захвата</span><select name="interface" id="capture-interface" required ${locked}>${interfaceOptions(ctx)}</select></label><label class="field"><span>Протокол</span><select name="protocol" ${locked}>${["all", "tcp", "udp", "icmp"].map((value) => html`<option value="${value}" ${input.protocol === value ? "selected" : ""}>${value === "all" ? t("Все протоколы IPv4") : value.toUpperCase()}</option>`).join("")}</select></label><label class="field"><span>Источник IPv4 / CIDR</span><input name="source" value="${ctx.e(input.source)}" placeholder="192.0.2.0/24" maxlength="32" ${locked}></label><label class="field"><span>Назначение IPv4 / CIDR</span><input name="destination" value="${ctx.e(input.destination)}" placeholder="198.51.100.10" maxlength="32" ${locked}></label><label class="field"><span>Порт · необязательно</span><input name="port" value="${ctx.e(input.port)}" type="number" min="1" max="65535" step="1" placeholder="443" ${disabled || input.protocol === "icmp" ? "disabled" : ""}><small>TCP / UDP · источник или назначение</small></label><div class="wide settings-actions capture-actions"><button type="submit" class="primary" data-action="capture-start" ${disabled || readiness(ctx) ? "disabled" : ""}>${ctx.icon("activity")}Начать захват</button><button type="button" data-action="capture-stop" ${active ? "" : "hidden"}>Стоп</button><button type="button" data-action="capture-refresh" ${active || statusRequest ? "disabled" : ""}>${ctx.icon("refresh")}Обновить интерфейсы</button></div></form><div class="connection-error" id="capture-error" role="alert" ${error ? "" : "hidden"}>${ctx.e(error)}</div><div class="tools-result capture-result"><div class="tools-result-heading"><strong>Пакеты</strong><span id="capture-meta" role="status" aria-live="polite">${ctx.e(meta || t("Захват выключен"))}</span></div><pre id="capture-output" tabindex="0" aria-live="off" aria-label="Заголовки перехваченных пакетов">${ctx.e(output || t("Выберите интерфейс и фильтры, затем начните захват."))}</pre></div><p class="feature-note">Захват работает до нажатия «Стоп». Вывод содержит заголовки пакетов без содержимого и хранит последние 32 КиБ только в этом окне. Закрытие раздела останавливает захват. Фильтры не меняют правила Firewall.</p></div>`;
}

function updateCapture(ctx) {
  const form = document.querySelector("#capture-form");
  if (!form) return;
  const select = document.querySelector("#capture-interface");
  if (select) {
    const markup = interfaceOptions(ctx);
    if (renderedOptions.get(select) !== markup) {
      select.innerHTML = markup;
      renderedOptions.set(select, markup);
    }
    select.value = input.interface;
  }
  const readinessNode = document.querySelector("#capture-readiness");
  if (readinessNode)
    readinessNode.textContent = readiness(ctx) || t("Готов к захвату пакетов");
  const errorNode = document.querySelector("#capture-error");
  if (errorNode) {
    errorNode.textContent = error;
    errorNode.hidden = !error;
  }
  const metaNode = document.querySelector("#capture-meta");
  if (metaNode) metaNode.textContent = meta || t("Захват выключен");
  const outputNode = document.querySelector("#capture-output");
  if (outputNode) {
    const follow =
      outputNode.scrollHeight - outputNode.scrollTop - outputNode.clientHeight <
      32;
    const text =
      output || t("Выберите интерфейс и фильтры, затем начните захват.");
    if (outputNode.textContent !== text) outputNode.textContent = text;
    if (follow) outputNode.scrollTop = outputNode.scrollHeight;
  }
  for (const control of form.querySelectorAll("input,select,button")) {
    const action = control.dataset.action;
    if (action === "capture-stop") {
      control.hidden = !active;
      control.disabled = false;
    } else
      control.disabled =
        !!active ||
        !ctx.canWrite() ||
        ctx.offline ||
        (control.name === "port" && input.protocol === "icmp") ||
        (action === "capture-start" && !!readiness(ctx)) ||
        (action === "capture-refresh" && !!statusRequest);
  }
}

function schedulePaint(ctx) {
  if (paintTimer !== null) return;
  const currentEpoch = epoch;
  const generation = ctx.generation;
  paintTimer = setTimeout(() => {
    paintTimer = null;
    if (currentEpoch === epoch && generation === ctx.getGeneration())
      updateCapture(ctx);
  }, 100);
}

export async function refreshCapture(ctx) {
  if (statusRequest) return statusRequest;
  const currentEpoch = epoch;
  const generation = ctx.generation;
  const controller = new AbortController();
  statusController = controller;
  const request = Promise.resolve().then(async () => {
    try {
      const value = await ctx.api("tools/capture/status", {
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(8000)]),
      });
      if (
        controller.signal.aborted ||
        currentEpoch !== epoch ||
        generation !== ctx.getGeneration()
      )
        return;
      if (
        !value ||
        typeof value.available !== "boolean" ||
        !Array.isArray(value.interfaces) ||
        value.interfaces.some((name) => typeof name !== "string")
      )
        throw new Error(t("Некорректный ответ диагностики."));
      status = value;
      statusError = "";
      if (!active && !interfaces().includes(input.interface))
        input.interface = "";
    } catch (failure) {
      if (
        !controller.signal.aborted &&
        currentEpoch === epoch &&
        generation === ctx.getGeneration()
      )
        statusError = failure.message;
    } finally {
      if (statusRequest === request) statusRequest = null;
      if (statusController === controller) statusController = null;
      if (
        !controller.signal.aborted &&
        currentEpoch === epoch &&
        generation === ctx.getGeneration()
      )
        updateCapture(ctx);
    }
  });
  statusRequest = request;
  return request;
}

export function handleCaptureInput(event, ctx) {
  const form = event.target?.closest?.("#capture-form");
  if (!form) return false;
  if (active) return true;
  const values = new FormData(form);
  const previousPort = input.port;
  input = Object.fromEntries(
    Object.keys(defaults()).map((name) => [
      name,
      String(values.get(name) || ""),
    ]),
  );
  if (!values.has("port")) input.port = previousPort;
  updateCapture(ctx);
  return true;
}

export async function handleCaptureAction(button, ctx) {
  const action = button.dataset.action;
  if (!["capture-start", "capture-stop", "capture-refresh"].includes(action))
    return false;
  if (action === "capture-stop") {
    active?.abort();
    return true;
  }
  if (action === "capture-refresh") {
    await refreshCapture(ctx);
    return true;
  }
  if (!ctx.canWrite())
    throw new Error(t("Для захвата пакетов нужна группа full."));
  if (active) return true;
  const reason = readiness(ctx);
  if (reason) throw new Error(reason);
  const form = document.querySelector("#capture-form");
  if (!form?.reportValidity()) return true;
  handleCaptureInput({ target: form.querySelector("input,select") }, ctx);
  const generation = ctx.generation;
  const currentEpoch = epoch;
  const controller = new AbortController();
  active = controller;
  error = output = "";
  meta = t("Захват пакетов выполняется до остановки");
  updateCapture(ctx);
  let started = false;
  let finished = false;
  try {
    const response = await ctx.api("tools/capture/stream", {
      method: "POST",
      responseType: "stream",
      signal: controller.signal,
      body: JSON.stringify({
        ...input,
        source: input.source.trim(),
        destination: input.destination.trim(),
        port:
          input.protocol !== "icmp" && input.port ? Number(input.port) : null,
      }),
    });
    await readDiagnosticStream(
      response,
      (event) => {
        if (
          currentEpoch !== epoch ||
          generation !== ctx.getGeneration() ||
          active !== controller
        ) {
          controller.abort();
          return;
        }
        if (event.type === "started") {
          if (event.tool !== "capture")
            throw new Error(t("Некорректный ответ диагностики."));
          started = true;
        } else if (event.type === "output") {
          if (!started) throw new Error(t("Некорректный ответ диагностики."));
          output = diagnosticOutputTail(output + event.text);
          schedulePaint(ctx);
          return;
        } else if (event.type === "completed") {
          if (
            event.result.tool !== "capture" ||
            typeof event.result.success !== "boolean"
          )
            throw new Error(t("Некорректный ответ диагностики."));
          output = diagnosticOutputTail(event.result.output);
          meta = event.result.demo
            ? t("DEMO · захват не запускался")
            : event.result.success
              ? t("Захват завершён")
              : t("Захват завершён с ошибкой");
          finished = true;
        } else if (event.type === "error")
          throw new Error(
            typeof event.message === "string"
              ? event.message
              : t("Захват завершён с ошибкой"),
          );
        updateCapture(ctx);
      },
      controller.signal,
      { continuous: true },
    );
    if (!finished)
      throw new Error(t("Поток диагностики прерван. Повторите проверку."));
  } catch (failure) {
    if (
      currentEpoch !== epoch ||
      generation !== ctx.getGeneration() ||
      active !== controller
    )
      return true;
    if (controller.signal.aborted) meta = t("Захват остановлен");
    else {
      error = failure.message;
      meta = t("Захват завершён с ошибкой");
    }
  } finally {
    if (active === controller) {
      clearTimeout(paintTimer);
      paintTimer = null;
      active = null;
      if (currentEpoch === epoch && generation === ctx.getGeneration())
        updateCapture(ctx);
    }
  }
  return true;
}
