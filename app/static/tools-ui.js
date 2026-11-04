let result = null;
let input = { tool: "ping", target: "", port: "443" };
export function resetTools() {
  result = null;
  input = { tool: "ping", target: "", port: "443" };
}
const tools = [
  ["ping", "Ping"],
  ["traceroute", "Traceroute"],
  ["dns", "DNS Lookup"],
  ["route", "Route Lookup"],
  ["tcp", "TCP Connect"],
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
  const disabled = !ctx.canWrite() || ctx.offline;
  return `<div class="feature-page tools-page"><div class="feature-heading"><div><h2>Network Tools</h2><p>Проверьте доступность, разрешение DNS и маршрут с самого роутера.</p></div>${ctx.icon("terminal")}</div><form id="tools-form" class="tools-form ${input.tool === "tcp" ? "is-tcp" : ""}"><label class="field"><span>Tool</span><select name="tool" ${disabled ? "disabled" : ""}>${tools.map(([id, label]) => `<option value="${id}" ${input.tool === id ? "selected" : ""}>${label}</option>`).join("")}</select></label><label class="field tools-target"><span>IPv4 / DNS name</span><input name="target" value="${ctx.e(input.target)}" placeholder="1.1.1.1 или vpn.example.com" maxlength="253" required ${disabled ? "disabled" : ""}></label><label class="field tools-port ${input.tool === "tcp" ? "" : "hidden"}"><span>TCP Port</span><input name="port" type="number" value="${ctx.e(input.port)}" min="1" max="65535" required ${disabled || input.tool !== "tcp" ? "disabled" : ""}><small>Используется только TCP Connect</small></label><button class="primary" data-action="tools-run" ${disabled ? "disabled" : ""}>${ctx.icon("activity")}Запустить</button></form><div class="tools-result"><div class="tools-result-heading"><strong>Результат</strong><span id="tools-result-meta">${result ? ctx.e(`${result.tool.toUpperCase()} · ${result.elapsed_ms} мс · ${result.demo ? "DEMO" : result.success ? "OK" : "недоступно"}`) : "До 20 секунд · один запуск за раз"}</span></div><pre id="tools-output" tabindex="0" aria-live="polite">${result ? ctx.e(result.output || "Ответ без данных.") : "Выберите инструмент и укажите адрес. Результат появится здесь."}</pre></div><p class="feature-note">Ping: 4 пакета. Traceroute: до 12 переходов. TCP Connect проверяет соединение без отправки данных. Для запуска нужна группа full. DNS использует системный резолвер роутера.</p></div>`;
}

export async function handleToolsAction(button, ctx) {
  if (button.dataset.action !== "tools-run") return false;
  if (!ctx.canWrite())
    throw new Error("Для сетевой диагностики нужна группа full.");
  const form = document.querySelector("#tools-form");
  if (!form?.reportValidity()) return true;
  const data = new FormData(form);
  await ctx.run(async () => {
    const generation = ctx.generation;
    const output = document.querySelector("#tools-output");
    const meta = document.querySelector("#tools-result-meta");
    output.textContent = "Выполняется диагностика…";
    meta.textContent = "Ожидание ответа роутера";
    try {
      const value = await ctx.api("tools/run", {
        method: "POST",
        body: JSON.stringify({
          tool: data.get("tool"),
          target: String(data.get("target") || "").trim(),
          port: data.has("port") ? Number(data.get("port")) : 443,
        }),
      });
      if (generation !== ctx.getGeneration()) return;
      result = value;
      if (output.isConnected) {
        output.textContent = value.output || "Ответ без данных.";
        meta.textContent = `${value.tool.toUpperCase()} · ${value.elapsed_ms} мс · ${value.demo ? "DEMO" : value.success ? "OK" : "недоступно"}`;
      }
    } catch (error) {
      if (generation === ctx.getGeneration() && output.isConnected) {
        output.textContent = error.message;
        meta.textContent = "Диагностика не завершена";
      }
      throw error;
    }
  });
  return true;
}
