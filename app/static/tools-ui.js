let result = null;
export function resetTools() {
  result = null;
}
const tools = [
  ["ping", "Ping"],
  ["traceroute", "Traceroute"],
  ["dns", "DNS Lookup"],
  ["route", "Route Lookup"],
  ["tcp", "TCP Connect"],
];

export function renderTools(ctx) {
  const disabled = !ctx.canWrite() || ctx.offline;
  return `<div class="feature-page tools-page"><div class="feature-heading"><div><h2>Network Tools</h2><p>Проверьте доступность, разрешение DNS и маршрут с самого роутера.</p></div>${ctx.icon("terminal")}</div><form id="tools-form" class="tools-form"><label class="field"><span>Tool</span><select name="tool" ${disabled ? "disabled" : ""}>${tools.map(([id, label]) => `<option value="${id}">${label}</option>`).join("")}</select></label><label class="field tools-target"><span>IPv4 / DNS name</span><input name="target" placeholder="1.1.1.1 или vpn.example.com" maxlength="253" required ${disabled ? "disabled" : ""}></label><label class="field tools-port"><span>TCP Port</span><input name="port" type="number" value="443" min="1" max="65535" required ${disabled ? "disabled" : ""}><small>Используется только TCP Connect</small></label><button class="primary" data-action="tools-run" ${disabled ? "disabled" : ""}>${ctx.icon("activity")}Запустить</button></form><div class="tools-result"><div class="tools-result-heading"><strong>Результат</strong><span id="tools-result-meta">${result ? ctx.e(`${result.tool.toUpperCase()} · ${result.elapsed_ms} мс · ${result.demo ? "DEMO" : result.success ? "OK" : "недоступно"}`) : "До 15 секунд · один запуск за раз"}</span></div><pre id="tools-output" tabindex="0" aria-live="polite">${result ? ctx.e(result.output || "Ответ без данных.") : "Выберите инструмент и укажите адрес. Результат появится здесь."}</pre></div><p class="feature-note">Ping: 4 пакета. Traceroute: до 12 переходов. TCP Connect проверяет соединение без отправки данных. Для запуска нужна группа full. DNS использует системный резолвер роутера.</p></div>`;
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
          port: Number(data.get("port")),
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
