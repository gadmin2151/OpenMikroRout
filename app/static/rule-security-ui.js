/** Shared WinBox-style NAT / Filter controls and per-service protection. */
const countries =
  "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS XK YE YT ZA ZM ZW".split(
    " ",
  );
const names =
  typeof Intl.DisplayNames === "function"
    ? new Intl.DisplayNames(["ru"], { type: "region" })
    : null;

export function countryOptions() {
  return countries
    .map((code) => [code, `${names?.of(code) || code} · ${code}`])
    .sort((a, b) => a[1].localeCompare(b[1], "ru"));
}

export function countryField(ctx, name, value = "") {
  const options = countryOptions();
  if (value && !countries.includes(value))
    options.push([value, `${value} · из конфигурации`]);
  const label = name === "src_country" ? "Src. Country" : "Dst. Country";
  return `<label class="field"><span>${label}</span><select name="${ctx.e(name)}" aria-label="${label}"><option value="">Любая страна</option>${options.map(([code, text]) => `<option value="${ctx.e(code)}" ${value === code ? "selected" : ""}>${ctx.e(text)}</option>`).join("")}</select></label>`;
}

export const defaultRuleProtection = () => ({
  enabled: false,
  event_source: "connections",
  max_retry: 5,
  find_time: 600,
  ban_time: 900,
});

export function collectRuleProtection(form, original) {
  if (!form.querySelector('[name="protection_enabled"]')) return original;
  const values = new FormData(form);
  return {
    ...defaultRuleProtection(),
    ...original,
    enabled: values.has("protection_enabled"),
    event_source: String(
      values.get("protection_event_source") || "connections",
    ),
    max_retry: Number(values.get("protection_max_retry")),
    find_time: Number(values.get("protection_find_time")),
    ban_time: Number(values.get("protection_ban_time")),
  };
}

export function ruleServiceSummary(item) {
  const nat = "to_address" in item || ["dstnat", "srcnat"].includes(item.chain);
  const translated = nat && item.action === "dst-nat";
  return {
    chain: nat
      ? item.action === "redirect"
        ? "input"
        : "input / forward"
      : item.chain,
    destination: translated
      ? item.to_address
      : item.action === "redirect"
        ? "Этот роутер"
        : item.dst_address || item.dst_list || "Любой адрес",
    ports: (nat && item.to_ports) || item.dst_ports || "Не заданы",
    incoming: item.in_interface || item.in_interface_list || "Любой интерфейс",
    supported:
      item.protocol === "tcp" &&
      (nat
        ? item.chain === "dstnat" &&
          ["dst-nat", "redirect"].includes(item.action)
        : ["input", "forward"].includes(item.chain)),
  };
}

export function renderRuleFail2ban(ctx, item) {
  const protection = { ...defaultRuleProtection(), ...item.protection };
  const service = ruleServiceSummary(item);
  const number = (label, name, value, min, max) =>
    `<label class="field"><span>${label}</span><input type="number" name="protection_${name}" aria-label="${label}" min="${min}" max="${max}" step="1" required value="${ctx.e(value)}"></label>`;
  return `<div class="winbox-form rule-security-fields">
    <label class="checkbox-label"><input type="checkbox" name="protection_enabled" ${protection.enabled ? "checked" : ""} ${!service.supported && !protection.enabled ? "disabled" : ""}>Автоматическая блокировка</label>
    ${!service.supported ? '<div class="field-note">Доступно для TCP: dstnat → dst-nat / redirect и Filter input / forward. Укажите порты сервиса в General / Action.</div>' : ""}
    <div class="field"><span>Сервис из правила</span><output>${ctx.e(service.destination)} : ${ctx.e(service.ports)} · TCP</output></div>
    <div class="field"><span>Направление</span><output>${ctx.e(service.chain)} · ${ctx.e(service.incoming)}</output></div>
    <div class="form-divider"></div>
    <label class="field"><span>Считать попытки</span><select name="protection_event_source" aria-label="Считать попытки">${[
      ["connections", "Новые TCP-подключения"],
      ["web", "Ошибки входа в OpenMikroRout"],
      ["ssh", "Ошибки SSH этого роутера"],
    ]
      .map(
        ([key, text]) =>
          `<option value="${key}" ${protection.event_source === key ? "selected" : ""} ${key !== "connections" && service.chain !== "input" && protection.event_source !== key ? "disabled" : ""}>${text}</option>`,
      )
      .join("")}</select></label>
    ${service.chain !== "input" && protection.event_source !== "connections" ? '<p class="field-note" role="alert">Для сервера за NAT / forward выберите новые TCP-подключения. Ошибки Web / SSH относятся к входу на сам роутер.</p>' : ""}
    ${number("Попыток до бана", "max_retry", protection.max_retry, 1, 100)}
    ${number("За период · сек", "find_time", protection.find_time, 10, 86400)}
    ${number("Время бана · сек", "ban_time", protection.ban_time, 1, 2147483)}
    <div class="field-note">Профиль и правило блокировки создаются автоматически при применении. Адрес, порт и интерфейс берутся из этого правила; изменения синхронизируются.</div>
    ${item.enabled === false ? '<p class="muted">Само правило выключено: автоматическая защита также не будет активна.</p>' : ""}
    <details class="rule-condition-help"><summary>Область защиты</summary><p>Бан ограничен указанным сервисом и входным интерфейсом. В NAT используется конечный адрес и порт после трансляции. Страны и списки в Advanced задают условия исходного правила.</p><p>TCP-подключение — не ошибка пароля. Считается только новое соединение с завершённым двусторонним TCP-рукопожатием и наблюдённым ответом на обратном пути; отдельные SYN и их повторы не приводят к бану адреса. Для forward нужны разные входной и выходной интерфейсы: hairpin через один интерфейс не создаёт событий и показывает предупреждение. Ошибки входа Web / SSH доступны только для этого роутера; ошибки паролей на серверах за NAT требуют их журналов.</p></details>
    <p class="muted">Созданные профили и активные блокировки: Security → Fail2ban.</p>
  </div>`;
}

export function renderLegacyBanMatch(ctx, item) {
  const config = ctx.state.config.fail2ban;
  const profiles = config?.profiles || [];
  const selected = item.f2b_profile || "";
  const profile = profiles.find((p) => p.id === selected);
  const mode = item.f2b_match || "not_banned";
  const options = profiles.map((p) => [p.id, `${p.name} · f2b_${p.id}`]);
  if (selected && !profile)
    options.push([selected, `${selected} · профиль не найден`]);
  const nat = ["dstnat", "srcnat"].includes(item.chain) || "to_address" in item;
  const source =
    profile?.service === "ssh" ? "SSH этого роутера" : "Вход в OpenMikroRout";
  return `<div class="winbox-form rule-security-fields">
    <label class="field"><span>Ban list · профиль</span><select name="f2b_profile" aria-label="Ban list · профиль"><option value="">Не использовать</option>${options.map(([id, text]) => `<option value="${ctx.e(id)}" ${selected === id ? "selected" : ""}>${ctx.e(text)}</option>`).join("")}</select></label>
    <label class="field"><span>Source IP</span><select name="f2b_match" aria-label="Source IP"><option value="not_banned" ${mode === "not_banned" ? "selected" : ""}>Не входит в список блокировок</option><option value="banned" ${mode === "banned" ? "selected" : ""}>Входит в список блокировок</option></select></label>
    <div class="field-note">Проверяет Source IP по списку; защиту не включает. ${nat ? "NAT не блокирует пакеты." : "Действие задаётся на вкладке Action."}</div>
    ${profile ? `<div class="field"><span>Источник событий</span><strong>${source}</strong></div><div class="field"><span>Профиль в черновике</span><output>${config.enabled && profile.enabled ? "Включён" : "Выключен"} · ${ctx.e(profile.max_retry)} ошибок / ${ctx.e(profile.find_time)} с · бан ${ctx.e(profile.ban_time)} с</output></div>${!config.enabled || !profile.enabled ? '<p class="muted">Сбор выключен; существующие баны действуют до истечения срока.</p>' : ""}` : ""}
    <details class="rule-condition-help"><summary>Как работает условие</summary>
      <p>Условие действует вместе с адресами, странами и портами (AND). Без выбранного профиля оно не используется. При пустом списке «Не входит» совпадает для всех IP.</p>
      <p>${nat ? "Если условие не совпало, обработка продолжится следующими правилами NAT. Для блокировки используйте Firewall Filter: «Входит в список» и Action drop / reject." : "Для блокировки выберите «Входит в список» и Action drop / reject; расположите правило до разрешающих. При несовпадении проверяется следующее правило."}</p>
      <p>Ошибки входа на серверы за NAT (например, RDP) автоматически не собираются.</p>
    </details>
    <p class="muted">Профили и активные блокировки: Security → Fail2ban.</p>
  </div>`;
}
