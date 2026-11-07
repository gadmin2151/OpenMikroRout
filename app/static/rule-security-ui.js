/** Shared NAT / Filter conditions. These match packets; they do not create a jail. */
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

export function renderRuleFail2ban(ctx, item) {
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
