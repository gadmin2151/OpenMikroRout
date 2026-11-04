/** Shared guards for long-lived editors and managed-interface deletion. */
export function prepareImportedConfig(imported, current) {
  if (!imported || typeof imported !== "object" || Array.isArray(imported)) {
    throw new Error("Файл не содержит объект конфигурации.");
  }
  const result = structuredClone(imported);
  // NAT Panel version-1 exports predate router sections. Preserve those sections
  // unless the imported file explicitly includes their replacement.
  for (const key of ["network", "filter_rules"]) {
    if (!Object.hasOwn(imported, key)) {
      result[key] = structuredClone(
        current[key] ?? (key === "network" ? {} : []),
      );
    }
  }
  return result;
}

export function assertDraftRevision(expected, current) {
  if (!Number.isSafeInteger(expected) || expected < 0 || expected !== current) {
    throw new Error(
      "Конфигурация изменилась в другой сессии. Введённые значения остаются в форме. Загрузите актуальный черновик и повторите изменение.",
    );
  }
  return expected;
}

export function linkReferences(config, name) {
  const network = config.network || {};
  const refs = [];
  const add = (label, item) => refs.push(`${label}: ${item}`);
  for (const item of network.addresses || [])
    if (item.interface === name) add("IP Address", item.address);
  for (const item of network.routes || [])
    if (item.interface === name) add("Route", item.destination);
  for (const item of network.dhcp_servers || [])
    if (item.interface === name) add("DHCP Server", item.name);
  for (const item of network.wireguard_peers || [])
    if (item.interface === name) add("WireGuard Peer", item.name);
  if ((network.dns?.listen_interfaces || []).includes(name))
    add("DNS Listen Interface", name);
  for (const item of network.vlans || [])
    if (item.parent === name) add("VLAN Parent", item.name);
  for (const item of network.bridges || [])
    if ((item.members || []).includes(name)) add("Bridge Port", item.name);
  for (const item of network.interface_lists || [])
    if ((item.members || []).includes(name)) add("Interface List", item.name);
  for (const [kind, rules] of [
    ["NAT", config.rules || []],
    ["Filter", config.filter_rules || []],
  ]) {
    for (const item of rules)
      if (item.in_interface === name || item.out_interface === name)
        add(kind, item.name);
  }
  return refs;
}

export function assertLinkRemoval(config, kind, id) {
  if (
    ![
      "bridges",
      "vlans",
      "virtual_interfaces",
      "wireguard_interfaces",
    ].includes(kind)
  )
    return;
  const item = (config.network?.[kind] || []).find((item) => item.id === id);
  if (!item) return;
  const refs = linkReferences(config, item.name);
  if (refs.length) {
    const details =
      refs.slice(0, 8).join("; ") +
      (refs.length > 8 ? `; ещё ${refs.length - 8}` : "");
    throw new Error(
      `Нельзя удалить ${item.name}: ${details}. Сначала переназначьте или удалите эти зависимости.`,
    );
  }
}
