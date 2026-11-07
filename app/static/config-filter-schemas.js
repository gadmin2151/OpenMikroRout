import { t } from "./i18n.js";

const field = (name, label, type = "text", extra = {}) => ({
  field: name,
  label: t(label),
  type,
  ...extra,
});
const choices = (values) => values.map((value) => [value, value]);
const enabled = () =>
  field("enabled", "Статус", "enum", {
    options: [
      ["true", t("Включён")],
      ["false", t("Выключен")],
    ],
    get: (row) => String(row.enabled),
  });

/** These schemas select displayed configuration rows; they never compile rules. */
export function natQuerySchema() {
  return [
    field("name", "Name"),
    field("chain", "Chain", "enum", {
      options: choices(["srcnat", "dstnat", "output"]),
    }),
    field("action", "Action", "enum", {
      options: choices([
        "dst-nat",
        "src-nat",
        "masquerade",
        "redirect",
        "accept",
      ]),
    }),
    field("protocol", "Protocol", "enum", {
      options: choices(["any", "tcp", "udp", "icmp", "gre", "esp", "ah"]),
    }),
    field("src_address", "Src. Address", "ipv4"),
    field("dst_address", "Dst. Address", "ipv4"),
    field("src_list", "Src. Address List"),
    field("dst_list", "Dst. Address List"),
    field("src_country", "Src. Country"),
    field("dst_country", "Dst. Country"),
    field("src_ports", "Src. Port", "ports"),
    field("dst_ports", "Dst. Port", "ports"),
    field("in_interface", "In. Interface"),
    field("out_interface", "Out. Interface"),
    field("connection_states", "Connection State", "enum", {
      options: choices([
        "NEW",
        "ESTABLISHED",
        "RELATED",
        "INVALID",
        "UNTRACKED",
      ]),
    }),
    enabled(),
    field("comment", "Comment"),
  ];
}

export function wireGuardQuerySchema() {
  return [
    field("name", "Name"),
    field("interface", "Interface"),
    field("public_key", "Public Key"),
    field("allowed_ips", "Allowed IPs", "ipv4"),
    field("endpoint_host", "Endpoint"),
    field("endpoint_port", "Порт", "ports"),
    enabled(),
    field("comment", "Comment"),
  ];
}

export function captureQuerySchema() {
  return [
    field("protocol", "Протокол", "enum", {
      options: choices(["tcp", "udp", "icmp"]),
      operators: ["eq", "neq", "in", "not_in"],
    }),
    field("source", "Источник IPv4 / CIDR", "ipv4", {
      operators: ["eq", "neq", "in", "not_in"],
    }),
    field("destination", "Назначение IPv4 / CIDR", "ipv4", {
      operators: ["eq", "neq", "in", "not_in"],
    }),
    field("port", "Порт", "ports", {
      operators: ["eq", "neq", "in", "not_in", "gt", "gte", "lt", "lte"],
    }),
  ];
}
