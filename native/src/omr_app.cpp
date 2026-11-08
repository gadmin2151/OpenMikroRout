// SPDX-License-Identifier: GPL-3.0-or-later
// OpenMikroRout's bounded application datapath. nDPI is a separately licensed
// library.
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <grp.h>
#include <iostream>
#include <json-c/json.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/seccomp.h>
#include <map>
#include <memory>
#include <ndpi_api.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pwd.h>
#include <set>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace omr {
constexpr uint32_t OWN_MASK = 0x00ffffff, VALID = 0x40, PENDING = 0x80;
constexpr size_t MAX_POLICY = 4 * 1024 * 1024, MAX_PACKET = 65535,
                 MAX_FLOWS = 4096;
constexpr uint32_t IPC_MAGIC = 0x4f4d5231;
volatile sig_atomic_t stopping = 0;
void stop_signal(int) { stopping = 1; }
uint64_t monotonic_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
double unix_time() {
  return std::chrono::duration<double>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
Json own(json_object *value) { return Json(value, json_object_put); }
json_object *field(json_object *object, const char *name) {
  json_object *value = nullptr;
  return object && json_object_object_get_ex(object, name, &value) ? value
                                                                   : nullptr;
}
std::string text(json_object *object, const char *name,
                 const std::string &fallback = "") {
  auto *value = field(object, name);
  if (!value)
    return fallback;
  if (!json_object_is_type(value, json_type_string))
    throw std::runtime_error(std::string("Invalid string: ") + name);
  auto length = json_object_get_string_len(value);
  if (length < 0 || length > 4096)
    throw std::runtime_error("String exceeds policy limits");
  return std::string(json_object_get_string(value),
                     static_cast<size_t>(length));
}
int number(json_object *object, const char *name, int fallback, int minimum,
           int maximum) {
  auto *value = field(object, name);
  if (!value)
    return fallback;
  if (!json_object_is_type(value, json_type_int))
    throw std::runtime_error(std::string("Invalid integer: ") + name);
  auto result = json_object_get_int64(value);
  if (result < minimum || result > maximum)
    throw std::runtime_error(std::string("Out-of-range integer: ") + name);
  return static_cast<int>(result);
}
bool boolean(json_object *object, const char *name, bool fallback = false) {
  auto *value = field(object, name);
  if (!value)
    return fallback;
  if (!json_object_is_type(value, json_type_boolean))
    throw std::runtime_error("Invalid boolean");
  return json_object_get_boolean(value);
}
std::vector<std::string> strings(json_object *object, const char *name,
                                 size_t maximum = 512) {
  std::vector<std::string> output;
  auto *array = field(object, name);
  if (!array)
    return output;
  if (!json_object_is_type(array, json_type_array) ||
      json_object_array_length(array) > maximum)
    throw std::runtime_error(std::string("Invalid bounded list: ") + name);
  for (size_t i = 0; i < json_object_array_length(array); ++i) {
    auto *entry = json_object_array_get_idx(array, i);
    if (!json_object_is_type(entry, json_type_string) ||
        json_object_get_string_len(entry) > 253)
      throw std::runtime_error("Invalid list entry");
    output.emplace_back(json_object_get_string(entry));
  }
  return output;
}
Json read_json(const std::string &path) {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    throw std::runtime_error("Cannot open owned policy");
  struct stat statbuf{};
  if (fstat(fd, &statbuf) || !S_ISREG(statbuf.st_mode) || statbuf.st_size < 2 ||
      statbuf.st_size > static_cast<off_t>(MAX_POLICY)) {
    close(fd);
    throw std::runtime_error("Invalid bounded policy file");
  }
  std::string data(static_cast<size_t>(statbuf.st_size), '\0');
  size_t done = 0;
  while (done < data.size()) {
    ssize_t count = read(fd, data.data() + done, data.size() - done);
    if (count <= 0) {
      close(fd);
      throw std::runtime_error("Incomplete policy read");
    }
    done += static_cast<size_t>(count);
  }
  close(fd);
  auto *tokener = json_tokener_new_ex(24);
  if (!tokener)
    throw std::runtime_error("JSON allocation failed");
  json_tokener_set_flags(tokener, JSON_TOKENER_STRICT);
  auto *value = json_tokener_parse_ex(tokener, data.data(),
                                      static_cast<int>(data.size()));
  const bool ok = json_tokener_get_error(tokener) == json_tokener_success &&
                  value && json_object_is_type(value, json_type_object);
  json_tokener_free(tokener);
  if (!ok) {
    if (value)
      json_object_put(value);
    throw std::runtime_error("Malformed policy JSON");
  }
  return own(value);
}
void add(json_object *object, const char *name, const std::string &value) {
  json_object_object_add(
      object, name,
      json_object_new_string_len(value.data(), static_cast<int>(value.size())));
}
void add(json_object *object, const char *name, const char *value) {
  add(object, name, std::string(value));
}
void add(json_object *object, const char *name, double value) {
  json_object_object_add(object, name, json_object_new_double(value));
}
void add(json_object *object, const char *name, uint64_t value) {
  json_object_object_add(object, name, json_object_new_uint64(value));
}
void add(json_object *object, const char *name, bool value) {
  json_object_object_add(object, name, json_object_new_boolean(value));
}
std::string normalize(std::string value) {
  std::string result;
  for (unsigned char c : value)
    if (std::isalnum(c))
      result += static_cast<char>(std::tolower(c));
  return result;
}
struct Network {
  uint32_t address = 0, mask = 0;
  explicit Network(const std::string &value) {
    auto slash = value.find('/');
    std::string host = value.substr(0, slash);
    unsigned bits = 32;
    if (slash != std::string::npos) {
      auto suffix = value.substr(slash + 1);
      if (suffix.empty() || suffix.size() > 2 ||
          !std::all_of(suffix.begin(), suffix.end(),
                       [](unsigned char c) { return std::isdigit(c); }))
        throw std::runtime_error("Invalid IPv4 prefix");
      bits = static_cast<unsigned>(std::stoul(suffix));
    }
    in_addr parsed{};
    if (bits > 32 || inet_pton(AF_INET, host.c_str(), &parsed) != 1)
      throw std::runtime_error("Invalid IPv4 network");
    mask = bits ? 0xffffffffU << (32 - bits) : 0;
    address = ntohl(parsed.s_addr) & mask;
  }
  bool contains(uint32_t value) const {
    return (ntohl(value) & mask) == address;
  }
};
std::vector<Network> networks(json_object *object, const char *name) {
  std::vector<Network> result;
  for (const auto &value : strings(object, name, 128))
    result.emplace_back(value);
  return result;
}
struct App {
  std::string id;
  std::vector<std::string> names, domains;
  bool allow = false, generic = false;
};
struct Rule {
  std::string id, action;
  std::vector<std::string> apps, inputs, outputs, states;
  std::vector<Network> sources, destinations;
};
struct Policy {
  std::string generation, mode, unknown_policy, failure_policy, engine_profile;
  bool reevaluate_interfaces = false;
  uint32_t epoch = 1;
  uint16_t queue = 5089;
  int timeout_ms = 2000, probe_packets = 32, probe_bytes = 65536,
      max_pending = 512;
  int max_per_client = 32, queue_limit = 256, verdict_ms = 250;
  std::vector<std::string> interfaces;
  std::vector<Network> scopes;
  std::vector<App> apps;
  std::unordered_map<std::string, size_t> protocol_index, domain_index;
  std::vector<Rule> rules;
  explicit Policy(json_object *root) {
    if (number(root, "schema", 0, 1, 1) != 1)
      throw std::runtime_error("Unsupported policy schema");
    generation = text(root, "generation");
    if (generation.size() != 64 ||
        !std::all_of(generation.begin(), generation.end(),
                     [](unsigned char c) { return std::isxdigit(c); }))
      throw std::runtime_error("Invalid policy generation");
    engine_profile = text(root, "engine_license_profile", "lgpl-only");
    if (engine_profile != "lgpl-only" && engine_profile != "not-for-profit" &&
        engine_profile != "commercial-license")
      throw std::runtime_error("Invalid engine license profile");
    mode = text(root, "mode");
    if (mode != "observe" && mode != "enforce")
      throw std::runtime_error("Invalid runtime mode");
    epoch = static_cast<uint32_t>(number(root, "epoch", 1, 1, 65535));
    queue = static_cast<uint16_t>(number(root, "queue_num", 5089, 1, 65535));
    if (number(root, "ct_mask", OWN_MASK, 0, OWN_MASK) !=
            static_cast<int>(OWN_MASK) ||
        number(root, "ct_valid_bit", VALID, 0, VALID) !=
            static_cast<int>(VALID) ||
        number(root, "ct_pending_bit", PENDING, 0, PENDING) !=
            static_cast<int>(PENDING) ||
        number(root, "ct_epoch_shift", 8, 0, 8) != 8)
      throw std::runtime_error("Unsupported conntrack layout");
    if (auto *shifts = field(root, "state_shifts"))
      if (number(shifts, "NEW", 0, 0, 0) != 0 ||
          number(shifts, "ESTABLISHED", 2, 2, 2) != 2 ||
          number(shifts, "RELATED", 4, 4, 4) != 4)
        throw std::runtime_error("Unsupported state profile");
    reevaluate_interfaces = boolean(root, "reevaluate_interfaces");
    interfaces = strings(root, "interfaces", 64);
    for (const auto &value : interfaces)
      if (value.empty() || value.size() >= IFNAMSIZ ||
          value.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR"
                                  "STUVWXYZ0123456789_.-:") !=
              std::string::npos)
        throw std::runtime_error("Invalid scoped interface");
    scopes = networks(root, "source_networks");
    if (interfaces.empty() || scopes.empty())
      throw std::runtime_error(
          "Explicit interfaces and source networks required");
    unknown_policy = text(root, "unknown_policy", "firewall");
    failure_policy = text(root, "failure_policy", "block");
    for (const auto &value : {unknown_policy, failure_policy})
      if (value != "firewall" && value != "block")
        throw std::runtime_error("Invalid failure policy");
    auto *limits = field(root, "limits");
    timeout_ms = number(limits, "probe_timeout_ms", 2000, 100, 10000);
    probe_packets = number(limits, "probe_packets", 32, 1, 128);
    probe_bytes = number(limits, "probe_bytes", 65536, 1024, 262144);
    max_pending = number(limits, "max_pending", 512, 1, 2048);
    max_per_client = number(limits, "max_pending_per_client", 32, 1, 128);
    queue_limit = number(limits, "queue_limit", 256, 16, 4096);
    verdict_ms = number(limits, "verdict_timeout_ms", 250, 10, 1000);
    auto *catalog = field(root, "catalog"),
         *entries = field(catalog, "entries");
    if (!entries || !json_object_is_type(entries, json_type_array) ||
        json_object_array_length(entries) > 4096)
      throw std::runtime_error("Invalid application catalog");
    std::set<std::string> ids, generic_ids;
    for (size_t i = 0; i < json_object_array_length(entries); ++i) {
      auto *entry = json_object_array_get_idx(entries, i);
      App app;
      app.id = text(entry, "id");
      if (app.id.empty() || app.id.size() > 128 || !ids.insert(app.id).second)
        throw std::runtime_error("Invalid application ID");
      app.names = strings(entry, "protocol_names", 32);
      app.domains = strings(entry, "domains", 4096);
      app.allow = boolean(entry, "allow_over_port_deny");
      const auto kind = text(entry, "kind", "application");
      if (kind != "application" && kind != "protocol")
        throw std::runtime_error("Invalid runtime application kind");
      app.generic = kind == "protocol";
      if (app.generic)
        generic_ids.insert(app.id);
      if (app.generic && app.allow)
        throw std::runtime_error(
            "Generic protocols cannot grant a port exception");
      for (auto &name : app.names)
        name = normalize(name);
      for (auto &domain : app.domains) {
        std::transform(
            domain.begin(), domain.end(), domain.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (domain.size() < 3 ||
            domain.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyz0123456789.-") != std::string::npos)
          throw std::runtime_error("Invalid literal catalog domain");
      }
      apps.push_back(std::move(app));
    }
    // Build once, outside the packet path. Conflicting domain ownership is
    // deliberately unclassified instead of attributing a shared CDN to the
    // first application in a large catalog.
    for (size_t i = 0; i < apps.size(); ++i) {
      for (const auto &name : apps[i].names) {
        auto previous = protocol_index.find(name);
        if (previous == protocol_index.end() ||
            (apps[previous->second].generic && !apps[i].generic))
          protocol_index[name] = i;
      }
      for (const auto &domain : apps[i].domains) {
        auto [previous, inserted] = domain_index.emplace(domain, i);
        if (!inserted && previous->second != i)
          previous->second = SIZE_MAX;
      }
    }
    auto *items = field(root, "rules");
    if (!items || !json_object_is_type(items, json_type_array) ||
        json_object_array_length(items) > 512)
      throw std::runtime_error("Invalid bounded application rules");
    std::set<std::string> rule_ids;
    for (size_t i = 0; i < json_object_array_length(items); ++i) {
      auto *item = json_object_array_get_idx(items, i);
      Rule rule;
      rule.id = text(item, "id");
      rule.action = text(item, "action");
      if (rule.id.empty() || !rule_ids.insert(rule.id).second ||
          (rule.action != "allow" && rule.action != "block"))
        throw std::runtime_error("Invalid application rule");
      rule.apps = strings(item, "application_ids", 256);
      if (rule.apps.empty())
        throw std::runtime_error("Empty application match");
      for (const auto &id : rule.apps)
        if (!ids.count(id) || generic_ids.count(id))
          throw std::runtime_error("Unknown catalog application");
      rule.inputs = strings(item, "in_interfaces", 64);
      rule.outputs = strings(item, "out_interfaces", 64);
      rule.states = strings(item, "connection_states", 3);
      for (const auto &state : rule.states)
        if (state != "NEW" && state != "ESTABLISHED" && state != "RELATED")
          throw std::runtime_error("Invalid rule state");
      rule.sources = networks(item, "src_addresses");
      rule.destinations = networks(item, "dst_addresses");
      rules.push_back(std::move(rule));
    }
  }
  const App *protocol(const std::string &name) const {
    auto found = protocol_index.find(name);
    return found == protocol_index.end() ? nullptr : &apps[found->second];
  }
  const App *hostname(std::string host) const {
    std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) {
      return static_cast<char>(std::tolower(c));
    });
    if (!host.empty() && host.back() == '.')
      host.pop_back();
    // Longest suffix wins, with a DNS-label boundary. An ambiguous exact
    // suffix does not fall back to a broader provider/category attribution.
    while (!host.empty()) {
      auto found = domain_index.find(host);
      if (found != domain_index.end())
        return found->second == SIZE_MAX ? nullptr : &apps[found->second];
      auto dot = host.find('.');
      if (dot == std::string::npos)
        break;
      host.erase(0, dot + 1);
    }
    return nullptr;
  }
};
struct Packet {
  uint32_t source = 0, destination = 0;
  uint16_t sport = 0, dport = 0;
  uint8_t protocol = 0;
  const uint8_t *payload = nullptr;
  size_t payload_size = 0;
  bool valid = false;
};
uint16_t be16(const uint8_t *p) {
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
Packet parse_packet(const uint8_t *bytes, size_t size) {
  Packet packet;
  if (size < 20 || bytes[0] >> 4 != 4)
    return packet;
  size_t ihl = (bytes[0] & 15U) * 4U, total = be16(bytes + 2);
  if (ihl < 20 || ihl > size || total > size || total < ihl ||
      (be16(bytes + 6) & 0x3fffU))
    return packet;
  packet.protocol = bytes[9];
  std::memcpy(&packet.source, bytes + 12, 4);
  std::memcpy(&packet.destination, bytes + 16, 4);
  if (packet.protocol == IPPROTO_TCP) {
    if (total < ihl + 20)
      return packet;
    size_t tcp = (bytes[ihl + 12] >> 4) * 4U;
    if (tcp < 20 || total < ihl + tcp)
      return packet;
    packet.sport = be16(bytes + ihl);
    packet.dport = be16(bytes + ihl + 2);
    packet.payload = bytes + ihl + tcp;
    packet.payload_size = total - ihl - tcp;
  } else if (packet.protocol == IPPROTO_UDP) {
    if (total < ihl + 8)
      return packet;
    size_t udp = be16(bytes + ihl + 4);
    if (udp < 8 || total < ihl + udp)
      return packet;
    packet.sport = be16(bytes + ihl);
    packet.dport = be16(bytes + ihl + 2);
    packet.payload = bytes + ihl + 8;
    packet.payload_size = udp - 8;
  } else
    return packet;
  packet.valid = true;
  return packet;
}
std::string address(uint32_t value) {
  char buffer[INET_ADDRSTRLEN]{};
  in_addr ip{};
  ip.s_addr = value;
  return inet_ntop(AF_INET, &ip, buffer, sizeof(buffer)) ? buffer : "";
}
std::string interface_name(uint32_t index) {
  char name[IFNAMSIZ]{};
  return index && if_indextoname(index, name) ? name : "";
}
bool in_networks(uint32_t ip, const std::vector<Network> &nets) {
  return nets.empty() ||
         std::any_of(nets.begin(), nets.end(),
                     [ip](const Network &n) { return n.contains(ip); });
}
bool has(const std::vector<std::string> &items, const std::string &value) {
  return items.empty() ||
         std::find(items.begin(), items.end(), value) != items.end();
}
// Owned, bounded TLS ClientHello SNI parser; never decrypts or treats SNI as
// strong identity.
std::string tls_hostname(const uint8_t *bytes, size_t size) {
  if (size < 9 || bytes[0] != 22 || bytes[1] != 3)
    return "";
  size_t record = be16(bytes + 3);
  if (record > size - 5 || record < 4 || bytes[5] != 1)
    return "";
  size_t handshake = (static_cast<size_t>(bytes[6]) << 16) |
                     (static_cast<size_t>(bytes[7]) << 8) | bytes[8];
  if (handshake > record - 4 || handshake < 38)
    return "";
  size_t end = 9 + handshake, pos = 9 + 34;
  if (pos >= end)
    return "";
  size_t session = bytes[pos++];
  if (session > end - pos)
    return "";
  pos += session;
  if (end - pos < 2)
    return "";
  size_t cipher = be16(bytes + pos);
  pos += 2;
  if (!cipher || cipher > end - pos)
    return "";
  pos += cipher;
  if (pos >= end)
    return "";
  size_t compression = bytes[pos++];
  if (!compression || compression > end - pos)
    return "";
  pos += compression;
  if (end - pos < 2)
    return "";
  size_t extensions = be16(bytes + pos);
  pos += 2;
  if (extensions > end - pos)
    return "";
  end = pos + extensions;
  while (end - pos >= 4) {
    auto kind = be16(bytes + pos);
    size_t length = be16(bytes + pos + 2);
    pos += 4;
    if (length > end - pos)
      return "";
    if (!kind) {
      if (length < 5)
        return "";
      size_t names = be16(bytes + pos);
      if (names + 2 != length || bytes[pos + 2] != 0)
        return "";
      size_t name_size = be16(bytes + pos + 3);
      if (!name_size || name_size > 253 || name_size + 5 > length)
        return "";
      std::string name(reinterpret_cast<const char *>(bytes + pos + 5),
                       name_size);
      for (auto &c : name) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' &&
            c != '-')
          return "";
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      return name;
    }
    pos += length;
  }
  return "";
}
struct Request {
  uint32_t magic = IPC_MAGIC, length = 0;
  uint64_t token = 0, time_ms = 0;
  uint8_t direction = 0, reserved[7]{};
  std::array<uint8_t, MAX_PACKET> packet{};
};
struct Response {
  uint32_t magic = IPC_MAGIC;
  uint16_t app_protocol = 0, master_protocol = 0;
  uint64_t token = 0;
  uint8_t confidence = 0, final = 0, hostname_evidence = 0, reserved = 0;
  std::array<char, 128> name{};
  std::array<char, 254> hostname{};
};
// Upstream license diagnostics use printf; reserve stdout for our framed JSON.
class DiagnosticRedirect {
  int saved_ = -1;

public:
  DiagnosticRedirect() {
    std::fflush(stdout);
    saved_ = dup(STDOUT_FILENO);
    if (saved_ < 0 || dup2(STDERR_FILENO, STDOUT_FILENO) < 0)
      throw std::runtime_error("Cannot frame engine diagnostics");
  }
  ~DiagnosticRedirect() {
    std::fflush(stdout);
    if (saved_ >= 0) {
      dup2(saved_, STDOUT_FILENO);
      close(saved_);
    }
  }
};
struct Engine {
  ndpi_detection_module_struct *module = nullptr;
  explicit Engine(const std::string &profile = "lgpl-only") {
    DiagnosticRedirect diagnostics;
    ndpi_license_type license =
        profile == "not-for-profit"       ? NDPI_LICENSE_NOT_FOR_PROFIT_LGPL
        : profile == "commercial-license" ? NDPI_LICENSE_FOR_PROFIT_DUAL_LICENSE
                                          : NDPI_LICENSE_FOR_PROFIT_LGPL;
    module = ndpi_init_detection_module(nullptr, license);
    if (!module)
      throw std::runtime_error("Cannot initialize permitted DPI engine");
    if (ndpi_finalize_initialization(module)) {
      ndpi_exit_detection_module(module);
      module = nullptr;
      throw std::runtime_error("Cannot finalize DPI engine");
    }
  }
  ~Engine() {
    if (module)
      ndpi_exit_detection_module(module);
  }
  Engine(const Engine &) = delete;
  Engine &operator=(const Engine &) = delete;
};
void worker_sandbox(pid_t parent) {
  rlimit address_limit{256ULL * 1024 * 1024, 256ULL * 1024 * 1024}, core{0, 0},
      files{16, 16}, processes{1, 1};
#ifdef OMR_EMULATION_TEST
  (void)address_limit;
  if (setrlimit(RLIMIT_CORE, &core) ||
#else
  if (setrlimit(RLIMIT_AS, &address_limit) || setrlimit(RLIMIT_CORE, &core) ||
#endif
      setrlimit(RLIMIT_NOFILE, &files) || setrlimit(RLIMIT_NPROC, &processes))
    throw std::runtime_error("Cannot restrict classifier resources");
  if (geteuid() == 0) {
    if (setgroups(0, nullptr) || setgid(65534) || setuid(65534))
      throw std::runtime_error("Cannot drop classifier identity");
  }
  if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent)
    throw std::runtime_error("Classifier parent changed");
  if (prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    throw std::runtime_error("Cannot restrict classifier privileges");
#if defined(__x86_64__)
  constexpr uint32_t arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
  constexpr uint32_t arch = AUDIT_ARCH_AARCH64;
#else
#error Unsupported native classifier architecture
#endif
  std::vector<sock_filter> program{
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
  };
  // The parser needs only its already-open private socket, memory management,
  // clocks and process-local signal bookkeeping. Default-deny also covers
  // io_uring, future file/network syscalls and cross-process signaling/ptrace.
  const std::vector<int> allowed{
      __NR_read,
      __NR_write,
      __NR_close,
      __NR_recvfrom,
      __NR_sendto,
      __NR_recvmsg,
      __NR_sendmsg,
      __NR_readv,
      __NR_writev,
      __NR_mmap,
      __NR_mprotect,
      __NR_munmap,
      __NR_brk,
      __NR_madvise,
      __NR_mremap,
      __NR_futex,
      __NR_clock_gettime,
      __NR_gettimeofday,
      __NR_getpid,
      __NR_getppid,
      __NR_gettid,
      __NR_getuid,
      __NR_geteuid,
      __NR_getgid,
      __NR_getegid,
      __NR_rt_sigaction,
      __NR_rt_sigprocmask,
      __NR_rt_sigreturn,
      __NR_sigaltstack,
      __NR_nanosleep,
      __NR_sched_yield,
      __NR_getrandom,
      __NR_restart_syscall,
      __NR_exit,
      __NR_exit_group,
#ifdef __NR_fstat
      __NR_fstat,
#endif
#ifdef __NR_time
      __NR_time,
#endif
#ifdef __NR_clock_gettime64
      __NR_clock_gettime64,
#endif
  };
  for (int call : allowed) {
    program.push_back(
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<uint32_t>(call), 0, 1));
    program.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
  }
  program.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
  sock_fprog filter{static_cast<unsigned short>(program.size()),
                    program.data()};
#ifdef OMR_EMULATION_TEST
  (void)filter; // Rosetta cannot install the guest syscall filter; never a
                // release binary.
#else
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter))
    throw std::runtime_error("Cannot install classifier syscall sandbox");
#endif
}
struct NativeFlow {
  ndpi_flow_struct *flow = nullptr;
  uint64_t last = 0;
  NativeFlow() {
    flow = static_cast<ndpi_flow_struct *>(
        ndpi_flow_malloc(sizeof(ndpi_flow_struct)));
    if (!flow)
      throw std::bad_alloc();
    std::memset(flow, 0, sizeof(*flow));
  }
  ~NativeFlow() {
    if (flow)
      ndpi_free_flow(flow);
  }
};
void classifier_loop(int fd, const std::string &profile, pid_t parent) {
  Engine engine(profile);
  std::unordered_map<uint64_t, std::unique_ptr<NativeFlow>> flows;
  worker_sandbox(parent);
  uint32_t ready = IPC_MAGIC;
  if (send(fd, &ready, sizeof(ready), MSG_NOSIGNAL) != sizeof(ready))
    return;
  Request request;
  while (!stopping) {
    ssize_t size = recv(fd, &request, sizeof(request), 0);
    if (size <= 0)
      break;
    constexpr size_t header = offsetof(Request, packet);
    if (request.magic != IPC_MAGIC || request.length > MAX_PACKET ||
        size != static_cast<ssize_t>(header + request.length))
      return;
    if (!request.length) {
      flows.erase(request.token);
      continue;
    }
    if (flows.size() >= MAX_FLOWS && !flows.count(request.token)) {
      auto oldest = std::min_element(flows.begin(), flows.end(),
                                     [](const auto &a, const auto &b) {
                                       return a.second->last < b.second->last;
                                     });
      if (oldest != flows.end())
        flows.erase(oldest);
    }
    auto &entry = flows[request.token];
    if (!entry)
      entry = std::make_unique<NativeFlow>();
    entry->last = request.time_ms;
    ndpi_flow_input_info info{};
    info.in_pkt_dir =
        request.direction ? NDPI_IN_PKT_DIR_S_TO_C : NDPI_IN_PKT_DIR_C_TO_S;
    info.seen_flow_beginning = NDPI_FLOW_BEGINNING_UNKNOWN;
    auto detected = ndpi_detection_process_packet(
        engine.module, entry->flow, request.packet.data(),
        static_cast<uint16_t>(request.length), request.time_ms, &info);
    Response response;
    response.token = request.token;
    response.app_protocol = detected.proto.app_protocol;
    response.master_protocol = detected.proto.master_protocol;
    response.confidence = static_cast<uint8_t>(entry->flow->confidence);
    response.final = detected.state == NDPI_STATE_CLASSIFIED ||
                     detected.state == NDPI_STATE_MONITORING;
    const char *name = ndpi_get_proto_name(
        engine.module, response.app_protocol ? response.app_protocol
                                             : response.master_protocol);
    if (name)
      std::snprintf(response.name.data(), response.name.size(), "%s", name);
    auto parsed = parse_packet(request.packet.data(), request.length);
    std::string hostname =
        parsed.valid && parsed.protocol == IPPROTO_TCP
            ? tls_hostname(parsed.payload, parsed.payload_size)
            : "";
    response.hostname_evidence =
        hostname.empty() && entry->flow->host_server_name[0] == 0 ? 0 : 1;
    if (hostname.empty())
      hostname = entry->flow->host_server_name;
    std::snprintf(response.hostname.data(), response.hostname.size(), "%s",
                  hostname.c_str());
    if (send(fd, &response, sizeof(response), MSG_NOSIGNAL) != sizeof(response))
      return;
  }
}
class Worker {
  int fd_ = -1;
  pid_t child_ = -1;

public:
  explicit Worker(const std::string &profile, int ready_ms = 5000) {
    const pid_t supervisor = getpid();
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets))
      throw std::runtime_error("Cannot create private classifier IPC");
    child_ = fork();
    if (child_ < 0) {
      close(sockets[0]);
      close(sockets[1]);
      throw std::runtime_error("Cannot fork classifier");
    }
    if (!child_) {
      if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != supervisor)
        _exit(70);
      close(sockets[0]);
      // No inherited directory, policy or host descriptor reaches the packet
      // parser.
      for (int candidate = 3; candidate < 65536; ++candidate)
        if (candidate != sockets[1])
          close(candidate);
      try {
        classifier_loop(sockets[1], profile, supervisor);
        close(sockets[1]);
        _exit(0);
      } catch (const std::exception &failure) {
        std::cerr << "Classifier: " << failure.what() << "\n";
        _exit(70);
      }
    }
    close(sockets[1]);
    fd_ = sockets[0];
    pollfd poller{fd_, POLLIN, 0};
    uint32_t ready = 0;
    if (poll(&poller, 1, ready_ms) != 1 ||
        recv(fd_, &ready, sizeof(ready), 0) != sizeof(ready) ||
        ready != IPC_MAGIC) {
      int result = 0;
      pid_t ended = waitpid(child_, &result, WNOHANG);
      std::string detail;
      if (ended == child_) {
        if (WIFSIGNALED(result))
          detail = " signal=" + std::to_string(WTERMSIG(result));
        child_ = -1;
      }
      shutdown_worker();
      throw std::runtime_error("Classifier sandbox did not become ready" +
                               detail);
    }
  }
  ~Worker() { shutdown_worker(); }
  void shutdown_worker() {
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
    if (child_ > 0) {
      kill(child_, SIGTERM);
      for (int i = 0; i < 20; ++i) {
        if (waitpid(child_, nullptr, WNOHANG) == child_) {
          child_ = -1;
          return;
        }
        usleep(10000);
      }
      if (kill(child_, SIGKILL) == 0)
        waitpid(child_, nullptr, 0);
      child_ = -1;
    }
  }
  bool alive() {
    if (child_ <= 0)
      return false;
    int state = 0;
    pid_t value = waitpid(child_, &state, WNOHANG);
    if (value == 0)
      return true;
    if (value == child_ || (value < 0 && errno == ECHILD)) {
      child_ = -1;
      if (fd_ >= 0) {
        close(fd_);
        fd_ = -1;
      }
      return false;
    }
    return true;
  }
  pid_t pid() const { return child_; }
  Response inspect(uint64_t token, const uint8_t *bytes, size_t size,
                   bool reverse, int timeout_ms) {
    Request request;
    request.token = token;
    request.time_ms = monotonic_ms();
    request.length = static_cast<uint32_t>(size);
    request.direction = reverse;
    if (size > MAX_PACKET)
      throw std::runtime_error("Oversized classification packet");
    std::copy(bytes, bytes + size, request.packet.begin());
    size_t length = offsetof(Request, packet) + size;
    if (send(fd_, &request, length, MSG_NOSIGNAL | MSG_DONTWAIT) !=
        static_cast<ssize_t>(length))
      throw std::runtime_error("Classifier IPC send failed");
    pollfd poller{fd_, POLLIN, 0};
    Response response;
    if (poll(&poller, 1, timeout_ms) != 1 ||
        recv(fd_, &response, sizeof(response), MSG_DONTWAIT) !=
            sizeof(response) ||
        response.magic != IPC_MAGIC || response.token != token ||
        !memchr(response.name.data(), 0, response.name.size()) ||
        !memchr(response.hostname.data(), 0, response.hostname.size()))
      throw std::runtime_error(
          "Classifier response deadline or contract failed");
    return response;
  }
};
struct Flow {
  uint64_t token = 0, packets = 0, bytes = 0, started_ms = 0, last_ms = 0;
  double first_seen = 0, last_seen = 0;
  uint32_t source = 0, destination = 0, translated_destination = 0;
  uint16_t source_port = 0, destination_port = 0, translated_port = 0;
  uint8_t protocol = 0;
  std::string connection_state = "UNKNOWN";
  std::string input, output, app,
      method = "unknown", reason = "classification_pending",
      classification = "pending", decision = "fallback", rule_id, protocol_name;
  bool pending = true, strong = false, failed = false, probe_viable = true,
       generic = false;
  uint32_t profile = 0;
};
class Manager {
  const Policy &policy_;
  Worker worker_;
  std::map<std::string, Flow> flows_;
  Flow admission_failure_;
  uint64_t next_ = 1, packets_ = 0, rate_window_ = 0, last_sweep_ = 0;
  uint64_t admission_failures_ = 0;
  unsigned global_new_ = 0;
  double started_ = unix_time();
  std::unordered_map<uint32_t, std::pair<uint64_t, unsigned>> client_rates_;
  bool healthy_ = true;
  std::string failure_;
  bool scope_match(const Rule &rule, const Flow &flow,
                   const std::string &state) const {
    return in_networks(flow.source, rule.sources) &&
           in_networks(flow.translated_destination ? flow.translated_destination
                                                   : flow.destination,
                       rule.destinations) &&
           has(rule.inputs, flow.input) && has(rule.outputs, flow.output) &&
           has(rule.states, state);
  }
  uint32_t outcome(const Flow &flow, const std::string &state,
                   std::string *matched = nullptr) const {
    if (flow.pending) {
      if (!flow.probe_viable)
        return 0;
      std::set<std::string> decided;
      for (const auto &rule : policy_.rules) {
        if (!scope_match(rule, flow, state))
          continue;
        for (const auto &id : rule.apps) {
          if (!decided.insert(id).second || rule.action != "allow")
            continue;
          auto app =
              std::find_if(policy_.apps.begin(), policy_.apps.end(),
                           [&id](const App &value) { return value.id == id; });
          if (app != policy_.apps.end() && app->allow) {
            if (matched)
              *matched = rule.id;
            return 1;
          }
        }
      }
      return 0;
    }
    for (const auto &rule : policy_.rules) {
      if (!scope_match(rule, flow, state))
        continue;
      if (std::find(rule.apps.begin(), rule.apps.end(), flow.app) ==
          rule.apps.end())
        continue;
      if (matched)
        *matched = rule.id;
      if (rule.action == "block")
        return 3;
      auto app = std::find_if(
          policy_.apps.begin(), policy_.apps.end(),
          [&flow](const App &value) { return value.id == flow.app; });
      if (flow.strong && app != policy_.apps.end() && app->allow)
        return 2;
      return policy_.unknown_policy == "block" ? 3 : 0;
    }
    return !flow.pending &&
                   (flow.failed ? policy_.failure_policy
                                : policy_.unknown_policy) == "block" &&
                   (flow.app.empty() || flow.generic || !flow.strong)
               ? 3
               : 0;
  }

public:
  explicit Manager(const Policy &policy)
      : policy_(policy), worker_(policy.engine_profile) {}
  Flow *process(const Packet &packet, const uint8_t *bytes, size_t length,
                const std::string &key, uint32_t original_source,
                uint32_t original_destination, uint16_t original_sport,
                uint16_t original_dport, const std::string &input,
                const std::string &output,
                const std::string &ct_state = "UNKNOWN",
                bool reply_direction = false) {
    ++packets_;
    uint64_t now = monotonic_ms();
    if (now - last_sweep_ >= 1000) {
      last_sweep_ = now;
      for (auto it = flows_.begin(); it != flows_.end();) {
        if (now - it->second.last_ms > 60000)
          it = flows_.erase(it);
        else
          ++it;
      }
      for (auto it = client_rates_.begin(); it != client_rates_.end();) {
        if (now - it->second.first > 60000)
          it = client_rates_.erase(it);
        else
          ++it;
      }
    }
    auto existing = flows_.find(key);
    if (existing == flows_.end()) {
      if (!in_networks(original_source, policy_.scopes))
        return nullptr;
      if (flows_.size() >= MAX_FLOWS) {
        // Preserve existing application decisions, especially for interface-
        // constrained flows which must revisit this process on every packet.
        // An untracked admission cannot borrow any existing CT permission.
        ++admission_failures_;
        admission_failure_ = Flow{};
        admission_failure_.pending = false;
        admission_failure_.failed = true;
        admission_failure_.classification = "unknown";
        admission_failure_.reason = "flow_capacity_drop";
        admission_failure_.decision = "block";
        admission_failure_.profile = 3U | (3U << 2) | (3U << 4);
        return &admission_failure_;
      }
      Flow flow;
      flow.token = next_++;
      flow.source = original_source;
      flow.destination = original_destination;
      flow.source_port = original_sport;
      flow.destination_port = original_dport;
      flow.protocol = packet.protocol;
      bool original_direction = ct_state != "UNKNOWN"
                                    ? !reply_direction
                                    : (packet.source == original_source &&
                                       packet.sport == original_sport);
      flow.translated_destination =
          original_direction ? packet.destination : packet.source;
      flow.translated_port = original_direction ? packet.dport : packet.sport;
      flow.started_ms = now;
      flow.first_seen = unix_time();
      flow.input = input;
      flow.output = output;
      existing = flows_.emplace(key, std::move(flow)).first;
      if (now - rate_window_ >= 1000) {
        rate_window_ = now;
        global_new_ = 0;
      }
      if (client_rates_.size() >= MAX_FLOWS &&
          !client_rates_.count(original_source)) {
        existing->second.pending = false;
        existing->second.failed = true;
        ++admission_failures_;
        existing->second.reason = "client_rate_capacity";
      } else {
        auto &rate = client_rates_[original_source];
        if (now - rate.first >= 1000) {
          rate.first = now;
          rate.second = 0;
        }
        if (++rate.second > 20 || ++global_new_ > 256) {
          existing->second.pending = false;
          existing->second.failed = true;
          ++admission_failures_;
          existing->second.reason = "new_flow_rate";
        }
      }
      if (!existing->second.pending)
        existing->second.classification = "unknown";
      size_t pending = 0, client_pending = 0;
      for (const auto &pair : flows_)
        if (pair.second.pending) {
          ++pending;
          if (pair.second.source == original_source)
            ++client_pending;
        }
      if (pending > static_cast<size_t>(policy_.max_pending) ||
          client_pending > static_cast<size_t>(policy_.max_per_client)) {
        existing->second.pending = false;
        existing->second.failed = true;
        ++admission_failures_;
        existing->second.classification = "unknown";
        existing->second.reason = "pending_capacity";
      }
    }
    Flow &flow = existing->second;
    flow.connection_state = ct_state;
    if (policy_.reevaluate_interfaces && ct_state != "UNKNOWN") {
      flow.input = input;
      flow.output = output;
    }
    flow.last_ms = now;
    flow.last_seen = unix_time();
    ++flow.packets;
    flow.bytes += length;
    if (flow.packets > 1 && !flow.pending && !policy_.reevaluate_interfaces) {
      uint32_t shift = ct_state == "NEW" ? 0 : ct_state == "RELATED" ? 4 : 2;
      uint32_t outcome = (flow.profile >> shift) & 3;
      flow.decision = outcome == 3   ? "block"
                      : outcome == 2 ? "allow"
                      : outcome == 1 ? "probe"
                                     : "fallback";
      return &flow;
    }
    if (flow.pending) {
      if (now - flow.started_ms > static_cast<uint64_t>(policy_.timeout_ms) ||
          flow.packets > static_cast<uint64_t>(policy_.probe_packets) ||
          flow.bytes > static_cast<uint64_t>(policy_.probe_bytes)) {
        flow.pending = false;
        flow.classification = "unknown";
        flow.reason = "classification_budget";
      } else {
        try {
          auto result = worker_.inspect(flow.token, bytes, length,
                                        ct_state != "UNKNOWN"
                                            ? reply_direction
                                            : packet.source != flow.source,
                                        policy_.verdict_ms);
          flow.protocol_name = result.name.data();
          std::string normalized = normalize(flow.protocol_name);
          const App *found = policy_.protocol(normalized);
          // nDPI can know the transport/application with DPI confidence while
          // remaining PARTIAL to collect metadata or recognize a sub-app. Such
          // traffic must stop receiving the temporary port-denial exception as
          // soon as its positively identified protocol is not an Allow-capable
          // candidate. Keep inspecting if needed, under the ordinary firewall.
          if (result.confidence == NDPI_CONFIDENCE_DPI &&
              (result.app_protocol || result.master_protocol) &&
              (!found || !found->allow))
            flow.probe_viable = false;
          bool domain_only = false;
          if ((!found || found->generic) && result.hostname[0]) {
            if (const auto *service =
                    policy_.hostname(result.hostname.data())) {
              found = service;
              domain_only = true;
            }
          }
          if (found &&
              (result.final || result.confidence == NDPI_CONFIDENCE_DPI) &&
              (!found->generic || result.final || domain_only)) {
            flow.app = found->id;
            flow.generic = found->generic;
            flow.strong = !domain_only && !result.hostname_evidence &&
                          result.confidence == NDPI_CONFIDENCE_DPI;
            flow.method =
                flow.strong
                    ? "dpi"
                    : (domain_only || result.hostname_evidence ? "hostname"
                       : result.confidence == NDPI_CONFIDENCE_MATCH_BY_IP
                           ? "ip"
                           : "heuristic");
            flow.pending = false;
            flow.classification = "detected";
            flow.reason = flow.strong ? "dpi_protocol" : "weak_evidence";
          } else if (result.final && result.app_protocol) {
            flow.pending = false;
            flow.classification = "unknown";
            flow.reason = "unmapped_protocol";
          }
        } catch (const std::exception &error) {
          flow.pending = false;
          flow.failed = true;
          flow.classification = "unknown";
          flow.reason = "classifier_unavailable";
          healthy_ = false;
          failure_ = error.what();
        }
      }
    }
    flow.profile = 0;
    flow.rule_id.clear();
    const std::array<std::string, 3> states{{"NEW", "ESTABLISHED", "RELATED"}};
    for (size_t i = 0; i < states.size(); ++i)
      flow.profile |= outcome(flow, states[i], i == 1 ? &flow.rule_id : nullptr)
                      << (i * 2);
    uint32_t shift = ct_state == "NEW" ? 0 : ct_state == "RELATED" ? 4 : 2;
    uint32_t effective = (flow.profile >> shift) & 3;
    flow.decision = effective == 3   ? "block"
                    : effective == 2 ? "allow"
                    : effective == 1 ? "probe"
                                     : "fallback";
    return &flow;
  }
  bool healthy() {
    if (healthy_ && !worker_.alive()) {
      healthy_ = false;
      failure_ = "classifier_exited";
    }
    return healthy_;
  }
  pid_t worker_pid() const { return worker_.pid(); }
  uint32_t mark(const Flow &flow) const {
    return (policy_.epoch << 8) | VALID | (flow.pending ? PENDING : 0) |
           flow.profile;
  }
  Json status() const {
    auto result = own(json_object_new_object());
    auto *r = result.get();
    add(r, "schema", uint64_t(1));
    add(r, "mode", policy_.mode);
    add(r, "generation", policy_.generation);
    add(r, "healthy", healthy_);
    add(r, "engine_version", ndpi_revision());
    add(r, "engine_profile", policy_.engine_profile);
    add(r, "packets", packets_);
    add(r, "flows", static_cast<uint64_t>(flows_.size()));
    add(r, "flow_capacity", static_cast<uint64_t>(MAX_FLOWS));
    add(r, "admission_failures", admission_failures_);
    add(r, "worker_pid", static_cast<uint64_t>(worker_.pid()));
    add(r, "started_at", started_);
    add(r, "updated_at", unix_time());
    add(r, "error", failure_);
    return result;
  }
  Json snapshot() const {
    auto result = own(json_object_new_object());
    auto *r = result.get();
    add(r, "schema", uint64_t(1));
    add(r, "generation", policy_.generation);
    add(r, "timestamp", unix_time());
    auto *items = json_object_new_array();
    json_object_object_add(r, "items", items);
    size_t count = 0;
    for (auto it = flows_.rbegin(); it != flows_.rend() && count < 500;
         ++it, ++count) {
      const auto &flow = it->second;
      auto *item = json_object_new_object();
      json_object_array_add(items, item);
      add(item, "id", std::to_string(flow.token));
      add(item, "application_id", flow.app);
      add(item, "source", address(flow.source));
      add(item, "destination", address(flow.destination));
      add(item, "translated_destination",
          flow.translated_destination != flow.destination
              ? address(flow.translated_destination)
              : "");
      add(item, "translated_port", uint64_t(flow.translated_port));
      add(item, "source_port", uint64_t(flow.source_port));
      add(item, "destination_port", uint64_t(flow.destination_port));
      add(item, "protocol", flow.protocol == IPPROTO_TCP ? "tcp" : "udp");
      add(item, "in_interface", flow.input);
      add(item, "out_interface", flow.output);
      add(item, "connection_state", flow.connection_state);
      add(item, "classification_state", flow.classification);
      add(item, "decision", flow.decision);
      add(item, "method", flow.method);
      add(item, "reason", flow.reason);
      add(item, "rule_id", flow.rule_id);
      add(item, "protocol_name", flow.protocol_name);
      add(item, "counters_complete", false);
      add(item, "counter_source",
          policy_.mode == "observe" ? "capture" : "classification");
      add(item, "interface_basis",
          policy_.mode == "observe" ? "capture" : "netfilter");
      add(item, "packets", flow.packets);
      add(item, "bytes", flow.bytes);
      add(item, "first_seen", flow.first_seen);
      add(item, "last_seen", flow.last_seen);
      add(item, "pending", flow.pending);
    }
    return result;
  }
};
class StateWriter {
  int directory_ = -1;
  uint64_t serial_ = 0;

public:
  explicit StateWriter(const std::string &path) {
    directory_ =
        open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat details{};
    if (directory_ < 0 || fstat(directory_, &details) ||
        details.st_uid != geteuid() || (details.st_mode & 0022))
      throw std::runtime_error(
          "Runtime directory must be owned and not group/world writable");
  }
  ~StateWriter() {
    if (directory_ >= 0)
      close(directory_);
  }
  void write(const std::string &name, json_object *value) {
    std::string temporary =
        ".native-" + std::to_string(getpid()) + "-" + std::to_string(++serial_);
    const char *raw =
        json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
    size_t size = std::strlen(raw);
    if (size > 2 * 1024 * 1024)
      throw std::runtime_error("Runtime snapshot exceeds bounded contract");
    int fd = openat(directory_, temporary.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
      throw std::runtime_error("Cannot create runtime snapshot");
    size_t done = 0;
    while (done < size) {
      ssize_t count = ::write(fd, raw + done, size - done);
      if (count <= 0) {
        close(fd);
        unlinkat(directory_, temporary.c_str(), 0);
        throw std::runtime_error("Cannot write runtime snapshot");
      }
      done += static_cast<size_t>(count);
    }
    if (fsync(fd)) {
      close(fd);
      unlinkat(directory_, temporary.c_str(), 0);
      throw std::runtime_error("Cannot sync runtime snapshot");
    }
    close(fd);
    if (renameat(directory_, temporary.c_str(), directory_, name.c_str())) {
      unlinkat(directory_, temporary.c_str(), 0);
      throw std::runtime_error("Cannot activate runtime snapshot");
    }
  }
  void update(const Manager &manager) {
    auto status = manager.status(), flows = manager.snapshot();
    write("status.json", status.get());
    write("flows.json", flows.get());
  }
};
struct Conntrack {
  uint32_t source = 0, destination = 0, id = 0, mark = 0;
  uint16_t sport = 0, dport = 0, zone = 0;
  uint8_t protocol = 0;
  bool valid = false;
};
struct AttrTable {
  nlattr **items;
  size_t maximum;
};
int collect_attr(const nlattr *attribute, void *data) {
  auto *table = static_cast<AttrTable *>(data);
  unsigned type = mnl_attr_get_type(attribute);
  if (type <= table->maximum)
    table->items[type] = const_cast<nlattr *>(attribute);
  return MNL_CB_OK;
}
bool attr_size(const nlattr *attribute, size_t size) {
  return attribute && mnl_attr_get_payload_len(attribute) == size;
}
Conntrack conntrack(const nlattr *attribute) {
  Conntrack result;
  if (!attribute)
    return result;
  std::array<nlattr *, CTA_MAX + 1> ct{};
  AttrTable table{ct.data(), CTA_MAX};
  if (mnl_attr_parse_nested(attribute, collect_attr, &table) < 0 ||
      !ct[CTA_TUPLE_ORIG] || !attr_size(ct[CTA_ID], 4))
    return result;
  result.id = ntohl(mnl_attr_get_u32(ct[CTA_ID]));
  if (attr_size(ct[CTA_ZONE], 2))
    result.zone = ntohs(mnl_attr_get_u16(ct[CTA_ZONE]));
  if (attr_size(ct[CTA_MARK], 4))
    result.mark = ntohl(mnl_attr_get_u32(ct[CTA_MARK]));
  std::array<nlattr *, CTA_TUPLE_MAX + 1> tuple{};
  table = {tuple.data(), CTA_TUPLE_MAX};
  if (mnl_attr_parse_nested(ct[CTA_TUPLE_ORIG], collect_attr, &table) < 0 ||
      !tuple[CTA_TUPLE_IP] || !tuple[CTA_TUPLE_PROTO])
    return result;
  std::array<nlattr *, CTA_IP_MAX + 1> ip{};
  table = {ip.data(), CTA_IP_MAX};
  if (mnl_attr_parse_nested(tuple[CTA_TUPLE_IP], collect_attr, &table) < 0 ||
      !attr_size(ip[CTA_IP_V4_SRC], 4) || !attr_size(ip[CTA_IP_V4_DST], 4))
    return result;
  result.source = mnl_attr_get_u32(ip[CTA_IP_V4_SRC]);
  result.destination = mnl_attr_get_u32(ip[CTA_IP_V4_DST]);
  std::array<nlattr *, CTA_PROTO_MAX + 1> protocol{};
  table = {protocol.data(), CTA_PROTO_MAX};
  if (mnl_attr_parse_nested(tuple[CTA_TUPLE_PROTO], collect_attr, &table) < 0 ||
      !attr_size(protocol[CTA_PROTO_NUM], 1) ||
      !attr_size(protocol[CTA_PROTO_SRC_PORT], 2) ||
      !attr_size(protocol[CTA_PROTO_DST_PORT], 2))
    return result;
  result.protocol = mnl_attr_get_u8(protocol[CTA_PROTO_NUM]);
  result.sport = ntohs(mnl_attr_get_u16(protocol[CTA_PROTO_SRC_PORT]));
  result.dport = ntohs(mnl_attr_get_u16(protocol[CTA_PROTO_DST_PORT]));
  result.valid =
      result.protocol == IPPROTO_TCP || result.protocol == IPPROTO_UDP;
  return result;
}
std::string flow_key(const Conntrack &ct) {
  return std::to_string(ct.zone) + ":" + std::to_string(ct.id) + ":" +
         std::to_string(ct.source) + ":" + std::to_string(ct.destination) +
         ":" + std::to_string(ct.protocol) + ":" + std::to_string(ct.sport) +
         ":" + std::to_string(ct.dport);
}
class Queue {
  const Policy &policy_;
  Manager &manager_;
  mnl_socket *socket_ = nullptr;
  uint32_t sequence_ = 0;
  static int packet_callback(const nlmsghdr *message, void *data) {
    return static_cast<Queue *>(data)->packet(message);
  }
  void config(nlmsghdr *message) {
    message->nlmsg_flags |= NLM_F_ACK;
    message->nlmsg_seq = ++sequence_;
    if (mnl_socket_sendto(socket_, message, message->nlmsg_len) < 0)
      throw std::runtime_error("NFQUEUE configuration send failed");
    pollfd waiting{mnl_socket_get_fd(socket_), POLLIN, 0};
    if (poll(&waiting, 1, 2000) != 1)
      throw std::runtime_error("NFQUEUE configuration ACK timed out");
    std::array<char, 8192> response{};
    ssize_t count =
        mnl_socket_recvfrom(socket_, response.data(), response.size());
    if (count < 0 ||
        mnl_cb_run(response.data(), static_cast<size_t>(count), sequence_,
                   mnl_socket_get_portid(socket_), nullptr, nullptr) < 0)
      throw std::runtime_error(
          "NFQUEUE unavailable, already owned, or unsupported");
  }
  int verdict(uint32_t id, uint32_t result, uint32_t mark, bool ct) {
    std::array<char, 4096> buffer{};
    auto *message =
        nfq_nlmsg_put(buffer.data(), NFQNL_MSG_VERDICT, policy_.queue);
    nfq_nlmsg_verdict_put(message, id, result);
    if (ct) {
      auto *nested = mnl_attr_nest_start(message, NFQA_CT);
      mnl_attr_put_u32(message, CTA_MARK, htonl(mark & OWN_MASK));
      mnl_attr_put_u32(message, CTA_MARK_MASK, htonl(OWN_MASK));
      mnl_attr_nest_end(message, nested);
    }
    if (mnl_socket_sendto(socket_, message, message->nlmsg_len) < 0)
      return MNL_CB_ERROR;
    return MNL_CB_OK;
  }
  int packet(const nlmsghdr *message) {
    try {
      std::array<nlattr *, NFQA_MAX + 1> attrs{};
      if (nfq_nlmsg_parse(message, attrs.data()) < 0 ||
          !attr_size(attrs[NFQA_PACKET_HDR], sizeof(nfqnl_msg_packet_hdr)))
        return MNL_CB_ERROR;
      const auto *header = static_cast<const nfqnl_msg_packet_hdr *>(
          mnl_attr_get_payload(attrs[NFQA_PACKET_HDR]));
      uint32_t id = ntohl(header->packet_id);
      if (!attrs[NFQA_PAYLOAD])
        return verdict(id, NF_DROP, 0, false);
      auto *bytes = static_cast<const uint8_t *>(
          mnl_attr_get_payload(attrs[NFQA_PAYLOAD]));
      size_t length = mnl_attr_get_payload_len(attrs[NFQA_PAYLOAD]);
      if (length > MAX_PACKET ||
          (attr_size(attrs[NFQA_CAP_LEN], 4) &&
           ntohl(mnl_attr_get_u32(attrs[NFQA_CAP_LEN])) > length))
        return verdict(id, NF_DROP, 0, false);
      auto parsed = parse_packet(bytes, length);
      auto ct = conntrack(attrs[NFQA_CT]);
      if (!parsed.valid || !ct.valid || parsed.protocol != ct.protocol)
        return verdict(id, NF_DROP, 0, false);
      uint32_t input = attr_size(attrs[NFQA_IFINDEX_INDEV], 4)
                           ? ntohl(mnl_attr_get_u32(attrs[NFQA_IFINDEX_INDEV]))
                           : 0;
      uint32_t output =
          attr_size(attrs[NFQA_IFINDEX_OUTDEV], 4)
              ? ntohl(mnl_attr_get_u32(attrs[NFQA_IFINDEX_OUTDEV]))
              : 0;
      uint32_t info = attr_size(attrs[NFQA_CT_INFO], 4)
                          ? ntohl(mnl_attr_get_u32(attrs[NFQA_CT_INFO]))
                          : 99;
      std::string state = info < 6 ? (info % 3 == 0   ? "ESTABLISHED"
                                      : info % 3 == 1 ? "RELATED"
                                                      : "NEW")
                                   : "UNKNOWN";
      if (state == "UNKNOWN")
        return verdict(id, NF_DROP, 0, false);
      const std::string incoming = interface_name(info >= 3 ? output : input);
      const std::string outgoing = interface_name(info >= 3 ? input : output);
      auto *flow = manager_.process(
          parsed, bytes, length, flow_key(ct), ct.source, ct.destination,
          ct.sport, ct.dport, incoming, outgoing, state, info >= 3);
      if (!manager_.healthy())
        return verdict(id, NF_DROP, 0, false);
      if (!flow)
        return verdict(id, NF_ACCEPT, 0, false);
      // The filter hook independently checks real conntrack state and current
      // generation. Never use NFQA_MARK: skb marks belong to routing/WireGuard.
      return verdict(id, NF_ACCEPT, manager_.mark(*flow), true);
    } catch (...) {
      return MNL_CB_ERROR;
    }
  }

public:
  Queue(const Policy &policy, Manager &manager)
      : policy_(policy), manager_(manager) {
    socket_ = mnl_socket_open(NETLINK_NETFILTER);
    if (!socket_)
      throw std::runtime_error("Cannot open NFQUEUE Netlink socket");
    if (mnl_socket_bind(socket_, 0, MNL_SOCKET_AUTOPID) < 0) {
      mnl_socket_close(socket_);
      socket_ = nullptr;
      throw std::runtime_error("Cannot bind private NFQUEUE socket");
    }
    try {
      std::array<char, 4096> buffer{};
      auto *message =
          nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, policy_.queue);
      nfq_nlmsg_cfg_put_cmd(message, AF_INET, NFQNL_CFG_CMD_BIND);
      config(message);
      message = nfq_nlmsg_put(buffer.data(), NFQNL_MSG_CONFIG, policy_.queue);
      nfq_nlmsg_cfg_put_params(message, NFQNL_COPY_PACKET, MAX_PACKET);
      mnl_attr_put_u32(message, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_CONNTRACK));
      mnl_attr_put_u32(
          message, NFQA_CFG_MASK,
          htonl(NFQA_CFG_F_CONNTRACK | NFQA_CFG_F_FAIL_OPEN | NFQA_CFG_F_GSO));
      mnl_attr_put_u32(message, NFQA_CFG_QUEUE_MAXLEN,
                       htonl(static_cast<uint32_t>(policy_.queue_limit)));
      config(message);
      int fd = mnl_socket_get_fd(socket_);
      int receive = 4 * 1024 * 1024;
      if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive, sizeof(receive)))
        throw std::runtime_error("Cannot bound queue socket buffer");
    } catch (...) {
      mnl_socket_close(socket_);
      socket_ = nullptr;
      throw;
    }
  }
  ~Queue() {
    if (socket_)
      mnl_socket_close(socket_);
  }
  void run(StateWriter &writer) {
    std::array<char, 131072> buffer{};
    uint64_t last = 0;
    writer.update(manager_);
    while (!stopping && manager_.healthy()) {
      pollfd waiting{mnl_socket_get_fd(socket_), POLLIN, 0};
      int ready = poll(&waiting, 1, 100);
      if (ready < 0 && errno != EINTR)
        throw std::runtime_error("NFQUEUE poll failed");
      if (ready > 0) {
        ssize_t count =
            mnl_socket_recvfrom(socket_, buffer.data(), buffer.size());
        if (count < 0 || mnl_cb_run(buffer.data(), static_cast<size_t>(count),
                                    0, 0, packet_callback, this) < 0)
          throw std::runtime_error(
              "NFQUEUE receive or classifier contract failed");
      }
      if (monotonic_ms() - last >= 1000) {
        writer.update(manager_);
        last = monotonic_ms();
      }
    }
    writer.update(manager_);
    if (!manager_.healthy())
      throw std::runtime_error(
          "Classifier unavailable; managed enforcement must fail closed");
  }
};
std::string raw_flow_key(const Packet &packet) {
  std::pair<uint32_t, uint16_t> left{packet.source, packet.sport},
      right{packet.destination, packet.dport};
  if (left > right)
    std::swap(left, right);
  return std::to_string(left.first) + ":" + std::to_string(left.second) + ":" +
         std::to_string(right.first) + ":" + std::to_string(right.second) +
         ":" + std::to_string(packet.protocol);
}
void observe(const Policy &policy, Manager &manager, StateWriter &writer) {
  std::vector<pollfd> sockets;
  try {
    for (const auto &name : policy.interfaces) {
      unsigned index = if_nametoindex(name.c_str());
      if (!index)
        throw std::runtime_error("Scoped observation interface is missing");
      // Outgoing packets are delivered to ETH_P_ALL taps, not
      // EtherType-specific receive handlers. SOCK_DGRAM keeps the network
      // header at byte zero; parse_packet below admits only valid IPv4 TCP/UDP
      // in the explicit scope.
      int fd = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_ALL));
      if (fd < 0)
        throw std::runtime_error("Passive observation requires CAP_NET_RAW");
      sockaddr_ll bind_address{};
      bind_address.sll_family = AF_PACKET;
      bind_address.sll_protocol = htons(ETH_P_ALL);
      bind_address.sll_ifindex = static_cast<int>(index);
      if (bind(fd, reinterpret_cast<sockaddr *>(&bind_address),
               sizeof(bind_address))) {
        close(fd);
        throw std::runtime_error("Cannot bind scoped passive interface");
      }
      sockets.push_back({fd, POLLIN, 0});
    }
    std::array<uint8_t, MAX_PACKET> bytes{};
    uint64_t last = 0;
    writer.update(manager);
    while (!stopping && manager.healthy()) {
      int ready = poll(sockets.data(), sockets.size(), 100);
      if (ready < 0 && errno != EINTR)
        throw std::runtime_error("Passive observation poll failed");
      if (ready > 0)
        for (size_t i = 0; i < sockets.size(); ++i)
          if (sockets[i].revents & POLLIN) {
            ssize_t size =
                recv(sockets[i].fd, bytes.data(), bytes.size(), MSG_DONTWAIT);
            if (size <= 0)
              continue;
            auto packet = parse_packet(bytes.data(), static_cast<size_t>(size));
            if (!packet.valid)
              continue;
            bool original = in_networks(packet.source, policy.scopes),
                 reply = in_networks(packet.destination, policy.scopes);
            if (!original && !reply)
              continue;
            manager.process(packet, bytes.data(), static_cast<size_t>(size),
                            raw_flow_key(packet),
                            original ? packet.source : packet.destination,
                            original ? packet.destination : packet.source,
                            original ? packet.sport : packet.dport,
                            original ? packet.dport : packet.sport,
                            policy.interfaces[i], "");
          }
      if (monotonic_ms() - last >= 1000) {
        writer.update(manager);
        last = monotonic_ms();
      }
    }
    writer.update(manager);
  } catch (...) {
    for (auto item : sockets)
      close(item.fd);
    throw;
  }
  for (auto item : sockets)
    close(item.fd);
}
Json capabilities(const std::string &profile) {
  Engine engine(profile);
  auto value = own(json_object_new_object());
  auto *r = value.get();
#ifdef OMR_EMULATION_TEST
  add(r, "test_instrumentation", true);
#else
  add(r, "test_instrumentation", false);
#endif
  add(r, "schema", uint64_t(1));
  add(r, "available", true);
  add(r, "observe", true);
  add(r, "enforce", true);
  add(r, "nfqueue", true);
  add(r, "allow_over_port_deny", true);
  add(r, "ct_metadata", "NFQA_CT/CTA_MARK_MASK");
  add(r, "ct_mask", uint64_t(OWN_MASK));
  add(r, "ct_valid_bit", uint64_t(VALID));
  add(r, "ct_pending_bit", uint64_t(PENDING));
  add(r, "ct_epoch_shift", uint64_t(8));
  auto *limits = json_object_new_object();
  json_object_object_add(r, "limits", limits);
  add(limits, "flow_capacity", uint64_t(MAX_FLOWS));
  add(limits, "snapshot_flows", uint64_t(500));
  add(limits, "new_flows_per_client_per_second", uint64_t(20));
  add(limits, "new_flows_global_per_second", uint64_t(256));
  auto *engine_info = json_object_new_object();
  json_object_object_add(r, "engine", engine_info);
  add(engine_info, "name", "ndpi");
  add(engine_info, "version", ndpi_revision());
  add(engine_info, "profile", profile);
  add(engine_info, "restricted_components_enabled", profile != "lgpl-only");
  add(engine_info, "commit", "cd1d03a52f0c968f1835110d70f5da652171a5d5");
  auto *protocols = json_object_new_array();
  json_object_object_add(r, "protocols", protocols);
  for (unsigned id = 1; id < ndpi_get_num_protocols(engine.module); ++id) {
    const char *name =
        ndpi_get_proto_name(engine.module, static_cast<uint16_t>(id));
    if (profile == "lgpl-only" && name &&
        (std::string(name) == "DNS" || std::string(name) == "DHCP" ||
         std::string(name) == "TLS" || std::string(name) == "DTLS" ||
         std::string(name) == "QUIC"))
      continue;

    if (!name || !*name || std::string(name) == "Unknown")
      continue;
    auto *item = json_object_new_object();
    json_object_array_add(protocols, item);
    add(item, "id", uint64_t(id));
    add(item, "name", name);
  }
  return value;
}
void replay(const Policy &policy, const std::string &path) {
  std::ifstream input(path, std::ios::binary);
  std::array<uint8_t, 24> header{};
  if (!input.read(reinterpret_cast<char *>(header.data()), header.size()))
    throw std::runtime_error("Invalid PCAP header");
  uint32_t magic;
  std::memcpy(&magic, header.data(), 4);
  bool little = magic == 0xa1b2c3d4U;
  if (!little && magic != 0xd4c3b2a1U)
    throw std::runtime_error("Only classic bounded PCAP supported");
  auto word = [little](const uint8_t *p) {
    uint32_t n;
    std::memcpy(&n, p, 4);
    return little ? n : __builtin_bswap32(n);
  };
  uint32_t link = word(header.data() + 20);
  if (link != 1 && link != 101)
    throw std::runtime_error("PCAP must contain Ethernet or raw IPv4");
  Manager manager(policy);
  size_t packets = 0;
  std::array<uint8_t, 16> record{};
  while (input.read(reinterpret_cast<char *>(record.data()), record.size())) {
    size_t length = word(record.data() + 8);
    if (length > MAX_PACKET + 64 || ++packets > 100000)
      throw std::runtime_error("PCAP exceeds replay limits");
    std::vector<uint8_t> bytes(length);
    if (!input.read(reinterpret_cast<char *>(bytes.data()), length))
      throw std::runtime_error("Truncated PCAP packet");
    size_t offset = link == 1 ? 14 : 0;
    if (length < offset)
      continue;
    if (link == 1 && be16(bytes.data() + 12) != 0x0800)
      continue;
    auto packet = parse_packet(bytes.data() + offset, length - offset);
    if (!packet.valid)
      continue;
    bool original = in_networks(packet.source, policy.scopes);
    if (!original && !in_networks(packet.destination, policy.scopes))
      continue;
    manager.process(
        packet, bytes.data() + offset, length - offset, raw_flow_key(packet),
        original ? packet.source : packet.destination,
        original ? packet.destination : packet.source,
        original ? packet.sport : packet.dport,
        original ? packet.dport : packet.sport, policy.interfaces[0], "");
  }
  auto result = manager.snapshot();
  std::cout << json_object_to_json_string_ext(result.get(),
                                              JSON_C_TO_STRING_PLAIN)
            << '\n';
}
} // namespace omr
int main(int argc, char **argv) {
  using namespace omr;
  signal(SIGTERM, stop_signal);
  signal(SIGINT, stop_signal);
  signal(SIGPIPE, SIG_IGN);
  try {
    if (argc < 2)
      throw std::runtime_error(
          "Expected capabilities, validate, run or replay command");
    std::string command = argv[1], policy_path, state_dir, pcap,
                license_profile = "lgpl-only";
    for (int i = 2; i < argc; ++i) {
      std::string key = argv[i];
      if (key == "--json")
        continue;
      if (i + 1 >= argc)
        throw std::runtime_error("Missing command argument");
      std::string value = argv[++i];
      if (key == "--policy")
        policy_path = value;
      else if (key == "--state-dir")
        state_dir = value;
      else if (key == "--pcap")
        pcap = value;
      else if (key == "--license-profile")
        license_profile = value;
      else
        throw std::runtime_error("Unknown command argument");
    }
    if (license_profile != "lgpl-only" && license_profile != "not-for-profit" &&
        license_profile != "commercial-license")
      throw std::runtime_error("Invalid engine license profile");
    if (command == "capabilities") {
      auto result = capabilities(license_profile);
      std::cout << json_object_to_json_string_ext(result.get(),
                                                  JSON_C_TO_STRING_PLAIN)
                << '\n';
      return 0;
    }
    if (policy_path.empty())
      throw std::runtime_error("Owned policy path required");
    auto root = read_json(policy_path);
    Policy policy(root.get());
    if (command == "validate") {
      Engine engine(policy.engine_profile);
      std::cout << "{\"schema\":1,\"valid\":true}\n";
      return 0;
    }
    if (command == "replay") {
      if (pcap.empty())
        throw std::runtime_error("PCAP path required");
      replay(policy, pcap);
      return 0;
    }
    if (command != "run" || state_dir.empty())
      throw std::runtime_error("Invalid native command");
    StateWriter writer(state_dir);
    Manager manager(policy);
    if (policy.mode == "observe")
      observe(policy, manager, writer);
    else {
      Queue queue(policy, manager);
      queue.run(writer);
    }
    auto result = manager.status();
    add(result.get(), "healthy", false);
    add(result.get(), "error", "runtime_stopped");
    writer.write("status.json", result.get());
    return 0;
  } catch (const std::exception &error) {
    std::cerr << "OpenMikroRout native: " << error.what() << '\n';
    return 70;
  }
}
