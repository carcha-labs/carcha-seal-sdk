// Every client scenario recorded from the Electron SDK (packages/client/tests/vectors.json, as lines from
// `cargo run --example scenarios_tsv`) through the C++ wrapper: the requests it sends through the
// transport and what it returns or throws, step by step, with license.dat in a folder.
// Usage: scenarios <scenarios.tsv> <folder> (emptied first)
#include <carcha/seal.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace seal = carcha::seal;

static const std::string NONE = "\\N";

static std::vector<std::string> split(const std::string& line) {
  std::vector<std::string> out;
  std::string field;
  for (size_t i = 0; i < line.size(); ++i) {
    char c = line[i];
    if (c == '\t') {
      out.push_back(field);
      field.clear();
    } else if (c == '\\' && i + 1 < line.size() && line[i + 1] != 'N') {
      char n = line[++i];
      field += n == 't' ? '\t' : n == 'n' ? '\n' : n;
    } else {
      field += c;
    }
  }
  out.push_back(field);
  return out;
}

static std::optional<std::string> opt(const std::string& s) { return s == NONE ? std::nullopt : std::optional<std::string>(s); }

static std::string platform() {
#if defined(_WIN32)
  return "win32";
#elif defined(__APPLE__)
  return "darwin";
#else
  return "linux";
#endif
}

/// The recorded placeholders filled with what this build sends.
static std::string fill(std::string s) {
  for (auto [from, to] : {std::pair<std::string, std::string>{"<sdk-version>", seal_version()}, {"<platform>", platform()}}) {
    for (size_t at = s.find(from); at != std::string::npos; at = s.find(from, at + to.size())) s.replace(at, from.size(), to);
  }
  return s;
}

static std::string hex(const std::vector<uint8_t>& bytes) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  for (uint8_t b : bytes) {
    out += digits[b >> 4];
    out += digits[b & 15];
  }
  return out;
}

static std::vector<uint8_t> unhex(const std::string& s) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i + 1 < s.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(s.substr(i, 2), nullptr, 16)));
  return out;
}

static int failures = 0;
static void expect(bool ok, const std::string& where, const std::string& what, const std::string& got = "", const std::string& want = "") {
  if (ok) return;
  ++failures;
  std::cout << "FAIL: " << where << ": " << what;
  if (!got.empty() || !want.empty()) std::cout << "\n  got:  " << got << "\n  want: " << want;
  std::cout << "\n";
}

static std::string show(const std::optional<std::string>& s) { return s ? *s : NONE; }

static std::string join(const std::vector<std::string>& v) {
  std::string out;
  for (size_t i = 0; i < v.size(); ++i) out += (i ? "," : "") + v[i];
  return out;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "usage: " << argv[0] << " <scenarios.tsv> <folder>\n";
    return 2;
  }
  std::ifstream in(argv[1]);
  const std::filesystem::path root = argv[2];
  // Every run starts with no saved license: a license.dat left by an earlier run would change the results.
  std::filesystem::remove_all(root);
  const std::string server = "https://seal.example.com";
  std::unique_ptr<seal::Client> client;
  std::string name;
  double now = 0;
  std::vector<seal::HttpRequest> sent;
  seal::HttpResponse scripted;
  int scenarios = 0, steps = 0;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    auto f = split(line);
    if (f[0] == "S") {
      name = f[1];
      seal::Options o;
      o.product = f[2];
      o.server_url = server;
      o.public_keys = f[3];
      o.storage_dir = (root / std::to_string(scenarios++)).string();
      if (f[4] != NONE) o.grace_days = std::stod(f[4]);
      o.app_version = opt(f[5]);
      o.machine_id = opt(f[6]);
      o.hardware = false;
      o.now_ms = [&now] { return now; };
      o.transport = [&sent, &scripted](const seal::HttpRequest& r) {
        sent.push_back(r);
        return scripted;
      };
      client = std::make_unique<seal::Client>(o);
      expect(std::string(client->user_agent()) == std::string("carcha-seal-native/") + seal_version() + " (cpp)", name, "user agent", client->user_agent());
      continue;
    }
    const std::string where = name + ", step " + f[1];
    now = std::stod(f[4]);
    scripted = seal::HttpResponse{f[5] == "-1" ? 0 : std::stoi(f[5]), f[6] == NONE ? std::string() : f[6]};
    sent.clear();
    const std::string& call = f[1];
    std::vector<std::string> outcome(f.begin() + 9, f.end());
    try {
      if (call == "activate" || call == "check" || call == "activateOffline") {
        seal::State s = call == "activate" ? client->activate(f[2], opt(f[3])) : call == "check" ? client->check() : client->activate_offline(f[2]);
        expect(outcome[0] == "V", where, "a state", "", outcome[0]);
        if (outcome[0] == "V") {
          const std::vector<std::string> got = {seal::to_string(s.status), s.offline ? "1" : "0", s.storage_protected ? "1" : "0", s.offline_activated ? "1" : "0", show(s.reason), show(s.message), show(s.customer), show(s.expires_at), show(s.maintenance_until), show(s.revalidate_by), show(s.key_hint), join(s.features), show(s.notices_json)};
          for (size_t i = 0; i < got.size(); ++i) expect(got[i] == outcome[i + 1], where, "state field " + std::to_string(i), got[i], outcome[i + 1]);
          bool usable = s.status == seal::Status::Valid || s.status == seal::Status::Grace;
          for (const auto& feature : s.features) expect(s.has_feature(feature) == usable, where, "has_feature");
        }
      } else if (call == "deactivate") {
        client->deactivate();
        expect(outcome[0] == "N", where, "nothing", "", outcome[0]);
      } else if (call == "offlineRequest" || call == "deactivateOffline") {
        std::string text = call == "offlineRequest" ? client->offline_request(f[2], opt(f[3])) : client->deactivate_offline();
        expect(outcome[0] == "X" && text == fill(outcome[1]), where, "file text", text, outcome.size() > 1 ? fill(outcome[1]) : "");
      } else if (call == "decrypt") {
        std::string plain = hex(client->decrypt(f[2], unhex(f[3])));
        expect(outcome[0] == "D" && plain == outcome[1], where, "decrypted data", plain, outcome.size() > 1 ? outcome[1] : "");
      } else {
        expect(false, where, "unknown call " + call);
      }
    } catch (const seal::LicenseError& e) {
      expect(outcome[0] == "E", where, "no error", e.code(), outcome[0]);
      if (outcome[0] == "E") {
        expect(e.code() == outcome[1], where, "error code", e.code(), outcome[1]);
        expect(std::string(e.what()) == outcome[2], where, "error message", e.what(), outcome[2]);
      }
    }
    if (f[7] == NONE) {
      expect(sent.empty(), where, "no request");
    } else {
      expect(sent.size() == 1, where, "one request");
      if (sent.size() == 1) {
        expect(sent[0].url == server + f[7], where, "request url", sent[0].url, server + f[7]);
        expect(sent[0].body == fill(f[8]), where, "request body", sent[0].body, fill(f[8]));
        expect(sent[0].user_agent == client->user_agent(), where, "request user agent");
      }
    }
    ++steps;
  }
  if (scenarios < 25 || steps < 90) {
    std::cout << "FAIL: only " << scenarios << " scenarios, " << steps << " steps\n";
    return 1;
  }

  // Options that are refused name the problem.
  seal::Options bad;
  bad.product = "studio";
  bad.server_url = "http://seal.example.com";
  bad.public_keys = "x";
  bad.storage_dir = (root / "bad").string();
  bad.transport = [](const seal::HttpRequest&) { return seal::HttpResponse{}; };
  try {
    seal::Client c(bad);
    expect(false, "options", "plain http accepted");
  } catch (const std::invalid_argument& e) {
    expect(std::string(e.what()) == "carcha::seal: insecure_server_url", "options", "error names the problem", e.what());
  }
  if (failures) {
    std::cout << failures << " failures\n";
    return 1;
  }
  std::cout << "seal " << seal_version() << ": " << scenarios << " scenarios, " << steps << " steps through the C++ wrapper\nOK\n";
  return 0;
}
