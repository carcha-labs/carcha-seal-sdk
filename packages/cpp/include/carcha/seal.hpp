// Carcha Seal for C++ (C++17): licensing for desktop apps that keeps working offline. A thin, header-only
// layer over the native library's C interface (seal.h); the client logic, lease verification and
// decryption run there, with the same behaviour as the Electron SDK.
//
//   carcha::seal::Options options;
//   options.product = "studio";
//   options.server_url = "https://seal.carchalabs.com/<your slug>";
//   options.public_keys = kPublicKeys;            // compiled into your app, not read from a file
//   options.storage_dir = app_data_dir;           // license.dat is kept here
//   carcha::seal::Client client(options);         // the built-in HTTP client, or pass your own
//   carcha::seal::State state = client.check();
//   if (state.has_feature("pro")) { ... }
//
// Operations that fail throw carcha::seal::LicenseError with the SDK's code and a message to show.
// One call at a time runs on a Client; calls from several threads wait for each other.
#pragma once

#include <seal.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace carcha::seal {

/// A refusal or failure: code ("network", "activation_limit", "wrong_device", ...) and a message for the user.
class LicenseError : public std::runtime_error {
 public:
  LicenseError(std::string code, const std::string& message) : std::runtime_error(message), code_(std::move(code)) {}
  const std::string& code() const noexcept { return code_; }

 private:
  std::string code_;
};

enum class Status { Valid, Grace, Invalid, Unlicensed, ClockSuspect };

inline const char* to_string(Status s) {
  switch (s) {
    case Status::Valid: return "valid";
    case Status::Grace: return "grace";
    case Status::Invalid: return "invalid";
    case Status::Unlicensed: return "unlicensed";
    case Status::ClockSuspect: return "clock_suspect";
  }
  return "invalid";
}

/// The license state, as the Electron SDK's LicenseState. Dates are ISO 8601 UTC.
struct State {
  Status status = Status::Unlicensed;
  bool offline = false;
  bool storage_protected = false;
  /// The license came from an offline license file.
  bool offline_activated = false;
  std::optional<std::string> reason;
  std::optional<std::string> message;
  std::optional<std::string> customer;
  std::vector<std::string> features;
  std::optional<std::string> expires_at;
  std::optional<std::string> maintenance_until;
  std::optional<std::string> revalidate_by;
  std::optional<std::string> key_hint;
  /// The server's notices (sdk_update_recommended, app_update_recommended, ...) as a JSON array.
  std::optional<std::string> notices_json;

  bool usable() const { return status == Status::Valid || status == Status::Grace; }
  bool has_feature(std::string_view feature) const {
    if (!usable()) return false;
    for (const auto& f : features)
      if (f == feature) return true;
    return false;
  }
};

/// A request to the license server: POST `body` (JSON) to `url` with this User-Agent.
struct HttpRequest {
  std::string url;
  std::string user_agent;
  std::string body;
};

/// The server's answer. status 0: no answer (no connection, timeout, TLS failure, a redirect).
struct HttpResponse {
  int status = 0;
  std::string body;
};

/// Sends a request. Your own must POST with Content-Type: application/json and the User-Agent, refuse
/// redirects, use a timeout, and return status 0 when there was no answer.
using Transport = std::function<HttpResponse(const HttpRequest&)>;

#ifdef SEAL_HAS_HTTP
/// The built-in HTTP client: certificates checked by the OS, the proxy from HTTPS_PROXY / ALL_PROXY (on Windows
/// also the user's proxy setting; not PAC scripts), redirects not followed.
inline HttpResponse builtin_post(const HttpRequest& request, std::chrono::milliseconds timeout = std::chrono::milliseconds(8000)) {
  uint8_t* body = nullptr;
  size_t len = 0;
  const auto ms = static_cast<uint32_t>(timeout.count() > 0 ? timeout.count() : 1);
  const int32_t status = seal_http_post(request.url.c_str(), request.user_agent.c_str(), request.body.c_str(), ms, &body, &len);
  if (status < 0) throw std::invalid_argument("carcha::seal: the request cannot be sent (not https:// or this computer)");
  HttpResponse response{status, body ? std::string(reinterpret_cast<const char*>(body), len) : std::string()};
  seal_bytes_free(body, len);
  return response;
}
#endif

struct Options {
  /// Your product code.
  std::string product;
  /// https://, or http:// on this computer only. A hosted vendor's is https://seal.carchalabs.com/<slug>.
  std::string server_url;
  /// The Ed25519 public keys you trust (PEM), in your app's code.
  std::string public_keys;
  /// The folder that keeps license.dat.
  std::string storage_dir;
  /// Sent so you can require a minimum app version.
  std::optional<std::string> app_version;
  /// Offline grace when the lease has none (default: 7 days).
  std::optional<double> grace_days;
  /// Send hashed hardware components and this device's public key (default true).
  bool hardware = true;
  /// Tests only: a fixed raw machine id instead of this machine's.
  std::optional<std::string> machine_id;
  /// Tests only: the clock, milliseconds since the Unix epoch (default: the system clock).
  std::function<double()> now_ms;
  /// How requests are sent; empty: the built-in HTTP client (when built with it).
  Transport transport;
};

namespace detail {
struct ResultDeleter {
  void operator()(seal_result* r) const noexcept { seal_result_free(r); }
};
struct ClientDeleter {
  void operator()(seal_client* c) const noexcept { seal_client_free(c); }
};
using Result = std::unique_ptr<seal_result, ResultDeleter>;

inline std::optional<std::string> opt(const char* s) { return s ? std::optional<std::string>(s) : std::nullopt; }
inline std::string str(const char* s) { return s ? std::string(s) : std::string(); }

inline Result checked(seal_result* r) {
  if (!r) throw std::invalid_argument("carcha::seal: invalid argument");
  return Result(r);
}

/// Throws the result's LicenseError, if it is one.
inline void throw_if_error(const Result& r) {
  if (seal_result_kind(r.get()) == SEAL_RESULT_ERROR)
    throw LicenseError(str(seal_result_error_code(r.get())), str(seal_result_error_message(r.get())));
}

inline State state_of(const Result& r) {
  throw_if_error(r);
  const seal_result* p = r.get();
  State s;
  switch (seal_state_status(p)) {
    case SEAL_STATUS_VALID: s.status = Status::Valid; break;
    case SEAL_STATUS_GRACE: s.status = Status::Grace; break;
    case SEAL_STATUS_INVALID: s.status = Status::Invalid; break;
    case SEAL_STATUS_UNLICENSED: s.status = Status::Unlicensed; break;
    case SEAL_STATUS_CLOCK_SUSPECT: s.status = Status::ClockSuspect; break;
    default: throw std::logic_error("carcha::seal: the result holds no license state");
  }
  s.offline = seal_state_flag(p, SEAL_FLAG_OFFLINE) == 1;
  s.storage_protected = seal_state_flag(p, SEAL_FLAG_STORAGE_PROTECTED) == 1;
  s.offline_activated = seal_state_flag(p, SEAL_FLAG_OFFLINE_ACTIVATED) == 1;
  s.reason = opt(seal_state_text(p, SEAL_FIELD_REASON));
  s.message = opt(seal_state_text(p, SEAL_FIELD_MESSAGE));
  s.customer = opt(seal_state_text(p, SEAL_FIELD_CUSTOMER));
  s.expires_at = opt(seal_state_text(p, SEAL_FIELD_EXPIRES_AT));
  s.maintenance_until = opt(seal_state_text(p, SEAL_FIELD_MAINTENANCE_UNTIL));
  s.revalidate_by = opt(seal_state_text(p, SEAL_FIELD_REVALIDATE_BY));
  s.key_hint = opt(seal_state_text(p, SEAL_FIELD_KEY_HINT));
  s.notices_json = opt(seal_state_text(p, SEAL_FIELD_NOTICES_JSON));
  const size_t n = seal_state_feature_count(p);
  s.features.reserve(n);
  for (size_t i = 0; i < n; ++i) s.features.emplace_back(str(seal_state_feature(p, i)));
  return s;
}

inline std::string text_of(const Result& r) {
  throw_if_error(r);
  return str(seal_result_text(r.get()));
}

inline const char* c_or_null(const std::optional<std::string>& s) { return s ? s->c_str() : nullptr; }
}  // namespace detail

class Client {
 public:
  /// Throws std::invalid_argument naming the problem ("insecure_server_url", "invalid_public_keys", ...).
  explicit Client(Options options) : options_(std::move(options)) {
    if (!options_.transport) {
#ifdef SEAL_HAS_HTTP
      options_.transport = [](const HttpRequest& request) { return builtin_post(request); };
#else
      throw std::invalid_argument("carcha::seal: no transport (this build has no built-in HTTP client)");
#endif
    }
    if (!options_.now_ms) {
      options_.now_ms = [] {
        using namespace std::chrono;
        return static_cast<double>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
      };
    }
    seal_client_options o;
    seal_client_options_init(&o);
    o.product = options_.product.c_str();
    o.server_url = options_.server_url.c_str();
    o.public_keys = options_.public_keys.c_str();
    o.storage_dir = options_.storage_dir.c_str();
    o.app_version = detail::c_or_null(options_.app_version);
    if (options_.grace_days) o.grace_days = *options_.grace_days;
    o.sdk_name = "cpp";
    o.machine_id = detail::c_or_null(options_.machine_id);
    o.hardware = options_.hardware ? 1 : 0;
    if (const char* problem = seal_client_options_error(&o)) throw std::invalid_argument(std::string("carcha::seal: ") + problem);
    client_.reset(seal_client_new(&o));
    if (!client_) throw std::runtime_error("carcha::seal: the client could not be created");
  }

  /// Activates this device. machine_name: what the vendor sees for this device (none by default: a host name
  /// often holds a person's name).
  State activate(std::string_view license_key, const std::optional<std::string>& machine_name = std::nullopt) {
    const std::string key(license_key);
    auto begin = detail::checked(seal_client_activate_begin(client_.get(), key.c_str(), detail::c_or_null(machine_name)));
    return detail::state_of(finish(begin, [this](int status, const std::string& body, double now) {
      return seal_client_activate_finish(client_.get(), status, bytes(body), body.size(), now);
    }));
  }

  /// Checks the license: online when the server answers, otherwise from the saved lease with its offline grace.
  State check() {
    const double now = options_.now_ms();
    auto begin = detail::checked(seal_client_check_begin(client_.get(), now));
    return detail::state_of(finish(begin, [this](int status, const std::string& body, double at) {
      return seal_client_check_finish(client_.get(), status, bytes(body), body.size(), at);
    }));
  }

  /// Releases this device's seat on the server and removes the license here.
  void deactivate() {
    auto begin = detail::checked(seal_client_deactivate_begin(client_.get()));
    detail::throw_if_error(finish(begin, [this](int status, const std::string& body, double) {
      return seal_client_deactivate_finish(client_.get(), status, bytes(body), body.size());
    }));
  }

  /// Offline activation, step 1: the request file (JSON text) for a machine that cannot reach the server.
  std::string offline_request(std::string_view license_key, const std::optional<std::string>& machine_name = std::nullopt) {
    const std::string key(license_key);
    return detail::text_of(detail::checked(seal_client_offline_request(client_.get(), key.c_str(), detail::c_or_null(machine_name))));
  }

  /// Offline activation, step 2: loads the license file the server issued for this machine's request.
  State activate_offline(std::string_view license_file) {
    const std::string file(license_file);
    return detail::state_of(detail::checked(seal_client_activate_offline(client_.get(), file.c_str(), options_.now_ms())));
  }

  /// Gives an offline machine's seat back: removes the license, returns the deactivation file (JSON text).
  std::string deactivate_offline() { return detail::text_of(detail::checked(seal_client_deactivate_offline(client_.get()))); }

  /// Decrypts data you encrypted for a feature, offline, with the saved lease. The content key stays in the library.
  std::vector<uint8_t> decrypt(std::string_view feature, const std::vector<uint8_t>& data) {
    const std::string name(feature);
    auto r = detail::checked(seal_client_decrypt(client_.get(), name.c_str(), data.empty() ? nullptr : data.data(), data.size(), options_.now_ms()));
    detail::throw_if_error(r);
    size_t len = 0;
    const uint8_t* plain = seal_result_data(r.get(), &len);
    return std::vector<uint8_t>(plain, plain + len);
  }

  const char* user_agent() const { return seal_client_user_agent(client_.get()); }

 private:
  static const uint8_t* bytes(const std::string& s) { return reinterpret_cast<const uint8_t*>(s.data()); }

  /// Sends the begin result's request when it has one and returns the finish result; otherwise the begin result.
  template <typename Finish>
  detail::Result finish(detail::Result& begin, Finish&& finish_call) {
    if (seal_result_kind(begin.get()) != SEAL_RESULT_SEND) return std::move(begin);
    HttpRequest request{detail::str(seal_result_request_url(begin.get())), detail::str(user_agent()), detail::str(seal_result_request_body(begin.get()))};
    begin.reset();
    const HttpResponse response = options_.transport(request);
    const int status = response.status >= 100 && response.status <= 599 ? response.status : 0;
    return detail::checked(finish_call(status, response.body, options_.now_ms()));
  }

  Options options_;
  std::unique_ptr<seal_client, detail::ClientDeleter> client_;
};

}  // namespace carcha::seal
