//! Carcha Seal license client for the native SDKs (C++, C#, Java): the same behaviour as the `Seal` class of
//! @carchalabs/seal-electron — activation, check-ins, offline grace, clock checks, refusals kept offline, offline
//! license files and feature decryption — checked against the scenarios in tests/vectors.json, which are recorded
//! from that SDK.
//!
//! The HTTP request is left to the caller, so it goes through the app's own network stack (proxy, certificates):
//! an operation that needs the server returns [`Outcome::Send`] with the request, and the caller passes the
//! server's answer to the matching `*_finish` method. Nothing here does network I/O.

use std::path::PathBuf;

use seal_lease::{DEFAULT_LEEWAY_SECONDS, DecryptError, Failure, Options, TrustedKey};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// File formats of offline activation, shared with the license server.
pub const OFFLINE_REQUEST_FORMAT: &str = "licensekit-offline-request";
pub const OFFLINE_LICENSE_FORMAT: &str = "licensekit-offline-license";
pub const OFFLINE_DEACTIVATION_FORMAT: &str = "licensekit-offline-deactivation";

/// Server refusals that are final until something changes on the server: kept, so going offline cannot bring the
/// license back.
const DEFINITIVE: [&str; 8] = [
    "invalid_key",
    "not_activated",
    "license_suspended",
    "license_revoked",
    "license_expired",
    "sdk_update_required",
    "app_update_required",
    "vm_not_allowed",
];
/// The license itself is gone: the key is forgotten too.
const FORGET_KEY: [&str; 2] = ["invalid_key", "license_revoked"];
const CLOCK_TOLERANCE_SECONDS: i64 = 24 * 3600;
/// A check-in answered 2xx whose lease fails for one of these reasons did not come from this app's license server for
/// this device (a TLS-inspecting proxy's or captive portal's page, say): it is treated as no answer, and the saved
/// lease is kept. A lease that fails only on time is the server's, and is used. As the Electron SDK.
const NOT_A_LEASE_FOR_THIS_DEVICE: [&str; 8] = ["malformed", "unsupported_algorithm", "wrong_type", "unknown_key", "bad_signature", "wrong_issuer", "wrong_product", "wrong_device"];
const DEFAULT_GRACE_DAYS: f64 = 7.0;
/// The server accepts at most this many hardware components.
const MAX_COMPONENTS: usize = 32;
const CLOCK_MESSAGE: &str = "The date and time on this computer look wrong. Correct them, then connect to the internet.";
const MACHINE_ID_MESSAGE: &str = "This computer's id could not be read. Try again; if it keeps failing, contact the app's support.";

fn reason_text(failure: Failure) -> &'static str {
    match failure {
        Failure::Malformed => "The saved license is damaged. Please activate again.",
        Failure::BadSignature => "The saved license was modified. Please activate again.",
        Failure::UnsupportedAlgorithm | Failure::WrongType | Failure::UnknownKey => "Please update the app.",
        Failure::WrongIssuer => "This license was issued by a different license server.",
        Failure::NotYetValid => CLOCK_MESSAGE,
        Failure::WrongProduct => "This license is for a different product.",
        Failure::WrongDevice => "This license is activated on another device.",
        Failure::Expired => "Your license has expired.",
        Failure::RevalidationRequired => "Connect to the internet to confirm your license.",
    }
}

// ---- Errors, states, requests --------------------------------------------------------------

/// A refusal or failure, with the SDK's code (`network`, `activation_limit`, `wrong_device`, …) and message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LicenseError {
    pub code: String,
    pub message: String,
    /// The HTTP status, when the server sent the refusal.
    pub status: Option<u16>,
}

impl LicenseError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> LicenseError {
        LicenseError { code: code.into(), message: message.into(), status: None }
    }
}

impl std::fmt::Display for LicenseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for LicenseError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Valid,
    Grace,
    Invalid,
    Unlicensed,
    ClockSuspect,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Valid => "valid",
            Status::Grace => "grace",
            Status::Invalid => "invalid",
            Status::Unlicensed => "unlicensed",
            Status::ClockSuspect => "clock_suspect",
        }
    }
}

/// The license state, as the SDK's LicenseState.
#[derive(Clone, Debug, PartialEq)]
pub struct State {
    pub status: Status,
    pub offline: bool,
    pub storage_protected: bool,
    pub reason: Option<String>,
    pub message: Option<String>,
    pub customer: Option<String>,
    pub features: Vec<String>,
    /// ISO 8601 (UTC); None for a perpetual license or no license.
    pub expires_at: Option<String>,
    /// Present (Some) on states from a lease: Some(None) means no maintenance date.
    pub maintenance_until: Option<Option<String>>,
    pub revalidate_by: Option<String>,
    pub key_hint: Option<String>,
    /// From the last successful check-in, as the server sent them; kept while offline.
    pub notices: Option<Vec<Value>>,
    /// The license came from an offline license file.
    pub offline_activated: bool,
}

impl State {
    fn empty(status: Status, offline: bool, storage_protected: bool) -> State {
        State {
            status,
            offline,
            storage_protected,
            reason: None,
            message: None,
            customer: None,
            features: Vec::new(),
            expires_at: None,
            maintenance_until: None,
            revalidate_by: None,
            key_hint: None,
            notices: None,
            offline_activated: false,
        }
    }

    /// True when the state grants the feature (valid or in grace).
    pub fn has_feature(&self, feature: &str) -> bool {
        matches!(self.status, Status::Valid | Status::Grace) && self.features.iter().any(|f| f == feature)
    }

    /// The state as the SDK's LicenseState JSON (camelCase, the same fields present).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("status".into(), json!(self.status.as_str()));
        m.insert("offline".into(), json!(self.offline));
        m.insert("storageProtected".into(), json!(self.storage_protected));
        let mut put = |name: &str, value: &Option<String>| {
            if let Some(v) = value {
                m.insert(name.into(), json!(v));
            }
        };
        put("reason", &self.reason);
        put("message", &self.message);
        put("customer", &self.customer);
        put("revalidateBy", &self.revalidate_by);
        put("keyHint", &self.key_hint);
        m.insert("features".into(), json!(self.features));
        m.insert("expiresAt".into(), json!(self.expires_at));
        if let Some(mnt) = &self.maintenance_until {
            m.insert("maintenanceUntil".into(), json!(mnt));
        }
        if let Some(notices) = &self.notices {
            m.insert("notices".into(), Value::Array(notices.clone()));
        }
        if self.offline_activated {
            m.insert("offlineActivated".into(), json!(true));
        }
        Value::Object(m)
    }
}

/// A request for the caller to send: POST `server_url + path` with `body` as JSON (Content-Type:
/// application/json), redirects refused, with a timeout.
#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub path: &'static str,
    pub body: Value,
}

/// What came back for a request.
#[derive(Clone, Debug)]
pub enum Response {
    /// No answer: no connection, a timeout, a refused redirect, a TLS failure.
    Network,
    /// An HTTP answer with its status and raw body.
    Http { status: u16, body: Vec<u8> },
}

/// The first half of an operation that may need the server.
#[derive(Debug)]
pub enum Outcome<T> {
    /// Send this request, then pass the answer to the operation's `*_finish` method.
    Send(Request),
    /// Finished without the server.
    Done(Result<T, LicenseError>),
}

// ---- Configuration and storage -------------------------------------------------------------

/// Hashed hardware components (see seal_hwid), sent with each request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hardware {
    /// (kind, lowercase hex hash).
    pub components: Vec<(String, String)>,
    pub vm: bool,
}

/// Where the client keeps its record (the license key, the signed lease, the last time seen, a refusal).
pub trait Storage {
    /// The saved record; None when there is none or it cannot be read.
    fn load(&self) -> Option<String>;
    fn save(&mut self, text: &str) -> std::io::Result<()>;
    fn clear(&mut self) -> std::io::Result<()>;
    /// True when the record is encrypted or otherwise protected by the OS.
    fn protected(&self) -> bool {
        false
    }
}

/// In memory only (tests, or an app that stores the record itself).
#[derive(Default)]
pub struct MemoryStorage(pub Option<String>);

impl Storage for MemoryStorage {
    fn load(&self) -> Option<String> {
        self.0.clone()
    }
    fn save(&mut self, text: &str) -> std::io::Result<()> {
        self.0 = Some(text.to_string());
        Ok(())
    }
    fn clear(&mut self) -> std::io::Result<()> {
        self.0 = None;
        Ok(())
    }
}

/// `license.dat` in a folder, as the Electron SDK keeps it (plain JSON; owner-only on Unix). It is replaced whole: written
/// to `license.dat.tmp` first, then renamed over it, so a crash or full disk mid-write leaves the previous record.
pub struct FileStorage {
    file: PathBuf,
}

impl FileStorage {
    pub fn new(dir: impl Into<PathBuf>) -> FileStorage {
        FileStorage { file: dir.into().join("license.dat") }
    }
}

impl Storage for FileStorage {
    fn load(&self) -> Option<String> {
        std::fs::read_to_string(&self.file).ok()
    }
    fn save(&mut self, text: &str) -> std::io::Result<()> {
        if let Some(dir) = self.file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let temp = self.file.with_extension("dat.tmp");
        let written = options.open(&temp).and_then(|mut f| {
            f.write_all(text.as_bytes())?;
            f.sync_all()
        });
        match written.and_then(|()| std::fs::rename(&temp, &self.file)) {
            Ok(()) => Ok(()),
            Err(e) => {
                let _ = std::fs::remove_file(&temp);
                Err(e)
            }
        }
    }
    fn clear(&mut self) -> std::io::Result<()> {
        match std::fs::remove_file(&self.file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

type Provider<T> = Box<dyn Fn() -> Option<T> + Send + Sync>;

/// What the client needs from the app and the platform.
pub struct Config {
    pub product: String,
    /// The Ed25519 keys the app trusts for leases, from its own code.
    pub keys: Vec<TrustedKey>,
    /// Offline grace when the lease has none (default 7 days).
    pub grace_days: Option<f64>,
    pub app_version: Option<String>,
    /// Sent so the vendor can see (and require) which SDK each device runs.
    pub sdk_version: String,
    /// "win32", "darwin" or "linux", as the Electron SDK sends it.
    pub platform: String,
    /// The raw OS machine id ("win:…", "mac:…", "linux:…"); None when it cannot be read.
    pub machine_id: Provider<String>,
    /// This device's hashed hardware components; None sends none.
    pub hardware: Provider<Hardware>,
    /// This device's X25519 public key (base64url), sent so feature keys are wrapped for it.
    pub device_public_key: Provider<String>,
    /// This device's secret, for leases whose feature keys were wrapped for its public key.
    pub device_secret: Provider<[u8; 32]>,
}

impl Config {
    /// A configuration with no hardware, device key or machine id providers; set them for a real device.
    pub fn new(product: impl Into<String>, keys: Vec<TrustedKey>, sdk_version: impl Into<String>, platform: impl Into<String>) -> Config {
        Config {
            product: product.into(),
            keys,
            grace_days: None,
            app_version: None,
            sdk_version: sdk_version.into(),
            platform: platform.into(),
            machine_id: Box::new(|| None),
            hardware: Box::new(|| None),
            device_public_key: Box::new(|| None),
            device_secret: Box::new(|| None),
        }
    }
}

/// The saved record, in the same JSON as the Electron SDK's license.dat.
#[derive(Clone, Debug, Default)]
struct Stored {
    license_key: String,
    /// Absent after the server refused this device.
    token: Option<String>,
    last_seen: Option<i64>,
    refused: Option<(String, String, i64)>,
    notices: Option<Vec<Value>>,
    /// Activated from an offline license file.
    offline: bool,
}

impl Stored {
    fn parse(text: &str) -> Option<Stored> {
        let v: Value = serde_json::from_str(text).ok()?;
        let o = v.as_object()?;
        let refused = o.get("refused").and_then(Value::as_object).and_then(|r| {
            Some((r.get("code")?.as_str()?.to_string(), r.get("message")?.as_str()?.to_string(), r.get("at")?.as_f64()? as i64))
        });
        Some(Stored {
            license_key: o.get("licenseKey")?.as_str()?.to_string(),
            token: o.get("token").and_then(Value::as_str).map(String::from),
            last_seen: o.get("lastSeen").and_then(Value::as_f64).map(|n| n as i64),
            refused,
            notices: o.get("notices").and_then(Value::as_array).cloned(),
            offline: o.get("offline").and_then(Value::as_bool).unwrap_or(false),
        })
    }

    fn to_json(&self) -> String {
        let mut m = Map::new();
        m.insert("licenseKey".into(), json!(self.license_key));
        if let Some(t) = &self.token {
            m.insert("token".into(), json!(t));
        }
        if let Some(s) = self.last_seen {
            m.insert("lastSeen".into(), json!(s));
        }
        if let Some((code, message, at)) = &self.refused {
            m.insert("refused".into(), json!({ "code": code, "message": message, "at": at }));
        }
        if let Some(n) = &self.notices {
            m.insert("notices".into(), Value::Array(n.clone()));
        }
        if self.offline {
            m.insert("offline".into(), json!(true));
        }
        Value::Object(m).to_string()
    }

    fn key_hint(&self) -> String {
        key_hint(&self.license_key)
    }
}

fn key_hint(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    let head: String = chars.iter().take(7).collect();
    let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
    format!("{head}…{tail}")
}

/// What a pending request needs when its answer comes.
enum Pending {
    Activate { key: String },
    Check { stored: Stored },
    Deactivate,
}

// ---- The client ----------------------------------------------------------------------------

pub struct Client<S: Storage> {
    config: Config,
    storage: S,
    fingerprint: Option<String>,
    hardware: Option<Option<Hardware>>,
    device_key: Option<Option<String>>,
    pending: Option<Pending>,
}

/// Refuses a server address that would send requests in plain text (OWASP ASVS 4.1.2, 12.2.1), as the Electron SDK's
/// checkServerUrl: every request carries the license key and the device's fingerprint. http:// is accepted for this
/// computer only (localhost, 127.x.x.x, [::1]), where a server under development runs.
pub fn check_server_url(server_url: &str) -> Result<(), LicenseError> {
    let url = url::Url::parse(server_url).map_err(|_| LicenseError::new("invalid_server_url", "serverUrl is not a valid URL."))?;
    if url.scheme() == "https" {
        return Ok(());
    }
    let host = url.host_str().unwrap_or_default();
    let ipv4_loopback = host.strip_prefix("127.").is_some_and(|rest| {
        let parts: Vec<&str> = rest.split('.').collect();
        parts.len() == 3 && parts.iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
    });
    if url.scheme() == "http" && (host == "localhost" || host == "[::1]" || ipv4_loopback) {
        return Ok(());
    }
    Err(LicenseError::new("insecure_server_url", "serverUrl must start with https:// (http:// only for localhost)."))
}

/// The address a request goes to: the server URL without trailing slashes, then the request's path.
pub fn request_url(server_url: &str, request: &Request) -> String {
    format!("{}{}", server_url.trim_end_matches('/'), request.path)
}

/// SHA-256 of "licensekit:<product>:<raw machine id>", lowercase hex: the device fingerprint the lease carries.
pub fn hash_fingerprint(raw_machine_id: &str, product: &str) -> String {
    hex(&Sha256::digest(format!("licensekit:{product}:{raw_machine_id}").as_bytes()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_sec(now_ms: f64) -> i64 {
    (now_ms / 1000.0).floor() as i64
}

/// An ISO 8601 UTC time with milliseconds, as JavaScript's Date.prototype.toISOString writes it.
pub fn iso_time(seconds: f64) -> String {
    let ms = (seconds * 1000.0).trunc() as i64;
    let (days, ms_of_day) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Civil date from days since 1970-01-01 (H. Hinnant's days_from_civil, inverted).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let (h, m, s, milli) = (ms_of_day / 3_600_000, ms_of_day / 60_000 % 60, ms_of_day / 1000 % 60, ms_of_day % 1000);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{milli:03}Z")
}

fn finite(v: Option<&Value>) -> Option<f64> {
    v.and_then(Value::as_f64).filter(|n| n.is_finite())
}

impl<S: Storage> Client<S> {
    pub fn new(config: Config, storage: S) -> Client<S> {
        Client { config, storage, fingerprint: None, hardware: None, device_key: None, pending: None }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    fn grace_default(&self) -> f64 {
        self.config.grace_days.unwrap_or(DEFAULT_GRACE_DAYS) * 86400.0
    }

    /// This device's fingerprint hash; read once, retried on the next call when the id could not be read.
    pub fn fingerprint(&mut self) -> Result<String, LicenseError> {
        if self.fingerprint.is_none() {
            let raw = (self.config.machine_id)().ok_or_else(|| LicenseError::new("machine_id_unavailable", MACHINE_ID_MESSAGE))?;
            self.fingerprint = Some(hash_fingerprint(&raw, &self.config.product));
        }
        Ok(self.fingerprint.clone().unwrap_or_default())
    }

    /// The hardware fields and device key of a request body, read once per client.
    fn device_fields(&mut self, body: &mut Map<String, Value>, with_device_key: bool) {
        let hardware = self.hardware.get_or_insert_with(|| (self.config.hardware)()).clone();
        if let Some(h) = hardware.filter(|h| !h.components.is_empty()) {
            let components: Vec<Value> = h.components.iter().take(MAX_COMPONENTS).map(|(kind, hash)| json!({ "kind": kind, "hash": hash })).collect();
            body.insert("components".into(), Value::Array(components));
            body.insert("vm".into(), json!(h.vm));
        }
        if with_device_key {
            if let Some(key) = self.device_key.get_or_insert_with(|| (self.config.device_public_key)()).clone() {
                body.insert("devicePublicKey".into(), json!(key));
            }
        }
    }

    fn load(&self) -> Option<Stored> {
        self.storage.load().and_then(|text| Stored::parse(&text))
    }

    fn save(&mut self, stored: &Stored) -> Result<(), LicenseError> {
        self.storage.save(&stored.to_json()).map_err(|e| LicenseError::new("storage_error", format!("The license could not be saved: {e}")))
    }

    fn clear(&mut self) -> Result<(), LicenseError> {
        self.storage.clear().map_err(|e| LicenseError::new("storage_error", format!("The license could not be removed: {e}")))
    }

    fn empty_state(&self, status: Status, offline: bool) -> State {
        State::empty(status, offline, self.storage.protected())
    }

    fn options<'a>(&'a self, fingerprint: &'a str, now: i64, grace_seconds: f64) -> Options<'a> {
        Options {
            keys: &self.config.keys,
            product: &self.config.product,
            fingerprint_hash: fingerprint,
            issuer: None,
            now: now as f64,
            grace_seconds,
            leeway_seconds: DEFAULT_LEEWAY_SECONDS,
        }
    }

    /// The state a saved lease gives at `now`, as the SDK's stateFromLease.
    fn state_from_lease(&self, stored: &Stored, token: &str, offline: bool, now: i64) -> State {
        let fingerprint = self.fingerprint.clone().unwrap_or_default();
        let key_hint = stored.key_hint();
        let empty = |status, reason: &str, message: &str| {
            let mut s = self.empty_state(status, offline);
            s.reason = Some(reason.into());
            s.message = Some(message.into());
            s.key_hint = Some(key_hint.clone());
            s
        };
        if offline && stored.last_seen.is_some_and(|seen| now < seen - CLOCK_TOLERANCE_SECONDS) {
            return empty(Status::ClockSuspect, "clock_rollback", CLOCK_MESSAGE);
        }
        let from_claims = |status, claims: &Map<String, Value>| {
            let mut s = self.empty_state(status, offline);
            s.customer = claims.get("cus").and_then(Value::as_str).map(String::from);
            s.features = claims.get("feat").and_then(Value::as_array).map(|f| f.iter().filter_map(Value::as_str).map(String::from).collect()).unwrap_or_default();
            s.expires_at = finite(claims.get("exp")).map(iso_time);
            s.maintenance_until = Some(finite(claims.get("mnt")).map(iso_time));
            s.key_hint = Some(stored.key_hint());
            s.notices = stored.notices.clone();
            s.offline_activated = stored.offline;
            s
        };
        match seal_lease::verify(token, &self.options(&fingerprint, now, 0.0)) {
            Ok(verified) => {
                let mut s = from_claims(Status::Valid, &verified.claims);
                s.revalidate_by = finite(verified.claims.get("rev")).map(iso_time);
                s
            }
            Err((Failure::NotYetValid, _)) => empty(Status::ClockSuspect, "lease_from_future", CLOCK_MESSAGE),
            Err((Failure::RevalidationRequired, Some(claims))) => {
                let grace = finite(claims.get("grc")).unwrap_or_else(|| self.grace_default());
                match seal_lease::verify(token, &self.options(&fingerprint, now, grace)) {
                    Ok(lenient) => {
                        let mut s = from_claims(Status::Grace, &lenient.claims);
                        s.reason = Some("offline_grace".into());
                        s.message = Some(
                            if stored.offline {
                                "This offline license is past its renewal date. Load a new offline license file soon to keep using the app."
                            } else {
                                "Working offline. Connect to the internet soon to keep using the app."
                            }
                            .into(),
                        );
                        let rev = finite(lenient.claims.get("rev")).unwrap_or_default();
                        let until = finite(lenient.claims.get("exp")).map_or(rev + grace, |exp| (rev + grace).min(exp));
                        s.revalidate_by = Some(iso_time(until));
                        s
                    }
                    Err(_) => empty(Status::Invalid, Failure::RevalidationRequired.as_str(), reason_text(Failure::RevalidationRequired)),
                }
            }
            Err((failure, _)) => empty(Status::Invalid, failure.as_str(), reason_text(failure)),
        }
    }

    /// The code and message of a state that is not usable, for an operation that must fail with it.
    fn unusable(state: &State, fallback: &str) -> LicenseError {
        let code = if state.status == Status::ClockSuspect { "clock_suspect".to_string() } else { state.reason.clone().unwrap_or_else(|| "invalid".into()) };
        LicenseError::new(code, state.message.clone().unwrap_or_else(|| fallback.into()))
    }

    /// The server's answer to a request as the SDK's post() reads it: the JSON body on 2xx, the refusal otherwise.
    fn read_response(response: Response) -> Result<Value, LicenseError> {
        match response {
            Response::Network => Err(LicenseError::new("network", "Could not reach the license server.")),
            Response::Http { status, body } => {
                let json: Value = serde_json::from_slice(&body).unwrap_or_else(|_| json!({}));
                if (200..300).contains(&status) {
                    return Ok(json);
                }
                let text = |name: &str| json.get(name).and_then(Value::as_str).map(String::from);
                Err(LicenseError {
                    code: text("error").unwrap_or_else(|| "server_error".into()),
                    message: text("message").unwrap_or_else(|| format!("License server error ({status})")),
                    status: Some(status),
                })
            }
        }
    }

    fn notices_from(response: &Value) -> Option<Vec<Value>> {
        let list: Vec<Value> = response
            .get("notices")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter(|n| n.get("code").is_some_and(Value::is_string)).cloned().collect())
            .unwrap_or_default();
        (!list.is_empty()).then_some(list)
    }

    fn token_of(response: &Value) -> String {
        response.get("token").and_then(Value::as_str).unwrap_or_default().to_string()
    }

    fn activation_body(&mut self, key: &str, machine_name: Option<&str>) -> Result<Map<String, Value>, LicenseError> {
        let fingerprint = self.fingerprint()?;
        let mut body = Map::new();
        body.insert("licenseKey".into(), json!(key));
        body.insert("product".into(), json!(self.config.product));
        body.insert("fingerprint".into(), json!(fingerprint));
        if let Some(name) = machine_name {
            body.insert("machineName".into(), json!(name.chars().take(80).collect::<String>()));
        }
        body.insert("platform".into(), json!(self.config.platform));
        if let Some(v) = &self.config.app_version {
            body.insert("appVersion".into(), json!(v));
        }
        body.insert("sdkVersion".into(), json!(self.config.sdk_version));
        self.device_fields(&mut body, true);
        Ok(body)
    }

    // ---- activate ----

    /// Activates this device with a license key (and the name to show the vendor, if any).
    pub fn activate_begin(&mut self, license_key: &str, machine_name: Option<&str>) -> Outcome<State> {
        let key = license_key.trim().to_uppercase();
        match self.activation_body(&key, machine_name) {
            Ok(body) => {
                self.pending = Some(Pending::Activate { key });
                Outcome::Send(Request { path: "/v1/activate", body: Value::Object(body) })
            }
            Err(e) => Outcome::Done(Err(e)),
        }
    }

    pub fn activate_finish(&mut self, response: Response, now_ms: f64) -> Result<State, LicenseError> {
        let Some(Pending::Activate { key }) = self.pending.take() else {
            return Err(LicenseError::new("no_request", "activate_finish without activate_begin."));
        };
        let response = Self::read_response(response)?;
        let now = now_sec(now_ms);
        let token = Self::token_of(&response);
        let stored = Stored { license_key: key, token: Some(token.clone()), last_seen: Some(now), notices: Self::notices_from(&response), ..Default::default() };
        let state = self.state_from_lease(&stored, &token, false, now);
        if state.status != Status::Valid {
            return Err(Self::unusable(&state, "Server returned an unusable license"));
        }
        self.save(&stored)?;
        Ok(state)
    }

    // ---- check ----

    /// Checks the license: online when the server answers, from the saved lease when not.
    pub fn check_begin(&mut self, now_ms: f64) -> Outcome<State> {
        let fingerprint = match self.fingerprint() {
            Ok(f) => f,
            Err(e) => {
                let mut s = self.empty_state(Status::Invalid, false);
                s.reason = Some(e.code);
                s.message = Some(e.message);
                return Outcome::Done(Ok(s));
            }
        };
        let Some(stored) = self.load() else { return Outcome::Done(Ok(self.empty_state(Status::Unlicensed, false))) };
        if let (true, Some(token)) = (stored.offline, stored.token.clone()) {
            return Outcome::Done(self.offline_state(stored, &token, now_sec(now_ms)));
        }
        let mut body = Map::new();
        body.insert("licenseKey".into(), json!(stored.license_key));
        body.insert("product".into(), json!(self.config.product));
        body.insert("fingerprint".into(), json!(fingerprint));
        if let Some(v) = &self.config.app_version {
            body.insert("appVersion".into(), json!(v));
        }
        body.insert("sdkVersion".into(), json!(self.config.sdk_version));
        self.device_fields(&mut body, true);
        self.pending = Some(Pending::Check { stored });
        Outcome::Send(Request { path: "/v1/validate", body: Value::Object(body) })
    }

    /// The saved lease's state offline; a usable one moves the last-seen time forward.
    fn offline_state(&mut self, stored: Stored, token: &str, now: i64) -> Result<State, LicenseError> {
        let state = self.state_from_lease(&stored, token, true, now);
        if matches!(state.status, Status::Valid | Status::Grace) {
            let last_seen = Some(stored.last_seen.unwrap_or(0).max(now));
            self.save(&Stored { last_seen, ..stored })?;
        }
        Ok(state)
    }

    pub fn check_finish(&mut self, response: Response, now_ms: f64) -> Result<State, LicenseError> {
        let Some(Pending::Check { stored }) = self.pending.take() else {
            return Err(LicenseError::new("no_request", "check_finish without check_begin."));
        };
        let now = now_sec(now_ms);
        match Self::read_response(response) {
            Ok(response) => {
                if let Some(token) = response.get("token").and_then(Value::as_str).map(String::from) {
                    let fresh = Stored { license_key: stored.license_key.clone(), token: Some(token.clone()), last_seen: Some(now), notices: Self::notices_from(&response), ..Default::default() };
                    let state = self.state_from_lease(&fresh, &token, false, now);
                    let not_a_lease = state.status == Status::Invalid && state.reason.as_deref().is_some_and(|r| NOT_A_LEASE_FOR_THIS_DEVICE.contains(&r));
                    if !not_a_lease {
                        self.save(&fresh)?;
                        return Ok(state);
                    }
                }
                // A 2xx without a lease from this server for this device: as no answer.
                self.offline_check(stored, now)
            }
            Err(e) => {
                let key_hint = stored.key_hint();
                if DEFINITIVE.contains(&e.code.as_str()) {
                    if FORGET_KEY.contains(&e.code.as_str()) {
                        self.clear()?;
                    } else {
                        let refused = Stored {
                            license_key: stored.license_key.clone(),
                            last_seen: stored.last_seen,
                            refused: Some((e.code.clone(), e.message.clone(), now)),
                            ..Default::default()
                        };
                        self.save(&refused)?;
                    }
                    let mut s = self.empty_state(Status::Invalid, false);
                    (s.reason, s.message, s.key_hint) = (Some(e.code), Some(e.message), Some(key_hint));
                    return Ok(s);
                }
                self.offline_check(stored, now)
            }
        }
    }

    /// The state from the saved record when the server gave no usable answer.
    fn offline_check(&mut self, stored: Stored, now: i64) -> Result<State, LicenseError> {
        let Some(token) = stored.token.clone() else {
            let (code, message, _) = stored.refused.clone().unwrap_or(("not_activated".into(), "This device is not activated for this license".into(), 0));
            let mut s = self.empty_state(Status::Invalid, true);
            (s.reason, s.message, s.key_hint) = (Some(code), Some(message), Some(stored.key_hint()));
            return Ok(s);
        };
        self.offline_state(stored, &token, now)
    }

    // ---- deactivate ----

    /// Releases this device's seat on the server and removes the license here.
    pub fn deactivate_begin(&mut self) -> Outcome<()> {
        let Some(stored) = self.load() else { return Outcome::Done(Ok(())) };
        let fingerprint = match self.fingerprint() {
            Ok(f) => f,
            Err(e) => return Outcome::Done(Err(e)),
        };
        let mut body = Map::new();
        body.insert("licenseKey".into(), json!(stored.license_key));
        body.insert("product".into(), json!(self.config.product));
        body.insert("fingerprint".into(), json!(fingerprint));
        self.device_fields(&mut body, false);
        self.pending = Some(Pending::Deactivate);
        Outcome::Send(Request { path: "/v1/deactivate", body: Value::Object(body) })
    }

    pub fn deactivate_finish(&mut self, response: Response) -> Result<(), LicenseError> {
        let Some(Pending::Deactivate) = self.pending.take() else {
            return Err(LicenseError::new("no_request", "deactivate_finish without deactivate_begin."));
        };
        match Self::read_response(response) {
            Ok(_) => {}
            Err(e) if e.code == "not_activated" || e.code == "invalid_key" => {}
            Err(e) => return Err(e),
        }
        self.clear()
    }

    // ---- offline activation ----

    /// Offline activation, step 1: the request file (JSON text) for a machine that cannot reach the server.
    pub fn offline_request(&mut self, license_key: &str, machine_name: Option<&str>) -> Result<String, LicenseError> {
        let key = license_key.trim().to_uppercase();
        let activation = self.activation_body(&key, machine_name)?;
        let file = json!({ "format": OFFLINE_REQUEST_FORMAT, "version": 1, "activation": activation });
        Ok(serde_json::to_string_pretty(&file).unwrap_or_default())
    }

    /// Offline activation, step 2: loads the license file the server issued for this machine's request.
    pub fn activate_offline(&mut self, license_file: &str, now_ms: f64) -> Result<State, LicenseError> {
        self.fingerprint()?;
        let invalid = || LicenseError::new("invalid_file", "This is not a Carcha Seal offline license file.");
        let file: Value = serde_json::from_str(license_file).map_err(|_| invalid())?;
        let text = |name: &str| file.get(name).and_then(Value::as_str);
        let (Some(format), Some(1.0), Some(token), Some(license_key)) = (text("format"), file.get("version").and_then(Value::as_f64), text("token"), text("licenseKey")) else {
            return Err(invalid());
        };
        if format != OFFLINE_LICENSE_FORMAT {
            return Err(invalid());
        }
        if text("product") != Some(self.config.product.as_str()) {
            return Err(LicenseError::new("wrong_product", "This offline license file is for another product."));
        }
        let now = now_sec(now_ms);
        let stored = Stored { license_key: license_key.trim().to_uppercase(), token: Some(token.to_string()), last_seen: Some(now), offline: true, ..Default::default() };
        let state = self.state_from_lease(&stored, token, true, now);
        if state.status != Status::Valid {
            return Err(Self::unusable(&state, "This offline license file cannot be used on this computer."));
        }
        self.save(&stored)?;
        Ok(state)
    }

    /// Gives an offline machine's seat back: removes the license and returns the deactivation file (JSON text).
    pub fn deactivate_offline(&mut self) -> Result<String, LicenseError> {
        let Some(token) = self.load().and_then(|s| s.token) else {
            return Err(LicenseError::new("unlicensed", "This device has no license."));
        };
        self.clear()?;
        let file = json!({ "format": OFFLINE_DEACTIVATION_FORMAT, "version": 1, "product": self.config.product, "token": token });
        Ok(serde_json::to_string_pretty(&file).unwrap_or_default())
    }

    // ---- feature data ----

    /// Decrypts data encrypted for a feature, offline, with the saved lease (valid or in grace) and license key.
    pub fn decrypt(&mut self, feature: &str, data: &[u8], now_ms: f64) -> Result<Vec<u8>, LicenseError> {
        let fingerprint = self.fingerprint()?;
        let stored = self.load();
        let Some((stored, token)) = stored.and_then(|s| s.token.clone().map(|t| (s, t))) else {
            return Err(LicenseError::new("unlicensed", "This device has no license."));
        };
        let now = now_sec(now_ms);
        let state = self.state_from_lease(&stored, &token, true, now);
        if !matches!(state.status, Status::Valid | Status::Grace) {
            return Err(Self::unusable(&state, "The license is not valid."));
        }
        let grace = if state.status == Status::Grace {
            seal_lease::verify(&token, &self.options(&fingerprint, now, f64::INFINITY))
                .ok()
                .and_then(|v| finite(v.claims.get("grc")))
                .unwrap_or_else(|| self.grace_default())
        } else {
            0.0
        };
        let secret = (self.config.device_secret)();
        match seal_lease::decrypt_feature(&token, &self.options(&fingerprint, now, grace), &stored.license_key, feature, data, secret.as_ref()) {
            Ok(plain) => Ok(plain),
            Err(DecryptError::NotLicensed) => Err(LicenseError::new("feature_not_licensed", format!("This license does not include \"{feature}\"."))),
            Err(DecryptError::Failed) => Err(LicenseError::new("decrypt_failed", "The data could not be decrypted with this license.")),
            Err(DecryptError::Lease(failure)) => Err(LicenseError::new(failure.as_str(), reason_text(failure))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_time_matches_javascript() {
        assert_eq!(iso_time(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_time(1_800_000_000.0), "2027-01-15T08:00:00.000Z");
        assert_eq!(iso_time(951_782_400.0), "2000-02-29T00:00:00.000Z");
        assert_eq!(iso_time(1.5), "1970-01-01T00:00:01.500Z");
        assert_eq!(iso_time(-1.0), "1969-12-31T23:59:59.000Z");
        assert_eq!(iso_time(4_102_444_800.0), "2100-01-01T00:00:00.000Z");
    }

    #[test]
    fn file_storage_saves_loads_and_clears() {
        let dir = std::env::temp_dir().join(format!("seal-client-{}", std::process::id()));
        let mut storage = FileStorage::new(dir.join("nested"));
        assert_eq!(storage.load(), None);
        storage.clear().unwrap();
        storage.save(r#"{"licenseKey":"LK-A"}"#).unwrap();
        assert_eq!(storage.load().as_deref(), Some(r#"{"licenseKey":"LK-A"}"#));
        // Replaced whole, through a temporary file that does not stay behind.
        storage.save(r#"{"licenseKey":"LK-B"}"#).unwrap();
        assert_eq!(storage.load().as_deref(), Some(r#"{"licenseKey":"LK-B"}"#));
        assert!(!dir.join("nested/license.dat.tmp").exists());
        // A write that cannot happen leaves the saved record as it was.
        std::fs::create_dir(dir.join("nested/license.dat.tmp")).unwrap();
        assert!(storage.save(r#"{"licenseKey":"LK-C"}"#).is_err());
        assert_eq!(storage.load().as_deref(), Some(r#"{"licenseKey":"LK-B"}"#));
        std::fs::remove_dir(dir.join("nested/license.dat.tmp")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("nested/license.dat")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        storage.clear().unwrap();
        assert_eq!(storage.load(), None);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_record_is_the_electron_sdk_json() {
        let text = r#"{"licenseKey":"LK-A","token":"t","lastSeen":1800000000,"refused":{"code":"license_suspended","message":"m","at":1800000001},"notices":[{"code":"x"}],"offline":true}"#;
        let stored = Stored::parse(text).unwrap();
        let back: Value = serde_json::from_str(&stored.to_json()).unwrap();
        assert_eq!(back, serde_json::from_str::<Value>(text).unwrap());
        assert!(Stored::parse("not json").is_none());
        assert!(Stored::parse(r#"{"token":"t"}"#).is_none(), "no license key");
    }

    /// The cases of sdk-electron/src/server-url.test.ts.
    #[test]
    fn server_url_https_only_and_http_for_this_computer() {
        for url in ["https://seal.carchalabs.com", "https://licenses.example.com:8443/base/", "http://localhost:4000", "http://127.0.0.1:4000", "http://127.8.9.10", "http://[::1]:4000"] {
            assert_eq!(check_server_url(url), Ok(()), "{url}");
        }
        for url in ["http://seal.carchalabs.com", "http://192.168.1.10:4000", "http://localhost.example.com", "http://127.0.0.1.example.com", "ftp://seal.carchalabs.com", "ws://localhost"] {
            assert_eq!(check_server_url(url).unwrap_err().code, "insecure_server_url", "{url}");
        }
        assert_eq!(check_server_url("seal.carchalabs.com").unwrap_err().code, "invalid_server_url", "no scheme");
        let request = Request { path: "/v1/validate", body: json!({}) };
        assert_eq!(request_url("https://seal.carchalabs.com/acme//", &request), "https://seal.carchalabs.com/acme/v1/validate");
    }

    #[test]
    fn key_hint_as_the_sdk() {
        assert_eq!(key_hint("LK-7K2M-QX9P-4RTV-8WNB-3HCJ-6DFG-YZ5S"), "LK-7K2M…YZ5S");
        assert_eq!(key_hint("LK"), "LK…LK");
    }
}
