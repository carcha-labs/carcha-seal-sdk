//! C interface of the license client (`seal_client_*`, `seal_result_*` in include/seal.h), over `seal_client`.
//! Operations that need the server return a result of kind SEAL_RESULT_SEND with the request; the caller posts
//! it with its own HTTP stack and passes the answer to the matching `*_finish` function.

use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Mutex;

use seal_client::{Client, Config, FileStorage, Hardware, LicenseError, Outcome, Request, Response, State, Status};
use serde_json::{Value, json};

use crate::{parse_keys, product_key, text};

/// The `seal_client_options` struct of the header.
#[repr(C)]
pub struct SealClientOptions {
    pub product: *const c_char,
    pub server_url: *const c_char,
    pub public_keys: *const c_char,
    pub storage_dir: *const c_char,
    pub app_version: *const c_char,
    pub grace_days: f64,
    pub sdk_name: *const c_char,
    pub machine_id: *const c_char,
    pub hardware: i32,
}

/// The client behind a `seal_client *`. One operation at a time; the lock makes concurrent calls wait.
pub struct SealClient {
    inner: Mutex<Client<FileStorage>>,
    server_url: String,
    user_agent: CString,
}

/// What a `seal_result *` holds. Every string it hands out lives as long as the result.
pub struct SealResult {
    kind: i32,
    json: CString,
    path: Option<CString>,
    url: Option<CString>,
    body: Option<CString>,
    error: Option<(CString, CString)>,
    state: Option<(State, StateStrings)>,
    text: Option<CString>,
    data: Option<Vec<u8>>,
}

/// The state's strings as C strings, in the order of the SEAL_STATE_* field numbers.
struct StateStrings {
    fields: Vec<Option<CString>>,
    features: Vec<CString>,
}

pub const SEAL_RESULT_SEND: i32 = 1;
pub const SEAL_RESULT_DONE: i32 = 2;
pub const SEAL_RESULT_ERROR: i32 = 3;

pub const SEAL_FLAG_OFFLINE: i32 = 1;
pub const SEAL_FLAG_STORAGE_PROTECTED: i32 = 2;
pub const SEAL_FLAG_OFFLINE_ACTIVATED: i32 = 3;

/// The SEAL_FIELD_* numbers: index + 1 in StateStrings::fields.
pub const SEAL_FIELD_NOTICES_JSON: i32 = 8;

fn cstring(s: &str) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

/// The SDK version every native SDK reports: this library's, since the client logic is here.
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

fn platform() -> &'static str {
    if cfg!(windows) {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

fn valid_sdk_name(name: &str) -> bool {
    (1..=20).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Sets the options' defaults: grace from the lease or 7 days, hardware on, SDK name "c".
///
/// # Safety
/// `options` must be NULL or point to a writable seal_client_options.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_options_init(options: *mut SealClientOptions) {
    if !options.is_null() {
        let defaults = SealClientOptions {
            product: std::ptr::null(),
            server_url: std::ptr::null(),
            public_keys: std::ptr::null(),
            storage_dir: std::ptr::null(),
            app_version: std::ptr::null(),
            grace_days: -1.0,
            sdk_name: std::ptr::null(),
            machine_id: std::ptr::null(),
            hardware: 1,
        };
        // SAFETY: non-null and writable per the contract.
        unsafe { options.write(defaults) };
    }
}

fn hardware_of(product: &str) -> Option<Hardware> {
    let collected = seal_hwid::collect(product_key(product).as_bytes());
    Some(Hardware { components: collected.components.into_iter().map(|c| (c.kind.as_str().to_string(), c.hash)).collect(), vm: collected.vm })
}

/// Options read and checked: what seal_client_new builds a client from.
struct Parsed<'a> {
    product: &'a str,
    server_url: &'a str,
    keys: Vec<seal_lease::TrustedKey>,
    dir: &'a str,
    app_version: Option<&'a str>,
    grace_days: Option<f64>,
    sdk_name: &'a str,
    machine_id: Option<&'a str>,
    hardware: bool,
}

/// Reads the options; the error is the name of what is wrong (see seal_client_options_error).
///
/// # Safety
/// The options' strings must be NULL or NUL-terminated.
unsafe fn parse(o: &SealClientOptions) -> Result<Parsed<'_>, &'static str> {
    // SAFETY: per this function's contract (all the reads below).
    let given = |p: *const c_char, name: &'static str| -> Result<Option<&str>, &'static str> {
        if p.is_null() { Ok(None) } else { unsafe { text(p) }.map(Some).ok_or(name) }
    };
    let product = given(o.product, "invalid_product")?.filter(|p| !p.is_empty()).ok_or("invalid_product")?;
    let server_url = given(o.server_url, "invalid_server_url")?.ok_or("invalid_server_url")?;
    if let Err(e) = seal_client::check_server_url(server_url) {
        return Err(if e.code == "insecure_server_url" { "insecure_server_url" } else { "invalid_server_url" });
    }
    let keys = given(o.public_keys, "invalid_public_keys")?.and_then(parse_keys).ok_or("invalid_public_keys")?.keys;
    let dir = given(o.storage_dir, "invalid_storage_dir")?.filter(|d| !d.is_empty()).ok_or("invalid_storage_dir")?;
    if !(o.grace_days.is_finite() || o.grace_days < 0.0) {
        return Err("invalid_grace_days");
    }
    let sdk_name = given(o.sdk_name, "invalid_sdk_name")?.unwrap_or("c");
    if !valid_sdk_name(sdk_name) {
        return Err("invalid_sdk_name");
    }
    Ok(Parsed {
        product,
        server_url,
        keys,
        dir,
        app_version: given(o.app_version, "invalid_app_version")?,
        grace_days: (o.grace_days >= 0.0).then_some(o.grace_days),
        sdk_name,
        machine_id: given(o.machine_id, "invalid_machine_id")?,
        hardware: o.hardware != 0,
    })
}

/// What is wrong with the options, or NULL when a client can be made from them. Static. See seal.h.
///
/// # Safety
/// `options` must be NULL or point to a seal_client_options whose strings are NULL or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_options_error(options: *const SealClientOptions) -> *const c_char {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: per this function's contract.
        let Some(o) = (unsafe { options.as_ref() }) else { return c"invalid_options".as_ptr() };
        // SAFETY: per this function's contract.
        match unsafe { parse(o) } {
            Ok(_) => std::ptr::null(),
            Err(name) => match name {
                "invalid_product" => c"invalid_product",
                "invalid_server_url" => c"invalid_server_url",
                "insecure_server_url" => c"insecure_server_url",
                "invalid_public_keys" => c"invalid_public_keys",
                "invalid_storage_dir" => c"invalid_storage_dir",
                "invalid_grace_days" => c"invalid_grace_days",
                "invalid_sdk_name" => c"invalid_sdk_name",
                "invalid_app_version" => c"invalid_app_version",
                _ => c"invalid_machine_id",
            }
            .as_ptr(),
        }
    }))
    .unwrap_or(c"invalid_options".as_ptr())
}

/// A client from the options; NULL when seal_client_options_error names a problem.
///
/// # Safety
/// `options` must be NULL or point to a seal_client_options whose strings are NULL or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_new(options: *const SealClientOptions) -> *mut SealClient {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: per this function's contract.
        let Some(o) = (unsafe { options.as_ref() }) else { return std::ptr::null_mut() };
        // SAFETY: per this function's contract.
        let Ok(p) = (unsafe { parse(o) }) else { return std::ptr::null_mut() };
        let mut config = Config::new(p.product, p.keys, SDK_VERSION, platform());
        config.grace_days = p.grace_days;
        config.app_version = p.app_version.map(String::from);
        config.machine_id = match p.machine_id {
            Some(id) => {
                let id = id.to_string();
                Box::new(move || Some(id.clone()))
            }
            None => Box::new(seal_hwid::os_machine_id),
        };
        if p.hardware {
            let product = p.product.to_string();
            config.hardware = Box::new(move || hardware_of(&product));
            let product = p.product.to_string();
            config.device_public_key = Box::new(move || {
                use base64::Engine;
                seal_hwid::device_secret(product_key(&product).as_bytes())
                    .map(|s| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seal_lease::device_public_key(&s)))
            });
            let product = p.product.to_string();
            config.device_secret = Box::new(move || seal_hwid::device_secret(product_key(&product).as_bytes()));
        }
        let user_agent = cstring(&format!("carcha-seal-native/{SDK_VERSION} ({})", p.sdk_name));
        let client = SealClient { inner: Mutex::new(Client::new(config, FileStorage::new(p.dir))), server_url: p.server_url.to_string(), user_agent };
        Box::into_raw(Box::new(client))
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Frees a client; NULL is ignored.
///
/// # Safety
/// `client` must be NULL or a pointer from seal_client_new not freed yet, with no call on it running.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_free(client: *mut SealClient) {
    if !client.is_null() {
        // SAFETY: from Box::into_raw in seal_client_new, freed once per the contract.
        drop(unsafe { Box::from_raw(client) });
    }
}

/// The User-Agent header to send with every request, e.g. "carcha-seal-native/0.2.0 (dotnet)".
///
/// # Safety
/// `client` must be NULL or a live pointer from seal_client_new.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_user_agent(client: *const SealClient) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { client.as_ref() }.map_or(std::ptr::null(), |c| c.user_agent.as_ptr())
}

// ---- Results --------------------------------------------------------------------------------

fn state_strings(state: &State) -> StateStrings {
    let opt = |v: &Option<String>| v.as_deref().map(cstring);
    let notices = state.notices.as_ref().map(|n| cstring(&Value::Array(n.clone()).to_string()));
    StateStrings {
        fields: vec![
            opt(&state.reason),
            opt(&state.message),
            opt(&state.customer),
            opt(&state.expires_at),
            state.maintenance_until.clone().flatten().as_deref().map(cstring),
            opt(&state.revalidate_by),
            opt(&state.key_hint),
            notices,
        ],
        features: state.features.iter().map(|f| cstring(f)).collect(),
    }
}

fn base(kind: i32, json: Value) -> SealResult {
    SealResult { kind, json: cstring(&json.to_string()), path: None, url: None, body: None, error: None, state: None, text: None, data: None }
}

fn send(server_url: &str, request: Request) -> SealResult {
    let url = seal_client::request_url(server_url, &request);
    let mut r = base(SEAL_RESULT_SEND, json!({ "send": { "url": url, "path": request.path, "body": request.body } }));
    r.path = Some(cstring(request.path));
    r.url = Some(cstring(&url));
    r.body = Some(cstring(&request.body.to_string()));
    r
}

fn failed(e: LicenseError) -> SealResult {
    let mut r = base(SEAL_RESULT_ERROR, json!({ "ok": false, "error": { "code": e.code, "message": e.message } }));
    r.error = Some((cstring(&e.code), cstring(&e.message)));
    r
}

fn done_state(result: Result<State, LicenseError>) -> SealResult {
    match result {
        Ok(state) => {
            let mut r = base(SEAL_RESULT_DONE, json!({ "ok": true, "value": state.to_json() }));
            let strings = state_strings(&state);
            r.state = Some((state, strings));
            r
        }
        Err(e) => failed(e),
    }
}

fn done_unit(result: Result<(), LicenseError>) -> SealResult {
    match result {
        Ok(()) => base(SEAL_RESULT_DONE, json!({ "ok": true, "value": null })),
        Err(e) => failed(e),
    }
}

fn done_text(result: Result<String, LicenseError>) -> SealResult {
    match result {
        Ok(t) => {
            let value: Value = serde_json::from_str(&t).unwrap_or(Value::Null);
            let mut r = base(SEAL_RESULT_DONE, json!({ "ok": true, "value": value }));
            r.text = Some(cstring(&t));
            r
        }
        Err(e) => failed(e),
    }
}

fn into_ptr(result: SealResult) -> *mut SealResult {
    Box::into_raw(Box::new(result))
}

/// Runs an operation on the client under its lock; NULL for a NULL client or a panic.
fn with_client(client: *const SealClient, f: impl FnOnce(&mut Client<FileStorage>, &str) -> SealResult) -> *mut SealResult {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: a live pointer from seal_client_new per the callers' contracts.
        let Some(c) = (unsafe { client.as_ref() }) else { return std::ptr::null_mut() };
        // A panic in an earlier call is caught at the boundary; the client's state stays usable.
        let mut inner = c.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        into_ptr(f(&mut inner, &c.server_url))
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// The answer to a request: status 0 means no answer (no connection, timeout, refused redirect, TLS failure).
///
/// # Safety
/// `body` must point to `body_len` readable bytes, or be NULL with `body_len` 0.
unsafe fn response(status: i32, body: *const u8, body_len: usize) -> Option<Response> {
    if status == 0 {
        return Some(Response::Network);
    }
    let status = u16::try_from(status).ok().filter(|s| (100..=599).contains(s))?;
    let body = if body_len == 0 {
        Vec::new()
    } else if body.is_null() {
        return None;
    } else {
        // SAFETY: body_len readable bytes per the contract.
        unsafe { std::slice::from_raw_parts(body, body_len) }.to_vec()
    };
    Some(Response::Http { status, body })
}

// ---- Operations -----------------------------------------------------------------------------

/// Starts activation with a license key and, optionally, the machine name to show the vendor.
///
/// # Safety
/// `client` a live seal_client; `license_key` NUL-terminated; `machine_name` NULL or NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_activate_begin(client: *const SealClient, license_key: *const c_char, machine_name: *const c_char) -> *mut SealResult {
    // SAFETY: per this function's contract.
    let (key, name) = unsafe { (text(license_key), text(machine_name)) };
    let Some(key) = key else { return std::ptr::null_mut() };
    if !machine_name.is_null() && name.is_none() {
        return std::ptr::null_mut();
    }
    with_client(client, |c, server| match c.activate_begin(key, name) {
        Outcome::Send(r) => send(server, r),
        Outcome::Done(d) => done_state(d),
    })
}

/// Finishes activation with the server's answer.
///
/// # Safety
/// `client` a live seal_client; `body` `body_len` readable bytes or NULL with 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_activate_finish(client: *const SealClient, http_status: i32, body: *const u8, body_len: usize, now_ms: f64) -> *mut SealResult {
    // SAFETY: per this function's contract.
    let Some(answer) = (unsafe { response(http_status, body, body_len) }) else { return std::ptr::null_mut() };
    if !now_ms.is_finite() {
        return std::ptr::null_mut();
    }
    with_client(client, |c, _| done_state(c.activate_finish(answer, now_ms)))
}

/// Starts a license check.
///
/// # Safety
/// `client` a live seal_client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_check_begin(client: *const SealClient, now_ms: f64) -> *mut SealResult {
    if !now_ms.is_finite() {
        return std::ptr::null_mut();
    }
    with_client(client, |c, server| match c.check_begin(now_ms) {
        Outcome::Send(r) => send(server, r),
        Outcome::Done(d) => done_state(d),
    })
}

/// Finishes a license check with the server's answer (status 0: no answer, the saved lease is used).
///
/// # Safety
/// As seal_client_activate_finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_check_finish(client: *const SealClient, http_status: i32, body: *const u8, body_len: usize, now_ms: f64) -> *mut SealResult {
    // SAFETY: per this function's contract.
    let Some(answer) = (unsafe { response(http_status, body, body_len) }) else { return std::ptr::null_mut() };
    if !now_ms.is_finite() {
        return std::ptr::null_mut();
    }
    with_client(client, |c, _| done_state(c.check_finish(answer, now_ms)))
}

/// Starts deactivation (releases this device's seat).
///
/// # Safety
/// `client` a live seal_client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_deactivate_begin(client: *const SealClient) -> *mut SealResult {
    with_client(client, |c, server| match c.deactivate_begin() {
        Outcome::Send(r) => send(server, r),
        Outcome::Done(d) => done_unit(d),
    })
}

/// Finishes deactivation with the server's answer.
///
/// # Safety
/// As seal_client_activate_finish.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_deactivate_finish(client: *const SealClient, http_status: i32, body: *const u8, body_len: usize) -> *mut SealResult {
    // SAFETY: per this function's contract.
    let Some(answer) = (unsafe { response(http_status, body, body_len) }) else { return std::ptr::null_mut() };
    with_client(client, |c, _| done_unit(c.deactivate_finish(answer)))
}

/// The offline activation request file (JSON text, seal_result_text) for this machine.
///
/// # Safety
/// As seal_client_activate_begin.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_offline_request(client: *const SealClient, license_key: *const c_char, machine_name: *const c_char) -> *mut SealResult {
    // SAFETY: per this function's contract.
    let (key, name) = unsafe { (text(license_key), text(machine_name)) };
    let Some(key) = key else { return std::ptr::null_mut() };
    if !machine_name.is_null() && name.is_none() {
        return std::ptr::null_mut();
    }
    with_client(client, |c, _| done_text(c.offline_request(key, name)))
}

/// Loads an offline license file (JSON text) the server issued for this machine.
///
/// # Safety
/// `client` a live seal_client; `license_file` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_activate_offline(client: *const SealClient, license_file: *const c_char, now_ms: f64) -> *mut SealResult {
    // SAFETY: per this function's contract.
    let Some(file) = (unsafe { text(license_file) }) else { return std::ptr::null_mut() };
    if !now_ms.is_finite() {
        return std::ptr::null_mut();
    }
    with_client(client, |c, _| done_state(c.activate_offline(file, now_ms)))
}

/// Removes an offline license and returns the deactivation file (JSON text, seal_result_text).
///
/// # Safety
/// `client` a live seal_client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_deactivate_offline(client: *const SealClient) -> *mut SealResult {
    with_client(client, |c, _| done_text(c.deactivate_offline()))
}

/// Decrypts data encrypted for a feature with the saved lease (seal_result_data).
///
/// # Safety
/// `client` a live seal_client; `feature` NUL-terminated; `data` `data_len` readable bytes or NULL with 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_client_decrypt(client: *const SealClient, feature: *const c_char, data: *const u8, data_len: usize, now_ms: f64) -> *mut SealResult {
    // SAFETY: per this function's contract.
    let Some(feature) = (unsafe { text(feature) }) else { return std::ptr::null_mut() };
    if (data.is_null() && data_len != 0) || !now_ms.is_finite() {
        return std::ptr::null_mut();
    }
    let data: Vec<u8> = if data_len == 0 {
        Vec::new()
    } else {
        // SAFETY: data_len readable bytes per the contract.
        unsafe { std::slice::from_raw_parts(data, data_len) }.to_vec()
    };
    with_client(client, |c, _| match c.decrypt(feature, &data, now_ms) {
        Ok(plain) => {
            use base64::Engine;
            // The plaintext is in the JSON too (base64), so the JSON is built without copies that would be freed
            // unwiped, and seal_result_free wipes it with the data.
            let mut encoded = base64::engine::general_purpose::STANDARD.encode(&plain);
            let mut text = String::with_capacity(encoded.len() + 32);
            text.push_str(r#"{"ok":true,"value":""#);
            text.push_str(&encoded);
            text.push_str(r#""}"#);
            // SAFETY: zero bytes keep the string valid UTF-8, and it is not used again.
            wipe(unsafe { encoded.as_bytes_mut() });
            let mut r = base(SEAL_RESULT_DONE, Value::Null);
            // Base64 and the JSON around it hold no NUL, and the capacity has room for the terminator: no copy.
            r.json = CString::new(text).unwrap_or_default();
            r.data = Some(plain);
            r
        }
        Err(e) => failed(e),
    })
}

// ---- Result accessors -----------------------------------------------------------------------

/// Frees a result; NULL is ignored.
///
/// # Safety
/// `result` must be NULL or a pointer from a seal_client_* function not freed yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_free(result: *mut SealResult) {
    if !result.is_null() {
        // SAFETY: from Box::into_raw, freed once per the contract.
        let mut r = unsafe { Box::from_raw(result) };
        if let Some(data) = r.data.as_mut() {
            // Feature plaintext, here and as base64 in the JSON: overwritten before the memory is released.
            wipe(data);
            let mut json = std::mem::take(&mut r.json).into_bytes_with_nul();
            wipe(&mut json);
        }
    }
}

/// Overwrites bytes with zeros in a way the compiler does not remove.
fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: a valid, aligned byte of the slice.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// # Safety
/// `result` must be NULL or a live result.
unsafe fn get<'a>(result: *const SealResult) -> Option<&'a SealResult> {
    // SAFETY: per the callers' contracts.
    unsafe { result.as_ref() }
}

/// SEAL_RESULT_SEND, SEAL_RESULT_DONE or SEAL_RESULT_ERROR; 0 for NULL.
///
/// # Safety
/// `result` must be NULL or a live result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_kind(result: *const SealResult) -> i32 {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.map_or(0, |r| r.kind)
}

/// The whole result as JSON: {"send":{"path","body"}}, {"ok":true,"value":…} or {"ok":false,"error":{"code","message"}}.
///
/// # Safety
/// `result` must be NULL or a live result; the string lives as long as the result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_json(result: *const SealResult) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.map_or(std::ptr::null(), |r| r.json.as_ptr())
}

fn ptr(s: &Option<CString>) -> *const c_char {
    s.as_ref().map_or(std::ptr::null(), |s| s.as_ptr())
}

/// The request path to POST to (after the server URL); NULL unless SEAL_RESULT_SEND.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_request_path(result: *const SealResult) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.map_or(std::ptr::null(), |r| ptr(&r.path))
}

/// The whole address to POST to (server URL + path); NULL unless SEAL_RESULT_SEND.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_request_url(result: *const SealResult) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.map_or(std::ptr::null(), |r| ptr(&r.url))
}

/// The JSON body to POST, as is; NULL unless SEAL_RESULT_SEND.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_request_body(result: *const SealResult) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.map_or(std::ptr::null(), |r| ptr(&r.body))
}

/// The error code ("network", "activation_limit", "wrong_device", …); NULL unless SEAL_RESULT_ERROR.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_error_code(result: *const SealResult) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.and_then(|r| r.error.as_ref()).map_or(std::ptr::null(), |(c, _)| c.as_ptr())
}

/// The error message to show; NULL unless SEAL_RESULT_ERROR.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_error_message(result: *const SealResult) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.and_then(|r| r.error.as_ref()).map_or(std::ptr::null(), |(_, m)| m.as_ptr())
}

/// The license status (SEAL_STATUS_*), or 0 when the result holds no state.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_state_status(result: *const SealResult) -> i32 {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.and_then(|r| r.state.as_ref()).map_or(0, |(s, _)| match s.status {
        Status::Valid => 1,
        Status::Grace => 2,
        Status::Invalid => 3,
        Status::Unlicensed => 4,
        Status::ClockSuspect => 5,
    })
}

/// A flag of the state (SEAL_FLAG_*): 1 or 0; -1 when the result holds no state or the flag is unknown.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_state_flag(result: *const SealResult, flag: i32) -> i32 {
    // SAFETY: per this function's contract.
    let Some((s, _)) = (unsafe { get(result) }).and_then(|r| r.state.as_ref()) else { return -1 };
    match flag {
        SEAL_FLAG_OFFLINE => i32::from(s.offline),
        SEAL_FLAG_STORAGE_PROTECTED => i32::from(s.storage_protected),
        SEAL_FLAG_OFFLINE_ACTIVATED => i32::from(s.offline_activated),
        _ => -1,
    }
}

/// A text field of the state (SEAL_FIELD_*); NULL when absent.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_state_text(result: *const SealResult, field: i32) -> *const c_char {
    // SAFETY: per this function's contract.
    let Some((_, strings)) = (unsafe { get(result) }).and_then(|r| r.state.as_ref()) else { return std::ptr::null() };
    usize::try_from(field - 1).ok().and_then(|i| strings.fields.get(i)).map_or(std::ptr::null(), ptr)
}

/// Number of licensed features in the state.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_state_feature_count(result: *const SealResult) -> usize {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.and_then(|r| r.state.as_ref()).map_or(0, |(_, s)| s.features.len())
}

/// Feature `index`; NULL past the end.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_state_feature(result: *const SealResult, index: usize) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.and_then(|r| r.state.as_ref()).and_then(|(_, s)| s.features.get(index)).map_or(std::ptr::null(), |f| f.as_ptr())
}

/// 1 when the state grants the feature (valid or in grace), else 0.
///
/// # Safety
/// As seal_result_json; `feature` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_state_has_feature(result: *const SealResult, feature: *const c_char) -> i32 {
    // SAFETY: per this function's contract.
    let (Some((s, _)), Some(feature)) = ((unsafe { get(result) }).and_then(|r| r.state.as_ref()), unsafe { text(feature) }) else { return 0 };
    i32::from(s.has_feature(feature))
}

/// The file text of seal_client_offline_request and seal_client_deactivate_offline; NULL otherwise.
///
/// # Safety
/// As seal_result_json.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_text(result: *const SealResult) -> *const c_char {
    // SAFETY: per this function's contract.
    unsafe { get(result) }.map_or(std::ptr::null(), |r| ptr(&r.text))
}

/// The plaintext of seal_client_decrypt and its length; NULL otherwise. Overwritten when the result is freed.
///
/// # Safety
/// As seal_result_json; `len` NULL or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seal_result_data(result: *const SealResult, len: *mut usize) -> *const u8 {
    // SAFETY: per this function's contract.
    let data = unsafe { get(result) }.and_then(|r| r.data.as_ref());
    if !len.is_null() {
        // SAFETY: writable per the contract.
        unsafe { *len = data.map_or(0, Vec::len) };
    }
    data.map_or(std::ptr::null(), |d| if d.is_empty() { std::ptr::NonNull::<u8>::dangling().as_ptr() } else { d.as_ptr() })
}
