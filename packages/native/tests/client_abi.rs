//! The client scenarios of ../client/tests/vectors.json (recorded from the Electron SDK) through the C
//! interface: seal_client_options, the begin/finish calls and the result accessors, with license.dat in a
//! folder as an app keeps it. The SDK version and platform this library sends are compared as the
//! recorded placeholders.

use std::ffi::{CStr, CString, c_char};

use seal_native::*;
use serde_json::{Value, json};

fn read(p: *const c_char) -> Option<String> {
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string())
}

/// As the recorder's placeholders(): sdkVersion and platform, also inside an offline request's activation.
fn placeholders(mut v: Value) -> Value {
    if let Some(o) = v.as_object_mut() {
        if o.contains_key("sdkVersion") {
            assert_eq!(o["sdkVersion"], SDK_VERSION);
            o.insert("sdkVersion".into(), json!("<sdk-version>"));
        }
        if o.contains_key("platform") {
            assert!(["win32", "darwin", "linux"].contains(&o["platform"].as_str().unwrap()));
            o.insert("platform".into(), json!("<platform>"));
        }
        if let Some(a) = o.remove("activation") {
            o.insert("activation".into(), placeholders(a));
        }
    }
    v
}

/// Checks the accessors against the result's JSON, so both views say the same thing.
fn accessors_agree(r: *const SealResult, json: &Value) {
    unsafe {
        match seal_result_kind(r) {
            SEAL_RESULT_ERROR => {
                assert_eq!(read(seal_result_error_code(r)).as_deref(), json["error"]["code"].as_str());
                assert_eq!(read(seal_result_error_message(r)).as_deref(), json["error"]["message"].as_str());
                assert_eq!(seal_state_status(r), 0);
            }
            SEAL_RESULT_DONE => {
                let v = &json["value"];
                if v.get("status").is_some() {
                    let statuses = ["", "valid", "grace", "invalid", "unlicensed", "clock_suspect"];
                    assert_eq!(statuses[seal_state_status(r) as usize], v["status"]);
                    assert_eq!(seal_state_flag(r, SEAL_FLAG_OFFLINE), i32::from(v["offline"] == true));
                    assert_eq!(seal_state_flag(r, SEAL_FLAG_STORAGE_PROTECTED), 0);
                    assert_eq!(seal_state_flag(r, SEAL_FLAG_OFFLINE_ACTIVATED), i32::from(v["offlineActivated"] == true));
                    for (field, name) in [(1, "reason"), (2, "message"), (3, "customer"), (4, "expiresAt"), (5, "maintenanceUntil"), (6, "revalidateBy"), (7, "keyHint")] {
                        assert_eq!(read(seal_state_text(r, field)).as_deref(), v[name].as_str(), "{name}");
                    }
                    let notices = read(seal_state_text(r, SEAL_FIELD_NOTICES_JSON)).map(|t| serde_json::from_str::<Value>(&t).unwrap());
                    assert_eq!(notices.as_ref(), v.get("notices"));
                    let features: Vec<String> = (0..seal_state_feature_count(r)).map(|i| read(seal_state_feature(r, i)).unwrap()).collect();
                    assert_eq!(json!(features), v["features"]);
                    assert!(seal_state_feature(r, features.len()).is_null());
                    let usable = v["status"] == "valid" || v["status"] == "grace";
                    for f in &features {
                        let f = CString::new(f.as_str()).unwrap();
                        assert_eq!(seal_state_has_feature(r, f.as_ptr()), i32::from(usable));
                    }
                } else if v.is_string() {
                    let mut len = 0usize;
                    let data = seal_result_data(r, &mut len);
                    use base64::Engine;
                    assert_eq!(base64::engine::general_purpose::STANDARD.encode(std::slice::from_raw_parts(data, len)), v.as_str().unwrap());
                } else if v.is_object() {
                    let text: Value = serde_json::from_str(&read(seal_result_text(r)).unwrap()).unwrap();
                    assert_eq!(&text, v);
                }
            }
            other => panic!("kind {other}"),
        }
    }
}

struct Client(*mut SealClient);
impl Drop for Client {
    fn drop(&mut self) {
        unsafe { seal_client_free(self.0) };
    }
}

#[test]
fn every_client_scenario_through_the_c_interface() {
    let file: Value = serde_json::from_str(include_str!("../../client/tests/vectors.json")).unwrap();
    let mut steps_run = 0;
    for (n, scenario) in file["scenarios"].as_array().unwrap().iter().enumerate() {
        let name = scenario["name"].as_str().unwrap();
        // NULL machine_id means "read this machine's id"; an unreadable id is covered in packages/client.
        let Some(machine_id) = scenario["machineId"].as_str() else { continue };
        let o = &scenario["options"];
        let dir = std::env::temp_dir().join(format!("seal-native-abi-{}-{n}", std::process::id()));
        let keys: Vec<&str> = o["publicKey"].as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
        let (product, keys, dir_c, machine) =
            (CString::new(o["product"].as_str().unwrap()).unwrap(), CString::new(keys.join("")).unwrap(), CString::new(dir.to_str().unwrap()).unwrap(), CString::new(machine_id).unwrap());
        let app_version = o["appVersion"].as_str().map(|v| CString::new(v).unwrap());
        let sdk = CString::new("test").unwrap();
        let mut options = std::mem::MaybeUninit::<SealClientOptions>::uninit();
        let client = unsafe {
            seal_client_options_init(options.as_mut_ptr());
            let mut options = options.assume_init();
            options.product = product.as_ptr();
            options.public_keys = keys.as_ptr();
            options.storage_dir = dir_c.as_ptr();
            options.machine_id = machine.as_ptr();
            options.sdk_name = sdk.as_ptr();
            options.hardware = 0;
            options.app_version = app_version.as_ref().map_or(std::ptr::null(), |v| v.as_ptr());
            if let Some(g) = o["graceDays"].as_f64() {
                options.grace_days = g;
            }
            Client(seal_client_new(&options))
        };
        assert!(!client.0.is_null(), "{name}");
        assert_eq!(read(unsafe { seal_client_user_agent(client.0) }).unwrap(), format!("carcha-seal-native/{SDK_VERSION} (test)"));

        for (i, (step, expected)) in scenario["steps"].as_array().unwrap().iter().zip(scenario["outcomes"].as_array().unwrap()).enumerate() {
            let now = step["nowMs"].as_f64().unwrap();
            let args: Vec<CString> = step["args"].as_array().map(|a| a.iter().map(|x| CString::new(x.as_str().unwrap()).unwrap()).collect()).unwrap_or_default();
            let arg = |k: usize| args.get(k).map_or(std::ptr::null(), |a| a.as_ptr());
            let (status, body): (i32, Vec<u8>) = match &step["response"] {
                Value::Null => (0, Vec::new()),
                r if r.get("network").is_some() => (0, Vec::new()),
                r => (
                    r["status"].as_i64().unwrap() as i32,
                    r.get("raw").and_then(Value::as_str).map_or_else(|| serde_json::to_vec(r.get("body").unwrap_or(&json!({}))).unwrap(), |t| t.as_bytes().to_vec()),
                ),
            };
            let mut requests = Vec::new();
            let c = client.0;
            let mut two_step = |begin: *mut SealResult, finish: &dyn Fn() -> *mut SealResult| -> *mut SealResult {
                assert!(!begin.is_null());
                if unsafe { seal_result_kind(begin) } != SEAL_RESULT_SEND {
                    return begin;
                }
                let path = read(unsafe { seal_result_request_path(begin) }).unwrap();
                let body: Value = serde_json::from_str(&read(unsafe { seal_result_request_body(begin) }).unwrap()).unwrap();
                let whole: Value = serde_json::from_str(&read(unsafe { seal_result_json(begin) }).unwrap()).unwrap();
                assert_eq!(whole, json!({ "send": { "path": path, "body": body } }));
                requests.push(json!({ "path": path, "body": placeholders(body) }));
                unsafe { seal_result_free(begin) };
                finish()
            };
            let r = unsafe {
                match step["call"].as_str().unwrap() {
                    "activate" => two_step(seal_client_activate_begin(c, arg(0), arg(1)), &|| seal_client_activate_finish(c, status, body.as_ptr(), body.len(), now)),
                    "check" => two_step(seal_client_check_begin(c, now), &|| seal_client_check_finish(c, status, body.as_ptr(), body.len(), now)),
                    "deactivate" => two_step(seal_client_deactivate_begin(c), &|| seal_client_deactivate_finish(c, status, body.as_ptr(), body.len())),
                    "offlineRequest" => seal_client_offline_request(c, arg(0), arg(1)),
                    "activateOffline" => seal_client_activate_offline(c, arg(0), now),
                    "deactivateOffline" => seal_client_deactivate_offline(c),
                    "decrypt" => {
                        use base64::Engine;
                        let data = base64::engine::general_purpose::STANDARD.decode(step["args"][1].as_str().unwrap()).unwrap();
                        seal_client_decrypt(c, arg(0), data.as_ptr(), data.len(), now)
                    }
                    other => panic!("unknown call {other}"),
                }
            };
            assert!(!r.is_null(), "{name}, step {}", i + 1);
            let mut json: Value = serde_json::from_str(&read(unsafe { seal_result_json(r) }).unwrap()).unwrap();
            accessors_agree(r, &json);
            if json["value"].get("activation").is_some() {
                json["value"] = placeholders(json["value"].take());
            }
            unsafe { seal_result_free(r) };
            assert_eq!(json!({ "requests": requests, "result": json }), *expected, "{name}, step {} ({})", i + 1, step["call"]);
            steps_run += 1;
        }
        drop(client);
        let _ = std::fs::remove_dir_all(&dir);
    }
    assert!(steps_run >= 90, "{steps_run} steps");
}

#[test]
fn options_that_are_refused() {
    let (product, keys, dir) = (CString::new("studio").unwrap(), CString::new(include_str!("../../client/tests/vectors.json").split('"').nth(3).unwrap().replace("\\n", "\n")).unwrap(), CString::new("/tmp/x").unwrap());
    let base = || unsafe {
        let mut o = std::mem::MaybeUninit::<SealClientOptions>::uninit();
        seal_client_options_init(o.as_mut_ptr());
        let mut o = o.assume_init();
        o.product = product.as_ptr();
        o.public_keys = keys.as_ptr();
        o.storage_dir = dir.as_ptr();
        o
    };
    let ok = base();
    let c = unsafe { seal_client_new(&ok) };
    assert!(!c.is_null(), "the defaults with product, keys and folder");
    assert_eq!(read(unsafe { seal_client_user_agent(c) }).unwrap(), format!("carcha-seal-native/{SDK_VERSION} (c)"));
    unsafe { seal_client_free(c) };
    let bad_name = CString::new("C Sharp").unwrap();
    let empty = CString::new("").unwrap();
    type Change<'a> = Box<dyn Fn(&mut SealClientOptions) + 'a>;
    let cases: Vec<(&str, Change)> = vec![
        ("no product", Box::new(|o| o.product = std::ptr::null())),
        ("empty product", Box::new(|o| o.product = empty.as_ptr())),
        ("no keys", Box::new(|o| o.public_keys = std::ptr::null())),
        ("bad keys", Box::new(|o| o.public_keys = empty.as_ptr())),
        ("no folder", Box::new(|o| o.storage_dir = std::ptr::null())),
        ("NaN grace", Box::new(|o| o.grace_days = f64::NAN)),
        ("infinite grace", Box::new(|o| o.grace_days = f64::INFINITY)),
        ("SDK name with spaces", Box::new(|o| o.sdk_name = bad_name.as_ptr())),
    ];
    for (label, change) in cases {
        let mut o = base();
        change(&mut o);
        assert!(unsafe { seal_client_new(&o) }.is_null(), "{label}");
    }
    assert!(unsafe { seal_client_new(std::ptr::null()) }.is_null());
    assert!(unsafe { seal_client_check_begin(std::ptr::null(), 0.0) }.is_null());
    unsafe { seal_result_free(std::ptr::null_mut()) };
    unsafe { seal_client_free(std::ptr::null_mut()) };
}
