//! Every scenario in vectors.json (recorded from @carchalabs/seal-electron by make-vectors.js) gives the same
//! requests and results here, step by step on the same storage.

use base64::Engine;
use seal_client::{Client, Config, LicenseError, MemoryStorage, Outcome, Response};
use seal_lease::TrustedKey;
use serde_json::{Value, json};

fn response(scripted: &Value) -> Response {
    if scripted.get("network").is_some() || scripted.is_null() {
        return Response::Network;
    }
    let status = scripted["status"].as_u64().unwrap() as u16;
    let body = match scripted.get("raw").and_then(Value::as_str) {
        Some(raw) => raw.as_bytes().to_vec(),
        None => serde_json::to_vec(scripted.get("body").unwrap_or(&json!({}))).unwrap(),
    };
    Response::Http { status, body }
}

fn result<T>(r: Result<T, LicenseError>, value: impl FnOnce(T) -> Value) -> Value {
    match r {
        Ok(v) => json!({ "ok": true, "value": value(v) }),
        Err(e) => json!({ "ok": false, "error": { "code": e.code, "message": e.message } }),
    }
}

#[test]
fn every_client_scenario_matches_the_electron_sdk() {
    let file: Value = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let scenarios = file["scenarios"].as_array().unwrap();
    assert!(scenarios.len() >= 25);
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut steps_run = 0;
    for scenario in scenarios {
        let name = scenario["name"].as_str().unwrap();
        let o = &scenario["options"];
        let keys: Vec<TrustedKey> = o["publicKey"].as_array().unwrap().iter().map(|k| TrustedKey::from_spki_pem(k.as_str().unwrap()).unwrap()).collect();
        let mut config = Config::new(o["product"].as_str().unwrap(), keys, "<sdk-version>", "<platform>");
        config.grace_days = o["graceDays"].as_f64();
        config.app_version = o["appVersion"].as_str().map(String::from);
        let machine_id = scenario["machineId"].as_str().map(String::from);
        config.machine_id = Box::new(move || machine_id.clone());
        let mut client = Client::new(config, MemoryStorage::default());

        for (i, (step, expected)) in scenario["steps"].as_array().unwrap().iter().zip(scenario["outcomes"].as_array().unwrap()).enumerate() {
            let now = step["nowMs"].as_f64().unwrap();
            let args = step["args"].as_array().cloned().unwrap_or_default();
            let arg = |n: usize| args.get(n).and_then(Value::as_str);
            let mut requests = Vec::new();
            let mut send = |request: seal_client::Request| {
                requests.push(json!({ "path": request.path, "body": request.body }));
                response(&step["response"])
            };
            let got = match step["call"].as_str().unwrap() {
                "activate" => result(
                    match client.activate_begin(arg(0).unwrap(), arg(1)) {
                        Outcome::Send(r) => client.activate_finish(send(r), now),
                        Outcome::Done(d) => d,
                    },
                    |s| s.to_json(),
                ),
                "check" => result(
                    match client.check_begin(now) {
                        Outcome::Send(r) => client.check_finish(send(r), now),
                        Outcome::Done(d) => d,
                    },
                    |s| s.to_json(),
                ),
                "deactivate" => result(
                    match client.deactivate_begin() {
                        Outcome::Send(r) => client.deactivate_finish(send(r)),
                        Outcome::Done(d) => d,
                    },
                    |_| Value::Null,
                ),
                "offlineRequest" => result(client.offline_request(arg(0).unwrap(), arg(1)), |t| serde_json::from_str(&t).unwrap()),
                "activateOffline" => result(client.activate_offline(arg(0).unwrap(), now), |s| s.to_json()),
                "deactivateOffline" => result(client.deactivate_offline(), |t| serde_json::from_str(&t).unwrap()),
                "decrypt" => result(client.decrypt(arg(0).unwrap(), &b64.decode(arg(1).unwrap()).unwrap(), now), |d| json!(b64.encode(d))),
                other => panic!("unknown call {other}"),
            };
            let outcome = json!({ "requests": requests, "result": got });
            assert_eq!(outcome, *expected, "{name}, step {} ({})", i + 1, step["call"]);
            steps_run += 1;
        }
    }
    assert!(steps_run >= 90, "{steps_run} steps");
}
