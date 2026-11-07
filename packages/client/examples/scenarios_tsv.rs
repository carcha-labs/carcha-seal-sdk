//! Writes the client scenarios of tests/vectors.json as tab-separated lines for SDKs that test without a JSON
//! parser (the C++ wrapper's tests). Fields are escaped: \\ \t \n; "\N" means absent.
//!
//!   S  name  product  public keys  grace days  app version  machine id
//!   T  call  arg0  arg1 (decrypt: the data as hex)  now ms  response status (-1 none, 0 no answer)  response body
//!      request path  request body (canonical JSON)  outcome...
//!
//! outcome: E code message | N (nothing) | X file text (pretty JSON) | D hex | V status offline storageProtected
//! offlineActivated reason message customer expiresAt maintenanceUntil revalidateBy keyHint features(,) notices
//! Request bodies and files keep the "<sdk-version>" and "<platform>" placeholders for the test to fill in.
//! The scenario whose machine id cannot be read is left out: wrappers cannot set an unreadable id.

use serde_json::Value;

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\t', "\\t").replace('\n', "\\n")
}

fn opt(v: &Value) -> String {
    match v {
        Value::Null => "\\N".into(),
        Value::String(s) => esc(s),
        other => esc(&other.to_string()),
    }
}

fn main() {
    let file: Value = serde_json::from_str(include_str!("../tests/vectors.json")).unwrap();
    for s in file["scenarios"].as_array().unwrap() {
        if s["machineId"].is_null() {
            continue;
        }
        let o = &s["options"];
        let keys: Vec<&str> = o["publicKey"].as_array().unwrap().iter().map(|k| k.as_str().unwrap()).collect();
        println!("S\t{}\t{}\t{}\t{}\t{}\t{}", esc(s["name"].as_str().unwrap()), opt(&o["product"]), esc(&keys.join("")), opt(&o["graceDays"]), opt(&o["appVersion"]), opt(&s["machineId"]));
        for (step, outcome) in s["steps"].as_array().unwrap().iter().zip(s["outcomes"].as_array().unwrap()) {
            let args = step["args"].as_array().cloned().unwrap_or_default();
            let decrypt = step["call"] == "decrypt";
            let arg = |i: usize| {
                args.get(i).map_or("\\N".to_string(), |a| {
                    let a = a.as_str().unwrap();
                    if decrypt && i == 1 {
                        // The data as hex, so the test needs no base64 decoder.
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.decode(a).unwrap().iter().map(|b| format!("{b:02x}")).collect()
                    } else {
                        esc(a)
                    }
                })
            };
            let (status, body) = match &step["response"] {
                Value::Null => ("-1".to_string(), "\\N".to_string()),
                r if r.get("network").is_some() => ("0".to_string(), "\\N".to_string()),
                r => (r["status"].to_string(), esc(&r.get("raw").and_then(Value::as_str).map_or_else(|| r.get("body").map_or("{}".to_string(), Value::to_string), String::from))),
            };
            let requests = outcome["requests"].as_array().unwrap();
            assert!(requests.len() <= 1);
            let (path, req_body) = requests.first().map_or(("\\N".to_string(), "\\N".to_string()), |r| (esc(r["path"].as_str().unwrap()), esc(&r["body"].to_string())));
            let result = &outcome["result"];
            let out = if result["ok"] == false {
                format!("E\t{}\t{}", esc(result["error"]["code"].as_str().unwrap()), esc(result["error"]["message"].as_str().unwrap()))
            } else {
                let v = &result["value"];
                match step["call"].as_str().unwrap() {
                    "deactivate" => "N".to_string(),
                    "offlineRequest" | "deactivateOffline" => format!("X\t{}", esc(&serde_json::to_string_pretty(v).unwrap())),
                    "decrypt" => {
                        use base64::Engine;
                        let bytes = base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap();
                        format!("D\t{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
                    }
                    _ => {
                        let flag = |name: &str| if v[name] == true { "1" } else { "0" };
                        let features: Vec<&str> = v["features"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
                        let notices = v.get("notices").map_or("\\N".to_string(), |n| esc(&n.to_string()));
                        let fields = ["reason", "message", "customer", "expiresAt", "maintenanceUntil", "revalidateBy", "keyHint"].map(|n| opt(v.get(n).unwrap_or(&Value::Null)));
                        format!("V\t{}\t{}\t{}\t{}\t{}\t{}\t{}", v["status"].as_str().unwrap(), flag("offline"), flag("storageProtected"), flag("offlineActivated"), fields.join("\t"), esc(&features.join(",")), notices)
                    }
                }
            };
            println!("T\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}", step["call"].as_str().unwrap(), arg(0), arg(1), step["nowMs"], status, body, path, req_body, out);
        }
    }
}
