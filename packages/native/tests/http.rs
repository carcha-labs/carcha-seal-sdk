//! The built-in HTTP client against a local server (http:// is allowed for this computer only): what it sends,
//! statuses and bodies, redirects refused, no connection, a timeout, and refused addresses.
#![cfg(feature = "http")]

use std::ffi::CString;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use seal_native::{SEAL_E_ARGS, seal_bytes_free, seal_http_post};

/// One request on a local port: the raw request it got is sent back on the channel, `answer` is written as is.
fn serve_once(answer: &'static str, delay: Duration) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        let mut length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                length = v.trim().parse().unwrap();
            }
            head.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).unwrap();
        tx.send(format!("{head}{}", String::from_utf8(body).unwrap())).unwrap();
        std::thread::sleep(delay);
        let mut stream = stream;
        let _ = stream.write_all(answer.as_bytes());
    });
    (url, rx)
}

fn post(url: &str, timeout_ms: u32) -> (i32, Vec<u8>) {
    let (url, agent, body) = (CString::new(url).unwrap(), CString::new("carcha-seal-native/test (cpp)").unwrap(), CString::new(r#"{"licenseKey":"LK-A"}"#).unwrap());
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut len = 0usize;
    let status = unsafe { seal_http_post(url.as_ptr(), agent.as_ptr(), body.as_ptr(), timeout_ms, &mut out, &mut len) };
    let bytes = if out.is_null() { Vec::new() } else { unsafe { std::slice::from_raw_parts(out, len) }.to_vec() };
    unsafe { seal_bytes_free(out, len) };
    (status, bytes)
}

#[test]
fn posts_json_with_the_user_agent_and_returns_status_and_body() {
    let (url, got) = serve_once("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"token\":\"t\"}", Duration::ZERO);
    let (status, body) = post(&format!("{url}/v1/validate"), 5000);
    assert_eq!((status, body.as_slice()), (200, &b"{\"token\":\"t\"}"[..]));
    let request = got.recv().unwrap().to_ascii_lowercase();
    assert!(request.starts_with("post /v1/validate http/1.1\r\n"), "{request}");
    assert!(request.contains("\r\ncontent-type: application/json\r\n"), "{request}");
    assert!(request.contains("\r\nuser-agent: carcha-seal-native/test (cpp)\r\n"), "{request}");
    assert!(request.ends_with("{\"licensekey\":\"lk-a\"}"), "{request}");
}

#[test]
fn a_refusal_comes_back_with_its_status_and_body() {
    let (url, _got) = serve_once("HTTP/1.1 409 Conflict\r\nContent-Length: 28\r\nConnection: close\r\n\r\n{\"error\":\"activation_limit\"}", Duration::ZERO);
    let (status, body) = post(&format!("{url}/v1/activate"), 5000);
    assert_eq!((status, body.as_slice()), (409, &b"{\"error\":\"activation_limit\"}"[..]));
}

#[test]
fn a_redirect_is_not_followed() {
    // 307/308 keep the POST and its body; 301/302/303 turn it into a GET of the other address. Neither is followed.
    for code in ["307 Temporary Redirect", "308 Permanent Redirect", "301 Moved Permanently", "302 Found", "303 See Other"] {
        let (target, reached) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", Duration::ZERO);
        let answer: &'static str = Box::leak(format!("HTTP/1.1 {code}\r\nLocation: {target}/v1/activate\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_boxed_str());
        let (url, _got) = serve_once(answer, Duration::ZERO);
        assert_eq!(post(&format!("{url}/v1/activate"), 5000), (0, Vec::new()), "{code}");
        assert!(reached.recv_timeout(Duration::from_millis(300)).is_err(), "{code}: the other address was not reached");
    }
}

#[test]
fn no_connection_and_a_timeout_are_no_answer() {
    let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    assert_eq!(post(&format!("http://127.0.0.1:{port}/v1/validate"), 2000), (0, Vec::new()), "nothing listening");
    let (url, _got) = serve_once("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", Duration::from_millis(1500));
    assert_eq!(post(&format!("{url}/v1/validate"), 300), (0, Vec::new()), "timeout");
}

#[test]
fn plain_http_elsewhere_and_bad_arguments_are_refused() {
    assert_eq!(post("http://seal.carchalabs.com/v1/validate", 1000).0, SEAL_E_ARGS);
    assert_eq!(post("not a url", 1000).0, SEAL_E_ARGS);
    assert_eq!(post("http://127.0.0.1:1/v1/validate", 0).0, SEAL_E_ARGS, "zero timeout");
    let url = CString::new("http://127.0.0.1:1").unwrap();
    let mut out: *mut u8 = std::ptr::null_mut();
    let mut len = 0usize;
    assert_eq!(unsafe { seal_http_post(url.as_ptr(), std::ptr::null(), url.as_ptr(), 1000, &mut out, &mut len) }, SEAL_E_ARGS);
    unsafe { seal_bytes_free(std::ptr::null_mut(), 0) };
}
