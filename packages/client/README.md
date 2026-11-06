# seal_client

The Carcha Seal license client of the native SDKs (C++, C#, Java), in Rust: activation, check-ins, offline grace, clock checks, refusals kept offline, offline license files and feature decryption, with the same behaviour as the `Seal` class of `@carchalabs/seal-electron`. It keeps the same `license.dat` record as that SDK.

It does no network I/O. An operation that needs the server returns `Outcome::Send` with the request (path and JSON body); the caller posts it with its own HTTP stack, so the app's proxy and certificate settings apply, and passes the answer to the matching `*_finish` method:

```rust
let mut client = Client::new(config, FileStorage::new(dir));
let state = match client.check_begin(now_ms) {
    Outcome::Send(request) => client.check_finish(post(&server_url, request), now_ms),
    Outcome::Done(result) => result,
}?;
```

## Tests

`tests/vectors.json` records how the Electron SDK behaves: scenarios of activation, check-ins, offline grace, clock checks, refusals, deactivation, offline files and feature decryption, each run with a scripted license server and a set clock. For every step it holds what the SDK sent (path and body) and what it returned (the license state, or the error code and message). The SDK version and platform in request bodies are placeholders. `tests/vectors.rs` runs every step here and requires the same requests and results.

```
cargo test                                     # unit tests + every scenario
npm run build                                  # from the repository root, then:
node packages/client/tests/make-vectors.js     # regenerate after a deliberate change to the Electron SDK's behaviour
npm test -w packages/sdk-electron              # client-vectors.test.ts: the file still matches the Electron SDK
```

Leases are signed with the throwaway test key of `../lease/tests/vectors.json`.
