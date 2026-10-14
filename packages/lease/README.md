# licensekit_lease

Verifies LicenseKit leases (compact JWS, Ed25519) with the same rules, order and failure reasons as `verifyLease` in `@carchalabs/licensekit-core`: algorithm `Ed25519` only, type `licensekit-lease+jwt`, no `crit` header, a trusted key id, a valid signature (`verify_strict`), then the claims shape, issuer, product, device fingerprint, `nbf` / `exp` with the same clock-skew leeway, and the revalidation time with the grace period.

Used by the Node-API module (`../hwid-node`), which compiles in the keys it trusts.

```
cargo test   # unit tests + tests/conformance.rs: every vector in tests/vectors.json gives core's result
node tests/make-vectors.js   # regenerate the vectors (from the repository root's built core)
```
