# Changelog

Security fixes are marked **Security** and released as patch versions, apart from functional changes where
technically feasible.

## Unreleased

- `decryptFeature` also opens data encrypted under a feature's previous content key, when the lease carries it
  (`fk["<feature>~previous"]`, exported as `PREVIOUS_KEY_SUFFIX`) because the vendor replaced the key on the server.
  Data under the current key opens as before.

## 0.4.0 and earlier

Recorded in the git history; this changelog starts after 0.4.0.
