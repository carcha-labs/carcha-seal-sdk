# Carcha Seal and the EU Cyber Resilience Act

For software vendors who build Carcha Seal into their apps: who is responsible for what under the Cyber Resilience
Act (Regulation (EU) 2024/2847), what Carcha Labs provides for Seal, and what stays with you. This is Carcha Labs'
reading of the Regulation, not legal advice.

## Who is the manufacturer of what

- **Carcha Labs is the manufacturer of Carcha Seal**: the npm packages and Rust crates in this repository, and the
  Carcha Seal server at `seal.carchalabs.com`. The server is part of the same product: the Regulation counts a
  product's "remote data processing solutions" with it, meaning processing "the absence of which would prevent the
  product with digital elements from performing one of its functions" (Article 3(1) and (2)). Without the server
  there is no activation or licence check.
- **You are the manufacturer of your app.** Carcha Seal is a component of it.
- **Category.** Carcha Labs treats Seal as a product in the default category: licensing software is not among the
  important or critical product categories of Annexes III and IV.

## When it applies

| From | What |
|---|---|
| 11 September 2026 | Reporting actively exploited vulnerabilities and severe incidents (Article 14), also for products already on the market |
| 11 December 2027 | Everything else: the security requirements of Annex I, the software bill of materials, conformity assessment and CE marking. A product placed on the market before this date falls under them once it is substantially modified (Article 69(2)). |

## What Carcha Labs does for Carcha Seal

| Obligation | What Carcha Labs does |
|---|---|
| Designed, developed and produced to the security requirements of Annex I Part I (Article 13(1)) | Leases are Ed25519-signed and verified offline with the algorithm pinned; AES-256-GCM with a fresh random nonce for every encryption; a dependency audit (npm audit, cargo audit) blocks CI and publishing on a known high-severity advisory; every build action pinned to a commit. |
| A software bill of materials (Annex I Part II(1)) | A CycloneDX SBOM for each package version, attached to each GitHub release ([SECURITY.md](SECURITY.md#software-bill-of-materials)). |
| Vulnerability handling and coordinated disclosure (Annex I Part II) | [SECURITY.md](SECURITY.md): report to security@carchalabs.com or privately on GitHub; acknowledged within 3 business days, assessed within 10, disclosed within 90 days or when fixed. Also published at `seal.carchalabs.com/.well-known/security.txt`. |
| Security updates without delay and free of charge (Annex I Part II(2) and (8)) | Fixes go into the latest release of every supported version. |
| A support period of at least five years, with its end date stated (Article 13(8) and (19)) | From 1.0.0, each major version gets security fixes for at least five years; the end month and year are in [SECURITY.md](SECURITY.md#supported-versions-and-support-period). |
| Security updates stay available for ten years (Article 13(9)) | Every release stays on npm; none is unpublished. |
| Reporting to ENISA's Single Reporting Platform (Article 14) | An actively exploited vulnerability or a severe incident in Seal is reported by Carcha Labs: early warning within 24 hours, notification within 72 hours, final report after. |
| Informing users (Article 14(8)) | You are told about such a vulnerability or incident, and what to do about it, in a GitHub security advisory on this repository (machine-readable; `npm audit` reads it) and by email to every Carcha Seal account. |
| Where the software comes from | npm versions published after 15 October 2026 carry a provenance statement from GitHub Actions; each native file of the hardware module has a build attestation. |

## What stays with you, for your app

- **Due diligence on Seal as a component.** "Manufacturers shall exercise due diligence when integrating components
  sourced from third parties so that those components do not compromise the cybersecurity of the product"
  (Article 13(5)). The material for it: this page, [SECURITY.md](SECURITY.md), the SBOMs on the releases, and the
  checks in the README (`npm audit signatures`, `gh attestation verify`).
- **Seal in your own SBOM.** Your app's SBOM covers at least its top-level dependencies (Annex I Part II(1)); the
  Seal packages are among them.
- **Report what you find in Seal to us.** A manufacturer that finds a vulnerability in a component reports it to the
  component's manufacturer, and shares its fix if it made one (Article 13(6)): security@carchalabs.com.
- **Keep Seal up to date** within a supported version. To hear about security fixes, watch this repository's
  security advisories (Watch → Custom → Security alerts).
- **Your app's own obligations**: its risk assessment, conformity assessment, technical documentation, CE marking,
  information for your users (Annex II), its support period, and Article 14 reporting for your app.

## Information for you (Annex II)

What Annex II asks to accompany Carcha Seal, for you as the vendor who builds it into an app. Points 2, 3, 7 and 9
(vulnerability contact, identification, support period, SBOM) are in [SECURITY.md](SECURITY.md).

### Manufacturer

Carcha Labs, security@carchalabs.com, https://carchalabs.com.
Postal address: to be added here before 11 December 2027.

### Intended purpose, security environment, essential functions, security properties

- **Intended purpose.** Licensing a desktop app built with Electron or Node.js: licence keys, activation on a limited
  number of computers, offline use for a set time, paid features unlocked per licence.
- **Not intended for:** controlling access to systems or data, identifying people, or protecting anything that must
  hold against someone who controls the computer the app runs on.
- **Security environment.** The SDK runs in your app on your customer's computer, which your customer controls. It
  talks to the Carcha Seal server over HTTPS.
- **Essential functions.** Activate, check (online, and offline until the lease's check-in date plus the grace
  period), deactivate, offline activation with files, opening data or code encrypted for a feature.
- **Security properties: what Seal protects.**
  - A lease cannot be forged or changed without your signing key: it is checked with the public keys built into your
    app, and again in the native module.
  - A lease works on the computer it was issued for only.
  - Data you encrypt for a feature opens only with a licence that includes the feature, on that computer, and the
    content key stays in native code when the native module is trusted.
  - The licence key and device data travel over HTTPS only; device data leaves the computer only as hashes.
- **What Seal does not protect against.** Someone who controls the computer can change your app, its memory or the
  SDK's checks, and so run it without a licence with enough effort; Seal makes that harder, not impossible. A
  feature's decrypted data is in memory while your app uses it.

### Foreseeable circumstances that may lead to significant risks

- An outdated SDK: fixes reach your customers only when you ship them (point 8(c)). The server can ask apps to update
  (`sdk_update_recommended`, `sdk_update_required`).
- Pinning only the current public key: a key rotation then breaks installed apps. Pin both keys the console shows
  (`publicKey: [current, next]`).
- Storing the lease unprotected: pass `secureStore` (Electron `safeStorage`), or the licence key in `license.dat` can
  be copied.
- Sending a person's name as the machine name (`activate(key, machineName)`): send a device label, or nothing.
- Shipping your app without Electron's fuses and ASAR integrity: code can then be changed before the SDK runs.
- Sharing a product code with another vendor on the hosted service: device hashes are keyed by product code until
  a later release keys them per vendor.
- Leaking a feature key: replace it in the console and encrypt your data again; the previous key keeps opening older
  data until the next replacement.

### Instructions

#### (a) Secure use, at first use and after

1. Get the server address and both public keys from the console (Settings) and build them into your app.
2. Pass `secureStore` with Electron `safeStorage`.
3. Enable Electron's fuses (`RunAsNode` off, `EnableEmbeddedAsarIntegrityValidation` and `OnlyLoadAppFromAsar` on)
   and sign your app.
4. Ship the native module (`@carchalabs/seal-hwid`) unpacked from the ASAR, so the second check and native decryption
   run.
5. Call `check()` at startup and every few hours; show the notices it returns (`notices`).
6. Keep API keys on your backend only; never in the app.
7. Turn on two-factor sign-in for your console account.

#### (b) How changes can affect the security of data

Options that send or keep less: no machine name; `hardware: false` (no hardware hashes, weaker binding);
`allowFallbackFingerprint` only if the operating system's machine id cannot be read, since the fallback uses the
host name. Details: `PRIVACY.md`.

#### (c) How security updates are installed

The SDK is a library inside your app; it does not update itself and installs nothing. Security fixes are published to
npm as patch versions, marked as security fixes in the changelog and announced in a GitHub security advisory. Update
the dependency, rebuild your app and ship it through your app's update channel. The server's operator can set a
minimum SDK version: older apps first get a notice (`sdk_update_recommended`), then from a set date a refusal
(`sdk_update_required`), so outdated copies stop rather than run with a known flaw. You can do the same for your app's
own version (`app_update_required`).

#### (d) Secure decommissioning and removing user data

- On a computer: `deactivate()` frees the seat and deletes `license.dat`.
- On the server: erase a device or a licence with its data (console, or `POST /api/activations/:id/erase` and
  `POST /api/licenses/:id/erase`); delete your account under Settings. Backups keep data until they rotate out (14
  copies).

#### (e) Turning off automatic security updates

Not applicable: the SDK has no automatic update to turn off, because a library inside your app cannot replace itself
(see (c)). Your app's own updater decides.

Personal data that the Carcha Seal server processes for you is described in the privacy notice:
https://seal.carchalabs.com/privacy/.

Questions: security@carchalabs.com.
