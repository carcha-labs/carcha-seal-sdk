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

Personal data that the Carcha Seal server processes for you is described in the privacy notice:
https://seal.carchalabs.com/privacy/.

Questions: security@carchalabs.com.
