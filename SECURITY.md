# Security policy

Carcha Labs makes Carcha Seal: the SDK packages in this repository and the Carcha Seal server they talk to. We want
to hear about any vulnerability in them, and we handle reports by coordinated disclosure.

## Reporting a vulnerability

Email **security@carchalabs.com**, or report it privately on GitHub (this repository's Security tab → Report a
vulnerability), with:

- the product and version (package and version, or `seal.carchalabs.com`),
- what an attacker can do, and the steps or code to reproduce it,
- whether you know of it being exploited,
- how you would like to be credited, if at all.

Please do not open a public issue or pull request for a vulnerability, and do not test against other vendors'
accounts or data on `seal.carchalabs.com`: use your own account, or a server you run yourself.

## What happens next

| Step | Within |
|---|---|
| We acknowledge your report | 3 business days |
| We give you our first assessment (confirmed or not, severity, next steps) | 10 business days |
| Coordinated disclosure | 90 days after the report, or sooner once a fix is released |

We keep you informed until it is fixed, agree the disclosure date with you, and credit you in the advisory unless
you prefer not to be named. If a vulnerability is being actively exploited, we may publish a fix or a warning
sooner, and we report it as the EU Cyber Resilience Act (Regulation (EU) 2024/2847, Article 14) requires.

## Scope

In scope:

- `@carchalabs/seal-core`, `@carchalabs/seal-electron`, `@carchalabs/seal-quickstart`, `@carchalabs/seal-hwid` and
  its platform packages, and the Rust crates `seal_hwid` and `seal_lease`;
- the Carcha Seal server at `https://seal.carchalabs.com` (licence API, console, payment connections).

Out of scope: denial of service by traffic volume, reports from automated scanners without a demonstrated impact,
missing security headers without an exploit, and social engineering.

## Supported versions and support period

Security fixes go into the latest release of a supported version. Upgrade to it to receive them.

- **From 1.0.0 on:** each major version of a package (1.x, 2.x, ...) gets security fixes for at least **five years**
  after its first release (x.0.0). They go into the latest release of that major, which needs no code changes to
  upgrade to. The table below gives the month and year each major's support ends, from its first release on.
- **0.x versions** (all packages today) are pre-1.0: a 0.x minor version can contain breaking changes, and security
  fixes go only into the latest release.
- For the support period of a major, the Carcha Seal server at `seal.carchalabs.com` keeps the API that the major
  calls.
- Every release stays on npm for at least ten years; none is unpublished.

| Package | Version | Security fixes until |
|---|---|---|
| All `@carchalabs/seal-*` packages | 0.x | the latest release only |

## Software bill of materials

Each GitHub release, from November 2026 on, has a CycloneDX SBOM (JSON) for each package at its version in that
release: `<package>-<version>.cdx.json`, for example `seal-electron-0.5.0.cdx.json`. For a platform package of
`@carchalabs/seal-hwid`, the SBOM lists the Rust crates compiled into its native file.

## Safe harbour

We will not take legal action against research done in good faith within this policy: research that avoids
privacy violations, data destruction and service disruption, and that gives us reasonable time to fix the issue
before it is made public.
