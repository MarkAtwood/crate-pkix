# Changelog

All notable changes to `pkix-identity` are documented here. The crate
follows [Keep a Changelog](https://keepachangelog.com/) headings and
[Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-05-11

### Added

- Initial scaffold (PKIX-fmtv.21). Workspace member; `no_std` (matches
  `pkix-path` discipline); `forbid(unsafe_code)`.
- Public API surface:
  - `ServerName<'a>` with `dns_name` / `ip_address` constructors.
  - `MailboxName<'a>` with `parse` constructor.
  - `IdentityError` enum (`#[non_exhaustive]`).
  - Free functions `verify_dns_name` and `verify_mailbox`.
- All public entry points return `IdentityError::NotYetImplemented`.
  Bodies fill in via PKIX-fmtv.11 (`verify_dns_name`) and
  PKIX-fmtv.12 (`verify_mailbox`).
- Only dep at this stage is `x509-cert` (for the `Certificate`
  signature type). `der` and `idna` are added in PKIX-fmtv.11 / .12
  alongside the bodies that use them.
