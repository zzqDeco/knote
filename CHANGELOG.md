# Changelog

This project follows semantic versioning. GitHub Releases remains the source of
truth for published tags and binary assets.

## [0.3.0] - 2026-07-16

### Added

- Opt-in real permissioned CLI composition with strict startup validation for
  the selected artifact bundle, OpenFGA identity, and operator provider.
- Catalog Claim tuple reconciliation, revision tracking, and revocation-safe
  authorization lifecycle handling.
- Protected tool, assistant, session, diff, and derived-artifact surfaces.
- Content-free operational telemetry with a closed schema and sink-failure
  isolation.
- Deterministic built-binary PTY acceptance for allow, deny, empty result,
  resume, revocation, telemetry, provider, and authorization-backend cases.

### Changed

- Real permissioned requests fail closed without falling back to legacy KAG
  query or explain paths.
- Release verification now runs the same built binary used for version-stamping
  checks through the permissioned acceptance suite.
- English and Chinese operator documentation now describe the same opt-in
  runtime and no-disclosure troubleshooting boundary.

### Security

- Evidence is loaded only from the verified selected bundle and is authorized
  before ranking, traversal, generation, citation, cache reuse, and replay.
- Claim traversal validates every participating resource and tuple against the
  current authorization revision.
- Telemetry excludes content, identifiers, paths, prompts, error text,
  endpoints, and secrets.

### Known limitations

- Permissioned mode is opt-in rather than default-on.
- `/eval` remains unavailable because the legacy explain dependency is outside
  the authorized evidence boundary.
- The credential-free release gates supplement, but do not replace, operator
  validation against disposable OpenFGA/OpenSPG and local Eino environments.

## [0.2.1] - 2026-07-15

- Included KAG adapters in Windows release archives.
- Hardened verified-tag release publication and asset checks.

[0.3.0]: https://github.com/zzqDeco/knote/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/zzqDeco/knote/releases/tag/v0.2.1
