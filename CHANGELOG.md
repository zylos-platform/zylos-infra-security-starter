# Changelog

All notable changes to `zylos-infra-security-starter` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- JWT validation core: `AudienceValidator`, `UnknownKidRefreshingJwtDecoder`,
  `UnknownKidRefreshingReactiveJwtDecoder`, `ZylosSecurityProperties`,
  servlet/reactive/common auto-configurations.
- IDE support metadata for `zylos.security.*` configuration keys.
- ADR 0002: JWT validation chain design.

## Initial release

### Added

- Initial repo scaffolding.
