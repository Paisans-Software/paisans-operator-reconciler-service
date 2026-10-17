# Changelog

All notable changes to this project are documented here, in the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## [Unreleased]

### Added

- The image carries /THIRD_PARTY_NOTICES: the licenses and notices of the Go standard library and every module the binary links.

### Changed

- A pass fails while only one operator is declared, so the operators heartbeat alerts until a second is added.

## [0.3.0] - 2026-10-14

### Added

- The operator reconciler, from the paisans toolkit: it reads Pocket ID and, when configured, the DNS provider's account, writes nothing, and serves /healthz and /livez on port 1412.
- Published as ghcr.io/paisans-software/operator-reconciler from a vX.Y.Z tag on this repository.
