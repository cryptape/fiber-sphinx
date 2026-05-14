# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-05-14

### Added
- `OnionPacket::from_bytes_with_packet_data_len` to validate the expected packet data length while parsing bytes
- `SphinxError::PacketDataLenMismatch` for bytes that do not match the expected packet data length
- `SphinxError::InvalidBlindingFactor` for blinding factors that reduce to zero modulo the secp256k1 curve order

### Changed
- `OnionSharedSecretIter` now returns `Result<[u8; 32], SphinxError>` to report invalid blinding factors

### Fixed
- Reduced SHA256 blinding factors modulo the secp256k1 curve order before applying key tweaks

### Deprecated
- `OnionPacket::from_bytes`; use `OnionPacket::from_bytes_with_packet_data_len` when the packet data length is known

## [2.3.0] - 2026-02-02

### Added
- Deploy workflow for automatic crates.io publishing on tag push
- CHANGELOG.md documenting all releases

### Changed
- Refactored code according to clippy warnings
- Added clippy to CI pipeline
- Added coverage workflow
- Moved tests into a separate file

### Documentation
- Added test vectors in spec

## [2.2.0] - 2024-12-12

### Added
- `extract_public_key_from_slice` function to extract public key from bytes

## [2.1.0] - 2024-11-29

### Added
- New interface to concat and split error packets

## [2.0.0] - 2024-11-28

### Changed
- **Breaking:** Error parsing now returns hops index

## [1.0.1] - 2024-09-29

### Fixed
- Outdated docs for error packet example

### Changed
- Enabled CI for merge group

### Documentation
- Fixed spec grammar errors

## [1.0.0] - 2024-09-26

### Added
- `OnionPacket::from_bytes` to construct onion packet from bytes

## [0.2.0] - 2024-09-25

### Added
- Support for returning error packets
- Fiber Sphinx protocol specification

### Documentation
- Documented returned value of `peel`
- Added spec on error packet
- Linked code to the spec

## [0.1.1] - 2024-09-23

### Fixed
- Crate publishing configuration

## [0.1.0] - 2024-09-23

### Added
- Initial implementation of Sphinx mix network protocol
- Onion packet creation with arbitrary packet data length
- Onion packet peeling (decryption for next hop)
- HMAC verification for packet integrity
- Ephemeral key derivation for each hop
- Hop shared secret derivation
- Filler generation for packet construction

[Unreleased]: https://github.com/nervosnetwork/fiber-sphinx/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/nervosnetwork/fiber-sphinx/compare/v2.3.0...v3.0.0
[2.3.0]: https://github.com/nervosnetwork/fiber-sphinx/compare/v2.2.0...v2.3.0
[2.2.0]: https://github.com/nervosnetwork/fiber-sphinx/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/nervosnetwork/fiber-sphinx/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/nervosnetwork/fiber-sphinx/compare/v1.0.1...v2.0.0
[1.0.1]: https://github.com/nervosnetwork/fiber-sphinx/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/nervosnetwork/fiber-sphinx/compare/v0.2.0...v1.0.0
[0.2.0]: https://github.com/nervosnetwork/fiber-sphinx/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/nervosnetwork/fiber-sphinx/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nervosnetwork/fiber-sphinx/releases/tag/v0.1.0
