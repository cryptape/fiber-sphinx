# AGENTS.md - AI Coding Agent Guidelines

Guidelines for AI coding agents working on the fiber-sphinx codebase.

## Project Overview

fiber-sphinx is a Rust implementation of the Sphinx mix network protocol for Fiber.
It implements onion message encryption/decryption for anonymous message routing.

## Build, Test, and Lint Commands

### Prerequisites
- Rust toolchain 1.76.0 (specified in `rust-toolchain.toml`)
- Components: rustfmt, clippy

### Build
```bash
cargo build                          # Build the project
RUSTFLAGS="-Dwarnings" cargo build   # Build with warnings as errors (CI mode)
```

### Test
```bash
cargo test                                         # Run all tests
cargo test test_onion_packet_from_bytes            # Run a specific test by name
cargo test test_derive                             # Run tests matching a pattern
cargo test test_create_onion_packet -- --nocapture # Run with output visible
```

### Lint and Format
```bash
cargo fmt                              # Format code (required before committing)
cargo fmt --check                      # Check formatting without changes
cargo clippy                           # Run clippy linter
RUSTFLAGS="-Dwarnings" cargo clippy    # Clippy with warnings as errors (CI mode)
```

### Documentation
```bash
cargo doc --open    # Generate and open documentation
```

## Code Style Guidelines

### Rust Edition and Version
- **Edition**: 2021
- **Minimum Rust Version**: 1.76.0

### Formatting
- Always run `cargo fmt` before committing
- Use rustfmt defaults (no custom configuration)

### Imports
- Group: 1) Standard library 2) External crates (alphabetically) 3) Internal modules
- Use specific imports, not glob imports
- Nested imports are acceptable: `use secp256k1::{PublicKey, SecretKey}`

### Naming Conventions
- **Types/Structs/Enums**: PascalCase (`OnionPacket`, `SphinxError`)
- **Functions/Methods**: snake_case (`derive_key`, `peel`)
- **Constants**: SCREAMING_SNAKE_CASE (`HMAC_KEY_RHO`, `CHACHA_NONCE`)
- **Variables**: snake_case (`session_key`, `hops_path`)
- **Generic Type Parameters**: Single uppercase letters (`C`, `F`, `T`)

### Type Annotations
- Use explicit types for public APIs
- Use `[u8; 32]` for fixed-size byte arrays (keys, HMACs)
- Use `Vec<u8>` for variable-length byte data

### Error Handling
- Use `thiserror` for error definitions
- Define errors with `#[derive(Error, Debug, Eq, PartialEq)]`
- Return `Result<T, SphinxError>` for fallible operations
- Use `Option<T>` for values that may not exist

Example:
```rust
#[derive(Error, Debug, Eq, PartialEq)]
pub enum SphinxError {
    #[error("The hops path does not match the hops data length")]
    HopsLenMismatch,
}
```

### Documentation
- Use `//!` for module-level documentation
- Use `///` for function/struct documentation
- Include code examples in doc comments
- Document public APIs thoroughly

### Function Patterns
- Use `&self` for methods that don't consume the struct
- Use `self` for consuming transforms (`into_bytes`, `peel`)
- Use generic constraints: `C: Signing` or `C: Verification`

### Testing
- Tests in `src/tests.rs` module
- Naming: `test_<function_name>` or `test_<feature_description>`
- Use `hex-conservative` for hex encoding/decoding
- Test both success and error cases

### Cryptographic Patterns
- Use `Secp256k1::new()` for secp256k1 context
- Use `SharedSecret::new()` for ECDH operations
- Use ChaCha20 with 12-byte zero nonce: `[0u8; 12]`
- Use HMAC-SHA256 for key derivation and MAC computation

### Memory and Safety
- Use `expect()` with descriptive messages for infallible operations
- Avoid `unwrap()` in library code; use `?` or proper error handling
- Use `#[inline]` for small, frequently-called functions

## Project Structure

```
fiber-sphinx/
├── Cargo.toml          # Project manifest and dependencies
├── rust-toolchain.toml # Rust version specification
├── src/
│   ├── lib.rs          # Main library code and public API
│   └── tests.rs        # Test module
├── docs/
│   ├── spec.md         # Protocol specification
│   ├── development.md  # Development guide
│   └── CONTRIBUTING.md # Contribution guidelines
└── .github/workflows/
    ├── ci.yml          # CI workflow (build, test, clippy)
    ├── cov.yml         # Coverage workflow
    └── deploy.yml      # Deploy to crates.io on tag push
```

## CI Requirements

The CI runs on Rust 1.76.0, stable, beta, and nightly. All must pass:
- `cargo build` - Compilation with no errors
- `cargo test` - All tests pass
- `cargo clippy` - No warnings (with `-Dwarnings`)

## Releasing

To publish a new version to crates.io:

1. Update the version in `Cargo.toml`
2. Commit the version bump
3. Create and push a tag: `git tag v<version> && git push origin v<version>`
4. The deploy workflow will automatically publish to crates.io

**Setup:** Uses crates.io Trusted Publishers (no API token required). Configure the trusted
publisher at https://crates.io/crates/fiber-sphinx/settings with:
- Repository: `cryptape/fiber-sphinx`
- Workflow: `deploy.yml`
- Environment: `crates.io`

## Contributing Workflow

1. Create branch from `develop`
2. Add tests for new code
3. Update documentation for API changes
4. Ensure tests pass and code lints
5. Run `cargo fmt` before committing

## Dependencies

### Runtime
- `secp256k1` (0.28.0) - Elliptic curve cryptography
- `sha2` (0.10.8) - SHA-256 hashing
- `hmac` (0.12.1) - HMAC implementation
- `chacha20` (0.9.1) - ChaCha20 stream cipher
- `thiserror` (1.0) - Error derive macro

### Dev
- `hex-conservative` (0.2.1) - Hex encoding/decoding for tests
