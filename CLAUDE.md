# nostringer-rs Development Guide

## Build Commands
- `cargo build` - Build the project
- `cargo build --release` - Build optimized version
- `cargo build --features wasm` - Build with WASM support
- `wasm-pack build --target web --features wasm` - Build for web browsers

## Test Commands
- `cargo test` - Run all tests
- `cargo test test_name` - Run a specific test
- `cargo test -- --test integration_test` - Run a specific test file
- `cargo test -- --test integration_test test_name` - Run a specific test in a file

## Lint/Format Commands
- `cargo clippy` - Run the Clippy linter
- `cargo fmt` - Format code using rustfmt

## Code Style Guidelines
- **Imports**: Standard library first, external crates grouped by functionality, internal modules last
- **Naming**: Snake_case for functions/variables, CamelCase for types, binary/hex suffixes for API variants
- **Error Handling**: Use `thiserror`, return `Result<T, Error>`, propagate with `?` operator
- **Types**: Strong typing with specific structs, re-exports of common types in lib.rs
- **Documentation**: Doc comments with `///` for public APIs, examples in doc comments
- **Structure**: Integration tests in `tests/`, unit tests within modules, benchmarks in `benches/`
- **Error Messages**: Clear, specific error messages with context about what went wrong

## API Conventions
- Binary API (`sign_binary`) for performance-critical code
- Hex string API (`sign_hex`) for ease of use
- WASM-specific API prefixed with `wasm_`