# CredVault

CredVault is a Rust-first foundation for a selective credential packaging tool. This repository now includes the core workspace, encrypted bundle format, a CLI, and deterministic fixture-backed browser examples for automated testing.

## What is implemented

- Rust workspace with:
  - `crates/credvault-core`: core data model, source registry, filtering, duplicate grouping, bundle encryption, and export rendering
  - `crates/credvault-cli`: CLI for `scan`, `list`, `export`, and `read`
  - `crates/credvault-napi`: minimal Node binding scaffold that exposes JSON-oriented helpers
- Native `.credvault` encrypted bundle format using Argon2id + AES-256-GCM
- Plaintext export renderers for:
  - CSV
  - `.env`
  - agent-config JSON
- Fixture-backed "Chrome-like" source adapters for:
  - a default Chrome profile
  - a work Chrome profile
- Automated tests covering:
  - source discovery
  - filtering and duplicate grouping
  - encrypted bundle round-trips
  - CLI bundle export and read flows

## Important boundary for this foundation

This repo currently uses **fixture-backed adapters only**. It does **not** include real browser, keychain, or password manager extraction against live user stores.

That is intentional for this first foundation pass:

- the indexing and bundle pipeline can be developed and tested safely
- the public core API stays stable before platform-specific integration work
- automated CI can validate deterministic fixtures without depending on macOS keychain prompts or browser lock behavior

When we add macOS-specific adapters later, they should be validated on your machine using distribution builds, since that environment can exercise native prompts and real browser profile layouts.

## Repository layout

```text
credvault/
├── Cargo.toml
├── fixtures/
│   ├── chrome-default.fixture.json
│   └── chrome-work.fixture.json
├── crates/
│   ├── credvault-core/
│   ├── credvault-cli/
│   └── credvault-napi/
└── README.md
```

## CLI usage

### Scan available sources

```bash
cargo run -p credvault-cli -- --fixtures fixtures scan
```

### List credentials

```bash
cargo run -p credvault-cli -- --fixtures fixtures list
cargo run -p credvault-cli -- --fixtures fixtures list --domain github.com
cargo run -p credvault-cli -- --fixtures fixtures list --type password --search aws
```

### Export a native encrypted bundle

```bash
cargo run -p credvault-cli -- --fixtures fixtures export \
  --id chrome-default-fixture:login:github-glavin \
  --format credvault \
  --password demo-password \
  --output demo.credvault
```

### Read a bundle

```bash
cargo run -p credvault-cli -- --fixtures fixtures read demo.credvault --password demo-password
```

### Export agent config JSON

```bash
cargo run -p credvault-cli -- --fixtures fixtures export \
  --domain github.com \
  --format agent-config
```

## Testing

Run the current automated suite:

```bash
cargo test
```

## Next steps

Suggested next implementation steps after this foundation:

1. add a platform-gated macOS adapter crate/module that reads copied test profile directories rather than live stores first
2. build a signed macOS release artifact for your local validation
3. add snapshot fixtures for real-world schema quirks discovered during your macOS testing
4. expand the Node binding from JSON helpers into typed async APIs
