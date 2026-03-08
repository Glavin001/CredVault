# CredVault

CredVault is a Rust-first selective credential packaging tool.

This repository now supports a safe real-world MVP flow:

1. read credentials from **official user-exported files**
2. normalize and filter them in a unified index
3. select a subset
4. package them into encrypted `.credvault` bundles or plaintext interoperability formats

It also keeps deterministic fixtures for unit and integration tests.

## What is implemented

- Rust workspace with:
  - `crates/credvault-core`: core data model, source registry, filtering, duplicate grouping, bundle encryption, and export rendering
  - `crates/credvault-cli`: CLI for `scan`, `list`, `export`, and `read`
  - `crates/credvault-napi`: minimal Node binding scaffold that exposes JSON-oriented helpers
- Real import adapters for official export files:
  - Chrome / Chromium password CSV export
  - Bitwarden JSON export
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
  - import flows for official export files
  - CLI bundle export and read flows

## Important security boundary

This repo supports **official exported files** as the real ingestion path.

It does **not** implement live extraction from browsers, OS keychains, or password managers.

That boundary is intentional:

- users remain in control of what they export
- the tool avoids bypassing browser and password-manager protections
- the ingest path is testable in CI and manually reproducible
- the bundle/index architecture is still reusable for future safe integrations

## Repository layout

```text
credvault/
├── Cargo.toml
├── fixtures/
│   ├── chrome-default.fixture.json
│   └── chrome-work.fixture.json
│   └── exports/
│       ├── chrome-passwords.csv
│       └── bitwarden-export.json
├── crates/
│   ├── credvault-core/
│   ├── credvault-cli/
│   └── credvault-napi/
└── README.md
```

## CLI usage

### Scan available sources

```bash
cargo run -p credvault-cli -- \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  --bitwarden-json fixtures/exports/bitwarden-export.json \
  scan
```

### List credentials

```bash
cargo run -p credvault-cli -- \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  --bitwarden-json fixtures/exports/bitwarden-export.json \
  list

cargo run -p credvault-cli -- \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  --bitwarden-json fixtures/exports/bitwarden-export.json \
  list --domain github.com

cargo run -p credvault-cli -- \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  list --type password --search aws
```

### Export a native encrypted bundle

```bash
cargo run -p credvault-cli -- \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  export \
  --domain github.com \
  --format credvault \
  --password demo-password \
  --output demo.credvault
```

### Read a bundle

```bash
cargo run -p credvault-cli -- read demo.credvault --password demo-password
```

### Export agent config JSON

```bash
cargo run -p credvault-cli -- \
  --bitwarden-json fixtures/exports/bitwarden-export.json \
  export --domain platform.openai.com \
  --format agent-config
```

### Fixture-only test mode

```bash
cargo run -p credvault-cli -- --fixture-dir fixtures scan
```

## Testing

Run the current automated suite:

```bash
cargo test
```

## Manual verification performed in this repo

These flows were executed successfully during implementation:

```bash
cargo test
cargo build --release

target/release/credvault \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  --bitwarden-json fixtures/exports/bitwarden-export.json \
  scan

target/release/credvault \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  --bitwarden-json fixtures/exports/bitwarden-export.json \
  list --domain github.com

target/release/credvault \
  --chrome-csv fixtures/exports/chrome-passwords.csv \
  export --domain github.com \
  --format credvault \
  --password demo-password \
  --output /tmp/demo.credvault

target/release/credvault read /tmp/demo.credvault --password demo-password
```

## Next steps

Suggested next implementation steps after this foundation:

1. expand importer coverage to more official export formats (1Password CSV, KeePass CSV/XML, Firefox CSV if available)
2. add a local encrypted workspace file for saved selection presets and audit logs
3. turn the Node binding scaffold into typed async APIs on a newer Rust toolchain
4. add desktop UI on top of the now-stable import/list/select/export flow
