# CredVault

Cross-Platform Multi-App Selective Credential Extraction & Provisioning Tool

CredVault discovers credential stores on your machine (browsers, OS keychains, password managers), lets you select a subset of credentials, and packages them into an encrypted, portable bundle.

## Quick Start

```bash
# Build
cargo build --release

# Scan for credential sources
credvault scan

# List all credentials
credvault list

# List credentials filtered by domain
credvault list --domain github.com,aws.amazon.com

# Search credentials
credvault list --search company

# Export to encrypted bundle
credvault export --domain github.com,vercel.com --format credvault --output dev-creds.credvault --label "Dev Credentials"

# Export as .env file
credvault export --domain github.com --format env --output .env

# Export as AI agent config
credvault export --domain github.com,aws.amazon.com --format agent-config --output agent-bundle.json --label "Coding Agent"

# Read a bundle
credvault read dev-creds.credvault
```

## Supported Sources

| Source | Status |
|--------|--------|
| Chrome | ✓ (macOS, Linux) |
| Edge | ✓ (macOS, Linux) |
| Brave | ✓ (macOS, Linux) |
| Vivaldi | ✓ (macOS, Linux) |
| Opera | ✓ (macOS, Linux) |
| Firefox | Planned |
| Safari | Planned |
| macOS Keychain | Planned |
| 1Password | Planned |
| KeePassXC | Planned |

## Export Formats

- **`.credvault`** — Encrypted native format (AES-256-GCM, Argon2id KDF)
- **`.csv`** — Plaintext CSV
- **`.env`** — Environment variable format
- **`agent-config`** — Structured JSON for AI agent consumption

## Architecture

```
credvault/
├── crates/
│   ├── credvault-core/    # Core library: extraction, indexing, bundling
│   │   ├── adapter/       # Source adapters (chromium, firefox, etc.)
│   │   ├── crypto/        # Decryption & bundle encryption
│   │   └── platform/      # OS-specific abstractions
│   └── credvault-cli/     # CLI binary
└── tests/                 # Integration tests
```

## Development

```bash
# Run tests
cargo test

# Run with debug logging
RUST_LOG=credvault=debug cargo run -- scan
```

## License

MIT OR Apache-2.0
