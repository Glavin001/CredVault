# CredVault Roadmap

## Completed

### Core Features
- **Chromium adapter** — Chromium, Chrome/Edge channels, Brave, Vivaldi, Opera, Arc (passwords + credit cards)
- **Firefox adapter** — Full NSS/PKCS#11 decryption from logins.json + key4.db
- **Windows DPAPI** — CryptUnprotectData for Chromium key extraction
- **macOS Keychain** — `security find-generic-password` integration
- **Linux libsecret** — `secret-tool` + "peanuts" fallback

### Crypto
- AES-128-CBC (Chromium macOS/Linux)
- AES-256-GCM (Chromium Windows)
- PBES2 + PBKDF2-HMAC-SHA256 + AES-256-CBC (Firefox modern)
- PBE-SHA1-3DES (Firefox legacy)
- AES-256-GCM + Argon2id (CredVault bundle encryption)
- ASN.1 DER parser for NSS structures

### Export Formats
- **CredVault** — Encrypted bundle (AES-256-GCM + Argon2id)
- **CSV** — Plaintext spreadsheet
- **ENV** — `.env` file format
- **Agent Config** — JSON for AI agent provisioning

### CLI Commands
- `scan` — Detect available credential sources
- `list` — Filter by domain/source/type/search with deduplication
- `export` — Extract + bundle with format/expiry options
- `read` — Decrypt and display bundles
- `test-setup` — Create mock profiles for testing

### Safety Hardening
- Read-only SQLite connections (`SQLITE_OPEN_READ_ONLY`)
- `NamedTempFile` for crash-safe temp cleanup
- Never modifies source files (verified by integration test)

### Infrastructure
- GitHub Actions CI/CD: fmt, clippy, test (Linux/macOS/Windows), release artifacts
- Comprehensive test suite (unit + integration), including safety verification
- Zero TODOs/FIXMEs/stubs in codebase

---

## Future Features

### Additional Sources
- OS Keychain adapter (macOS Keychain items, Windows Credential Manager, Linux Secret Service)
- 1Password adapter
- KeePassXC adapter
- Bitwarden adapter
- LastPass adapter

### Additional Credential Types
- Cookies extraction
- API Keys extraction
- Certificates extraction
- Session Tokens extraction

### Potential Enhancements
- Firefox master password support (currently only empty password)
- Safari/WebKit browser support
- Chromium cookies extraction
- Bookmark/history extraction
- Windows Arc path support (MSIX package path differs from standard Chromium)
- Selective profile export (currently exports all profiles per source)
- Bundle TTL enforcement (expiry is stored but not enforced on read)
- Remote bundle transfer (e.g., via QR code, short-lived URL)
