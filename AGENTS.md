# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

CredVault is a Rust workspace with 3 crates (`credvault-core`, `credvault-cli`, `credvault-gui`) plus a React/Vite frontend embedded in the Tauri GUI crate at `crates/credvault-gui/src-ui/`.

### Build order (important)

The frontend **must** be built before `cargo build/test/clippy` will succeed on the full workspace, because Tauri embeds the `src-ui/dist/` directory at compile time.

```
npm ci --prefix crates/credvault-gui/src-ui
npm run build --prefix crates/credvault-gui/src-ui
cargo build --workspace
```

### Key commands

| Task | Command |
|------|---------|
| Lint (format) | `cargo fmt --all -- --check` |
| Lint (clippy) | `cargo clippy --workspace --all-targets -- -D warnings` |
| Unit + integration tests | `cargo test --workspace` |
| CLI integration tests | `bash tests/cli_integration.sh` |
| Build workspace | `cargo build --workspace` |
| Run CLI with debug logs | `RUST_LOG=credvault=debug cargo run -- scan` |

### Caveats

- Rust stable **1.85+** is required (some transitive deps use `edition2024`). The VM's pre-installed 1.83.0 must be updated via `rustup update stable && rustup default stable`.
- Tauri system libraries are required on Linux: `libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev patchelf libssl-dev`.
- The CLI's `test-setup` subcommand creates a mock Chrome profile with 8 test credentials, useful for exercising the full pipeline without real browser data.
- SQLite is bundled via the `rusqlite` `bundled` feature — no system SQLite install is needed.
- No external services, databases, or Docker containers are required.
