# Contributing

Thank you for improving `fbm`.

## Development

```sh
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
node --check src/fbm_js_bridge/bridge.js
```

Use test fixtures with synthetic IDs and synthetic cookie values only. Do not add real exports, databases, appState files, or browser profile data.

## Pull requests

A good PR includes:

- a clear problem statement
- tests for behavior changes
- docs updates for user-facing changes
- no private data in commits, fixtures, screenshots, or logs
- attribution for any borrowed design or code

## Release checklist

1. `cargo fmt`
2. `cargo test`
3. `cargo clippy --all-targets -- -D warnings`
4. `node --check src/fbm_js_bridge/bridge.js`
5. secret scan with common token/path patterns
6. update `CHANGELOG.md`
7. tag `vX.Y.Z`
