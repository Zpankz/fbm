---
name: fbm
description: Install, operate, audit, and extend the fbm Messenger archive CLI while preserving privacy. Use when working on fbm commands, sync, browser-cookie auth, storage, structured categorization, releases, or diagnostics.
---

# fbm skill

## Privacy contract

Never expose real:

- appState JSON or browser cookie values
- SQLite/libSQL databases, WAL, or SHM files
- message bodies or attachments
- participant names, thread names, user IDs, thread IDs, message IDs
- Turso/libSQL auth tokens

Prefer aggregate counts, category paths, schema metadata, and synthetic fixtures.

## Install workflow

```sh
git clone https://github.com/Zpankz/fbm.git
cd fbm
cargo install --path . --locked
git clone https://github.com/nethgraves/ws3-fca.git ../ws3-fca
(cd ../ws3-fca && npm install)
fbm init --fca-dir ../ws3-fca --from-browser --browser auto
fbm status --json
```

## Development workflow

```sh
cargo fmt
cargo test
cargo clippy --all-targets -- -D warnings
node --check src/fbm_js_bridge/bridge.js
```

## Structured query workflow

After sync:

```sh
fbm categorize --json
fbm categorize --axis message.attachment --limit 20
```

Use `thread_dimensions`, `message_dimensions`, `thread_categories`, `message_categories`, `category_nodes`, and `v_category_counts` for programmatic extraction.

## Release safety checklist

- No DB/appState/export files tracked.
- No real identifiers or message content in docs/tests.
- README, privacy, security, attribution, changelog updated.
- CI green.
- Tag semver release.
