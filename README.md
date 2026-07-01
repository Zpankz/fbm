# fbm

`fbm` is a local-first command-line archive for Facebook Messenger conversations. It uses a small Node.js bridge to an existing [`ws3-fca`](https://github.com/nethgraves/ws3-fca) checkout for Messenger access, then stores normalized data in SQLite/libSQL for search, export, and structured querying.

> Not affiliated with Meta, Facebook, Messenger, or ws3-fca. Use only with accounts and data you are authorized to access. Respect platform terms and local law.

## Features

- Browser-cookie authentication from local Firefox, Chrome, Brave, Edge, Comet, and Chromium profiles.
- Manual appState fallback.
- Exhaustive, resumable sync across inbox, archived, other/request, pending, and spam folders.
- Full-history pagination with completion tracking.
- SQLite/libSQL storage with raw JSON retention and FTS5 search.
- Structured taxonomy layer for hierarchical and orthogonal metadata queries.
- JSON and Markdown export.
- Explicit send/listen commands for interactive Messenger workflows.

## Install

Prerequisites:

- Rust stable
- Node.js 20+
- A local `ws3-fca` checkout with dependencies installed

```sh
# 1. Install fbm from source.
git clone https://github.com/Zpankz/fbm.git
cd fbm
cargo install --path . --locked

# 2. Prepare ws3-fca separately.
git clone https://github.com/nethgraves/ws3-fca.git ../ws3-fca
cd ../ws3-fca
npm install
cd ../fbm

# 3. Initialize fbm using a logged-in local browser profile.
fbm init --fca-dir ../ws3-fca --from-browser --browser auto

# 4. Verify without printing cookies.
fbm status --json
fbm me --json
```

Browser-specific examples:

```sh
fbm init --fca-dir ../ws3-fca --from-browser --browser firefox
fbm init --fca-dir ../ws3-fca --from-browser --browser chrome --browser-profile Default
fbm init --fca-dir ../ws3-fca --from-browser --browser comet --browser-profile Default
```

Manual appState fallback is supported, but browser import is preferred because it avoids copying cookie values by hand:

```sh
fbm init --fca-dir ../ws3-fca --appstate /path/to/appstate.json
```

## Common commands

```sh
# Sync every reachable conversation plus full history. Reruns resume.
fbm sync --all --threads 100 --messages 500

# Limit work per run for cautious incremental extraction.
fbm sync --all --threads 100 --messages 500 --history-threads 25

# List conversations.
fbm threads --limit 50
fbm threads --query "project"

# Show messages for one thread.
fbm messages THREAD_ID --limit 100
fbm messages THREAD_ID --newest

# Full-text search.
fbm search '"project deadline"'
fbm search dinner --thread-id THREAD_ID

# Rebuild structured categories for efficient programmatic queries.
fbm categorize --json
fbm categorize --axis message.attachment --limit 20

# Export.
fbm export --thread-id THREAD_ID --format markdown --output thread.md
fbm export --format json --output messenger-export.json
```

## Storage and privacy

Default local files live under the platform application data directory, for example on macOS:

```text
~/Library/Application Support/dev.fbm.fbm/
```

That directory can contain private databases and appState caches. It is intentionally ignored by this repository. Do not commit:

- `appstate*.json`
- browser appState caches
- `*.db`, `*.sqlite`, `*.db-wal`, `*.db-shm`
- `.env` files
- exported conversations

See [`docs/privacy.md`](docs/privacy.md) before publishing logs, screenshots, issues, or exported data.

## Structured query layer

`fbm categorize` builds these local-only derived tables:

- `thread_dimensions`, `message_dimensions`: denormalized orthogonal dimensions.
- `thread_categories`, `message_categories`: one row per facet assignment.
- `category_nodes`: hierarchical taxonomy nodes with `axis`, `path`, `parent_path`, and `depth`.
- `v_thread_structured`, `v_message_structured`, `v_category_counts`: query-ready views.

Example:

```sql
SELECT path, item_count
FROM v_category_counts
WHERE scope = 'message' AND axis = 'message.attachment'
ORDER BY item_count DESC;
```

More examples: [`docs/structured-queries.md`](docs/structured-queries.md).

## Agentic installation

This repo includes project-local agent instructions and a reusable skill:

- [`AGENTS.md`](AGENTS.md)
- [`.agents/skills/fbm/SKILL.md`](.agents/skills/fbm/SKILL.md)

Agents should use those files to install, operate, audit, and extend `fbm` without exposing private cookies, databases, message bodies, or account identifiers.

## Attribution

`fbm` depends on [`ws3-fca`](https://github.com/nethgraves/ws3-fca) for Messenger API access. See [`ATTRIBUTION.md`](ATTRIBUTION.md). This repository does not vendor ws3-fca source.

## Dependency policy

`fbm` is stdlib-first. Convenience crates for CLI parsing, table formatting, timestamp formatting, project directories, error context, logging, and test temp directories were intentionally replaced with local stdlib helpers before the public release. Retained direct dependencies are limited to storage/runtime, structured serialization, and Chromium cookie cryptography where replacing them would materially hurt correctness or efficiency. See [`docs/dependencies.md`](docs/dependencies.md).

## Stability

The first stable source release is `v0.1.0`. The data schema is migration-based and intended to preserve existing local archives across upgrades, but Messenger/API behavior can change upstream.

## License

MIT, see [`LICENSE`](LICENSE).
