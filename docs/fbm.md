# fbm: Facebook Messenger CLI

`fbm` is a local-first, Rust-native CLI for retrieving, storing, searching, exporting, listening to, and sending Facebook Messenger conversations.

Architecture:

- **Messenger API**: uses the cloned `ws3-fca` checkout through a small Node.js JSON bridge.
- **Storage**: uses `libsql`, the Rust client for SQLite/Turso. Defaults to a local SQLite-compatible `.db`; can target remote Turso with `--turso-url` and `--turso-auth-token`.
- **Search**: stores normalized conversations plus raw JSON, and maintains an FTS5 index for message search.

## Safety

- `fbm` never prints appstate cookie values.
- Preferred auth is local browser-cookie import from an already logged-in browser profile. Cookies are copied from the local browser DB, converted to `ws3-fca` appState, and cached in the fbm data directory.
- `fbm status --json` redacts the Turso token.
- Retrieval is bounded by default. Use larger `--threads`, `--messages`, `--full`, and `--max-pages` for archival syncs.
- Sending is explicit via `fbm send <thread-id> <body>`.

## Setup

```sh
npm install
cargo build --release
./target/release/fbm init --from-browser --browser auto
```

`--from-browser` scans local Firefox, Chrome, Brave, Edge, Comet, and Chromium profiles for `facebook.com` / `messenger.com` cookies, verifies required `c_user` and `xs` cookies, and writes a local appState cache for `ws3-fca`.

Browser-specific examples:

```sh
./target/release/fbm init --from-browser --browser firefox
./target/release/fbm init --from-browser --browser chrome --browser-profile Default
./target/release/fbm init --from-browser --browser brave --browser-profile "Profile 1"
./target/release/fbm init --from-browser --browser comet --browser-profile Default
```

Manual appState JSON is still supported as a fallback:

```sh
./target/release/fbm init --appstate /path/to/appstate.json
```

Optional Turso remote:

```sh
./target/release/fbm init \
  --from-browser --browser auto \
  --turso-url libsql://your-db-org.turso.io \
  --turso-auth-token "$LIBSQL_AUTH_TOKEN"
```

## Commands

```sh
# Verify config and database counts
fbm status

# Check authenticated Facebook account without exposing cookies
fbm me --json

# Sync every reachable inbox, archived, other/request, pending, and spam conversation plus full history
fbm sync --all --threads 100 --messages 500

# Sync the 50 newest inbox threads and 200 messages per thread
fbm sync

# Deep sync, bounded by pages per thread
fbm sync --threads 500 --messages 500 --full --max-pages 100

# Exhaustive sync with optional safety caps; reruns resume older history from stored earliest messages
fbm sync --all --threads 100 --messages 500 --max-thread-pages 0
fbm sync --all --threads 100 --messages 500 --history-threads 25

# Sync a single conversation
fbm sync --thread-id 123456789 --messages 1000 --full

# List stored conversations
fbm threads --limit 50
fbm threads --query "Alice"

# Show messages
fbm messages 123456789 --limit 100
fbm messages 123456789 --newest

# Search stored messages
fbm search '"project deadline"'
fbm search dinner --thread-id 123456789

# Rebuild hierarchical + orthogonal structured categories for query/extraction
fbm categorize --json
fbm categorize --axis message.attachment --limit 20

# Send a message and store sent result
fbm send 123456789 "hello from fbm"

# Real-time listener, storing incoming message events
fbm listen
fbm listen --limit 10

# Export
fbm export --thread-id 123456789 --format markdown --output thread.md
fbm export --format json --output messenger-export.json
```

## Config

Default config path is platform-specific, for example macOS:

```text
~/Library/Application Support/dev.fbm.fbm/config.toml
```

Override with `--config` or `FBM_CONFIG`.

```toml
fca_dir = "/path/to/ws3-fca"
appstate = "/path/to/manual-appstate.json" # optional fallback when auth.method = "app-state"

[auth]
method = "browser"          # "browser" or "app-state"
browser = "auto"            # auto, firefox, chrome, brave, edge, comet, chromium
browser_profile = "Default" # optional
browser_appstate_cache = "/path/to/browser-appstate.json" # optional

[database]
path = "/path/to/fbm.db"
remote_url = "libsql://..." # optional
auth_token = "..."         # optional, redacted in status output
```

## Schema overview

- `threads`: normalized thread metadata plus raw `ws3-fca` JSON.
- `messages`: normalized messages plus raw JSON.
- `message_fts`: FTS5 index for `sender_id` and `body`.
- `sync_runs`: reserved for future sync auditing.
- `thread_history_state`: resumable full-history completion markers.
- `thread_dimensions` / `message_dimensions`: denormalized orthogonal dimensions for efficient SQL filters.
- `thread_categories` / `message_categories`: one row per derived facet assignment.
- `category_nodes`: hierarchical taxonomy nodes with `axis`, slash-delimited `path`, `parent_path`, and `depth`.
- `v_thread_structured` / `v_message_structured`: query-ready structured metadata views.
- `v_category_counts`: safe aggregate counts by item scope, axis, and path.

## Structured categorization

Run `fbm categorize` after a large sync to rebuild the derived taxonomy layer. It does not read browser cookies or contact Facebook; it only derives metadata from the local database and does not print message bodies.

The schema separates **orthogonal axes** so programmatic queries can combine filters without string parsing:

- Thread axes: `source.folder`, `thread.archive`, `thread.kind`, `thread.history`, `participants.size`, `volume.messages`, `time.activity`.
- Message axes: `message.kind`, `message.text`, `message.attachment`, `message.reactions`, `message.mentions`, `sender.scope`, `volume.body`, `time.sent`.

Time paths are hierarchical. For example `time.sent = time/2024/03/09/16` also has taxonomy ancestors `time`, `time/2024`, `time/2024/03`, and `time/2024/03/09` in `category_nodes`.

Example SQL:

```sql
-- Count message attachment classes without exposing content.
SELECT path, item_count
FROM v_category_counts
WHERE scope = 'message' AND axis = 'message.attachment'
ORDER BY item_count DESC;

-- Extract message IDs for photo messages in March 2024.
SELECT mc.message_id
FROM message_categories mc
JOIN message_dimensions md USING(message_id)
WHERE mc.axis = 'message.attachment'
  AND mc.path = 'attachment/photo'
  AND md.sent_year = 2024
  AND md.sent_month = 3;

-- Find complete group threads with 1000+ messages.
SELECT thread_id, stored_message_count
FROM thread_dimensions
WHERE thread_kind = 'group'
  AND history_state = 'complete'
  AND volume_bucket = '1000_plus';
```

## Notes

Facebook can invalidate cookies or challenge sessions. If bridge commands fail with login/challenge errors, log into Facebook in the selected local browser profile and rerun `fbm me`; `fbm` refreshes the browser-derived appState cache before bridge calls.
