# Privacy guide

`fbm` works with private Messenger archives. Keep private material local.

## Do not publish

- appState files or browser-derived appState caches
- SQLite/libSQL databases or WAL/SHM files
- exported JSON/Markdown conversations
- message bodies, attachments, snippets, screenshots, or logs with private content
- participant names, thread names, user IDs, thread IDs, message IDs
- Turso/libSQL auth tokens

## Safer diagnostics

Use aggregate output:

```sh
fbm status --json
fbm categorize --json
fbm categorize --axis message.attachment --limit 20
```

Redact paths if they identify a person or machine.
