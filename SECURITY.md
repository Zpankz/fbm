# Security policy

## Supported versions

Security fixes target the latest tagged release and `main`.

## Reporting vulnerabilities

Please open a private GitHub security advisory if available, or contact the repository owner through GitHub. Do not include real cookie values, appState JSON, database files, message bodies, thread IDs, user IDs, or exported conversations in public reports.

## Sensitive data rules

Never commit or paste:

- appState or browser-derived cookie caches
- SQLite/libSQL databases or WAL/SHM files
- Turso/libSQL auth tokens
- Facebook/Messenger user IDs, thread IDs, or message IDs from real accounts
- message bodies, attachments, exported conversations, screenshots, or logs that include private content

Before sharing diagnostics, prefer aggregate counts from `fbm status --json` or `fbm categorize --json` and redact identifiers.
