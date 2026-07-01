# Agent guide for fbm

`fbm` is privacy-sensitive. Treat all real Messenger data, appState files, browser profiles, DB files, logs, thread IDs, user IDs, message IDs, and exports as private.

## Safe defaults

- Never print cookie values, appState contents, message bodies, thread names, participant names, user IDs, or raw exports unless the user explicitly asks and the output remains local.
- Prefer aggregate counts and schema metadata.
- Run `cargo fmt`, `cargo test`, `cargo clippy --all-targets -- -D warnings`, and `node --check src/fbm_js_bridge/bridge.js` before release.
- Use synthetic fixtures only.
- Keep `ws3-fca` attribution intact.

## Useful commands

```sh
cargo test
fbm status --json
fbm categorize --json
```

For detailed workflow, load `.agents/skills/fbm/SKILL.md`.
