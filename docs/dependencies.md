# Dependency policy

`fbm` is stdlib-first. New dependencies should be avoided unless they clearly improve correctness, performance, portability, or maintenance more than a small local implementation would.

## Removed convenience dependencies

The public release avoids these direct dependencies by using small stdlib helpers instead:

- command parsing: local parser instead of `clap`
- table rendering: local formatter instead of `tabled`
- platform directories: local macOS/XDG path resolver instead of `directories`
- timestamps: local UTC date conversion instead of `chrono`
- error context: local `Result`/context helpers instead of `anyhow`
- logging: `eprintln!` warnings instead of `tracing`
- test temp dirs: local RAII temp dir instead of `tempfile`

## Retained direct dependencies

These are retained because stdlib replacements would be a significant drop in correctness, efficiency, or interoperability:

- `libsql`: SQLite/Turso access and local archive storage.
- `tokio`: async runtime required by `libsql` and the Node bridge process I/O.
- `serde`, `serde_json`, `toml`: stable config and JSON bridge protocol parsing/serialization.
- `aes`, `cbc`, `pbkdf2`, `sha1`, `sha2`: Chromium-family browser cookie decryption, including modern host-key hash handling.

## Review rule

Every new dependency must answer:

1. What stdlib implementation was considered?
2. Why is the dependency materially better for safety, performance, or portability?
3. Does it touch private user data, auth, networking, or storage?
4. Is the dependency actively maintained and appropriately licensed?
