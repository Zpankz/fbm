# Attribution

`fbm` is a Rust CLI and storage/query layer. Messenger access is delegated to a user-provided local checkout of [`ws3-fca`](https://github.com/nethgraves/ws3-fca), which is a separate project and is not vendored in this repository.

Related upstream lineage:

- [`ws3-fca`](https://github.com/nethgraves/ws3-fca), used at runtime via the Node.js bridge.
- The broader Facebook Chat API ecosystem, including earlier `facebook-chat-api` work.

The `fbm` bridge loads `module/index.js` from the configured `ws3-fca` directory and calls the public APIs exposed by that checkout. Users are responsible for installing and licensing any runtime dependencies they choose to use with `fbm`.

`fbm` is not affiliated with Meta, Facebook, Messenger, or the ws3-fca maintainers.
