use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use libsql::{params, Builder, Connection, Database};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs,
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};

type Aes128CbcDec = cbc::Decryptor<Aes128>;

const APP_NAME: &str = "fbm";
const BRIDGE_SOURCE: &str = include_str!("fbm_js_bridge/bridge.js");

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Debug)]
struct SimpleError(String);

struct AppDirs {
    config: PathBuf,
    data: PathBuf,
    cache: PathBuf,
}

impl AppDirs {
    fn config_dir(&self) -> &Path {
        &self.config
    }

    fn data_dir(&self) -> &Path {
        &self.data
    }

    fn cache_dir(&self) -> &Path {
        &self.cache
    }
}

impl std::fmt::Display for SimpleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for SimpleError {}

fn simple_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(SimpleError(message.into()))
}

macro_rules! anyhow {
    ($($arg:tt)*) => {
        simple_error(format!($($arg)*))
    };
}

macro_rules! bail {
    ($($arg:tt)*) => {
        return Err(anyhow!($($arg)*))
    };
}

trait Context<T> {
    fn context(self, message: impl Into<String>) -> Result<T>;
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E> Context<T> for std::result::Result<T, E>
where
    E: std::fmt::Display + Send + Sync + 'static,
{
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.map_err(|err| simple_error(format!("{}: {err}", message.into())))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|err| simple_error(format!("{}: {err}", f())))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, message: impl Into<String>) -> Result<T> {
        self.ok_or_else(|| simple_error(message.into()))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.ok_or_else(|| simple_error(f()))
    }
}

#[derive(Debug)]
struct Cli {
    /// Path to fbm config TOML. Defaults to platform config dir.
    config: Option<PathBuf>,

    /// Output machine-readable JSON where supported.
    json: bool,

    command: Commands,
}

#[derive(Debug)]
enum Commands {
    /// Create or update config and initialize the database schema.
    Init(InitArgs),
    /// Print config and database status with secrets redacted.
    Status,
    /// Retrieve threads and message history from Facebook into SQLite/libSQL.
    Sync(SyncArgs),
    /// List stored conversations.
    Threads(ThreadsArgs),
    /// Show stored messages for one conversation.
    Messages(MessagesArgs),
    /// Full-text search stored messages.
    Search(SearchArgs),
    /// Build structured hierarchical/orthogonal categories for programmatic querying.
    Categorize(CategorizeArgs),
    /// Send a message to a Facebook thread and store the sent result.
    Send(SendArgs),
    /// Listen to real-time Messenger events and store incoming messages.
    Listen(ListenArgs),
    /// Export conversations as JSON or Markdown.
    Export(ExportArgs),
    /// Low-level authenticated ws3-fca probe.
    Me,
}

#[derive(Debug)]
struct InitArgs {
    /// ws3-fca repository directory. Defaults to current directory.
    fca_dir: Option<PathBuf>,

    /// Facebook appstate JSON path. Optional when using --from-browser.
    appstate: Option<PathBuf>,

    /// Import Facebook cookies from a local browser profile and cache them as appState.
    from_browser: bool,

    /// Browser to import cookies from when using --from-browser.
    browser: BrowserKind,

    /// Browser profile name/path fragment, for example Default, Profile 1, or a Firefox profile dir name.
    browser_profile: Option<String>,

    /// Path where browser-derived appState cookies are cached.
    browser_appstate_cache: Option<PathBuf>,

    /// Local libSQL/SQLite file path.
    db: Option<PathBuf>,

    /// Remote Turso/libSQL URL, for example libsql://db-org.turso.io.
    turso_url: Option<String>,

    /// Remote Turso/libSQL auth token. Stored in config only if provided.
    turso_auth_token: Option<String>,

    /// Overwrite existing config values.
    force: bool,
}

#[derive(Debug)]
struct SyncArgs {
    /// Exhaustively sync all reachable conversations: inbox + archived threads, paginated thread list, and full history.
    all: bool,

    /// Max threads to fetch. Use a high value for full archive sync.
    threads: usize,

    /// Max messages to fetch per thread per pass.
    messages: usize,

    /// Facebook thread tags to fetch.
    tags: Vec<String>,

    /// Only sync a specific thread ID.
    thread_id: Option<String>,

    /// Continue history pages until exhausted or --max-pages.
    full: bool,

    /// Max thread-list pages when --all is set. 0 means no page cap.
    max_thread_pages: usize,

    /// Max history pages per thread when --full is set. 0 means no page cap.
    max_pages: usize,

    /// Max threads whose histories are fetched in this run. 0 means no thread cap.
    history_threads: usize,
}

#[derive(Debug)]
struct ThreadsArgs {
    /// Number of rows to show.
    limit: usize,

    /// Filter by name, participant, snippet, or thread id.
    query: Option<String>,

    /// Include archived threads.
    archived: bool,
}

#[derive(Debug)]
struct MessagesArgs {
    /// Thread id.
    thread_id: String,

    /// Number of messages to show.
    limit: usize,

    /// Show newest messages first.
    newest: bool,
}

#[derive(Debug)]
struct SearchArgs {
    /// FTS query.
    query: String,

    /// Restrict to a thread id.
    thread_id: Option<String>,

    limit: usize,
}

#[derive(Debug)]
struct CategorizeArgs {
    /// Restrict preview counts to one category axis, for example message.attachment or time.sent.
    axis: Option<String>,

    /// Number of category count rows to preview.
    limit: usize,
}

#[derive(Debug)]
struct SendArgs {
    /// Thread id.
    thread_id: String,

    /// Message body.
    body: String,

    /// Reply to message id.
    reply_to: Option<String>,
}

#[derive(Debug)]
struct ListenArgs {
    /// Stop after this many stored message events. Omit to run forever.
    limit: Option<usize>,
}

#[derive(Debug)]
struct ExportArgs {
    /// Thread id. Omit to export all threads.
    thread_id: Option<String>,

    /// Export format.
    format: ExportFormat,

    /// Output file. Defaults to stdout.
    output: Option<PathBuf>,
}

#[derive(Debug, Clone)]
enum ExportFormat {
    Json,
    Markdown,
}

impl Cli {
    fn parse() -> Result<Self> {
        let mut args = env::args().skip(1).collect::<Vec<_>>();
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            print_help();
            std::process::exit(0);
        }
        if args.iter().any(|arg| arg == "--version" || arg == "-V") {
            println!("fbm {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }

        let mut config = env::var_os("FBM_CONFIG").map(PathBuf::from);
        let mut json = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--json" => {
                    json = true;
                    args.remove(i);
                }
                "--config" => {
                    let value = take_value(&mut args, i, "--config")?;
                    config = Some(PathBuf::from(value));
                }
                flag if flag.starts_with("--config=") => {
                    config = Some(PathBuf::from(flag.trim_start_matches("--config=")));
                    args.remove(i);
                }
                _ => i += 1,
            }
        }
        if args.is_empty() {
            print_help();
            bail!("missing command")
        }
        let command = args.remove(0);
        let command = match command.as_str() {
            "init" => Commands::Init(parse_init_args(args)?),
            "status" => Commands::Status,
            "sync" => Commands::Sync(parse_sync_args(args)?),
            "threads" => Commands::Threads(parse_threads_args(args)?),
            "messages" => Commands::Messages(parse_messages_args(args)?),
            "search" => Commands::Search(parse_search_args(args)?),
            "categorize" => Commands::Categorize(parse_categorize_args(args)?),
            "send" => Commands::Send(parse_send_args(args)?),
            "listen" => Commands::Listen(parse_listen_args(args)?),
            "export" => Commands::Export(parse_export_args(args)?),
            "me" => Commands::Me,
            other => bail!("unknown command `{other}`"),
        };
        Ok(Self {
            config,
            json,
            command,
        })
    }
}

impl BrowserKind {
    fn parse(raw: &str) -> Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "firefox" => Ok(Self::Firefox),
            "chrome" => Ok(Self::Chrome),
            "brave" => Ok(Self::Brave),
            "edge" => Ok(Self::Edge),
            "comet" => Ok(Self::Comet),
            "chromium" => Ok(Self::Chromium),
            _ => bail!("unknown browser `{raw}`"),
        }
    }
}

impl ExportFormat {
    fn parse(raw: &str) -> Result<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            _ => bail!("unknown export format `{raw}`"),
        }
    }
}

fn take_value(args: &mut Vec<String>, i: usize, flag: &str) -> Result<String> {
    if i + 1 >= args.len() {
        bail!("{flag} requires a value")
    }
    let value = args.remove(i + 1);
    args.remove(i);
    Ok(value)
}

fn parse_usize(raw: String, flag: &str) -> Result<usize> {
    raw.parse::<usize>()
        .with_context(|| format!("invalid integer for {flag}"))
}

fn parse_init_args(args: Vec<String>) -> Result<InitArgs> {
    let mut out = InitArgs {
        fca_dir: env::var_os("FBM_FCA_DIR").map(PathBuf::from),
        appstate: env::var_os("FBM_APPSTATE").map(PathBuf::from),
        from_browser: false,
        browser: BrowserKind::Auto,
        browser_profile: None,
        browser_appstate_cache: env::var_os("FBM_BROWSER_APPSTATE_CACHE").map(PathBuf::from),
        db: env::var_os("FBM_DB").map(PathBuf::from),
        turso_url: env::var("LIBSQL_URL").ok(),
        turso_auth_token: env::var("LIBSQL_AUTH_TOKEN").ok(),
        force: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--from-browser" {
            out.from_browser = true;
            i += 1;
        } else if arg == "--force" {
            out.force = true;
            i += 1;
        } else if let Some(v) = value_at(&args, &mut i, "--fca-dir")? {
            out.fca_dir = Some(PathBuf::from(v));
        } else if let Some(v) = value_at(&args, &mut i, "--appstate")? {
            out.appstate = Some(PathBuf::from(v));
        } else if let Some(v) = value_at(&args, &mut i, "--browser")? {
            out.browser = BrowserKind::parse(&v)?;
        } else if let Some(v) = value_at(&args, &mut i, "--browser-profile")? {
            out.browser_profile = Some(v);
        } else if let Some(v) = value_at(&args, &mut i, "--browser-appstate-cache")? {
            out.browser_appstate_cache = Some(PathBuf::from(v));
        } else if let Some(v) = value_at(&args, &mut i, "--db")? {
            out.db = Some(PathBuf::from(v));
        } else if let Some(v) = value_at(&args, &mut i, "--turso-url")? {
            out.turso_url = Some(v);
        } else if let Some(v) = value_at(&args, &mut i, "--turso-auth-token")? {
            out.turso_auth_token = Some(v);
        } else {
            bail!("unknown init argument `{arg}`");
        }
    }
    Ok(out)
}

fn value_at(args: &[String], i: &mut usize, flag: &str) -> Result<Option<String>> {
    let arg = &args[*i];
    if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
        *i += 1;
        return Ok(Some(value.to_string()));
    }
    if arg == flag {
        if *i + 1 >= args.len() {
            bail!("{flag} requires a value")
        }
        let value = args[*i + 1].clone();
        *i += 2;
        return Ok(Some(value));
    }
    Ok(None)
}

fn parse_sync_args(args: Vec<String>) -> Result<SyncArgs> {
    let mut out = SyncArgs {
        all: false,
        threads: 50,
        messages: 200,
        tags: vec!["INBOX".into()],
        thread_id: None,
        full: false,
        max_thread_pages: 0,
        max_pages: 25,
        history_threads: 0,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--all" {
            out.all = true;
            i += 1;
        } else if arg == "--full" {
            out.full = true;
            i += 1;
        } else if let Some(v) = value_at(&args, &mut i, "--threads")? {
            out.threads = parse_usize(v, "--threads")?;
        } else if let Some(v) = value_at(&args, &mut i, "--messages")? {
            out.messages = parse_usize(v, "--messages")?;
        } else if let Some(v) = value_at(&args, &mut i, "--tags")? {
            out.tags = v.split(',').map(str::to_string).collect();
        } else if let Some(v) = value_at(&args, &mut i, "--thread-id")? {
            out.thread_id = Some(v);
        } else if let Some(v) = value_at(&args, &mut i, "--max-thread-pages")? {
            out.max_thread_pages = parse_usize(v, "--max-thread-pages")?;
        } else if let Some(v) = value_at(&args, &mut i, "--max-pages")? {
            out.max_pages = parse_usize(v, "--max-pages")?;
        } else if let Some(v) = value_at(&args, &mut i, "--history-threads")? {
            out.history_threads = parse_usize(v, "--history-threads")?;
        } else {
            bail!("unknown sync argument `{arg}`");
        }
    }
    Ok(out)
}

fn parse_threads_args(args: Vec<String>) -> Result<ThreadsArgs> {
    let mut out = ThreadsArgs {
        limit: 30,
        query: None,
        archived: false,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--archived" {
            out.archived = true;
            i += 1;
        } else if let Some(v) = value_or_short_at(&args, &mut i, "--limit", "-l")? {
            out.limit = parse_usize(v, "--limit")?;
        } else if let Some(v) = value_or_short_at(&args, &mut i, "--query", "-q")? {
            out.query = Some(v);
        } else {
            bail!("unknown threads argument `{arg}`");
        }
    }
    Ok(out)
}

fn value_or_short_at(
    args: &[String],
    i: &mut usize,
    long_flag: &str,
    short_flag: &str,
) -> Result<Option<String>> {
    if let Some(value) = value_at(args, i, long_flag)? {
        return Ok(Some(value));
    }
    if args[*i] == short_flag {
        if *i + 1 >= args.len() {
            bail!("{short_flag} requires a value")
        }
        let value = args[*i + 1].clone();
        *i += 2;
        return Ok(Some(value));
    }
    Ok(None)
}

fn parse_messages_args(args: Vec<String>) -> Result<MessagesArgs> {
    let mut out = MessagesArgs {
        thread_id: String::new(),
        limit: 50,
        newest: false,
    };
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "--newest" {
            out.newest = true;
            i += 1;
        } else if let Some(v) = value_or_short_at(&args, &mut i, "--limit", "-l")? {
            out.limit = parse_usize(v, "--limit")?;
        } else if arg.starts_with('-') {
            bail!("unknown messages argument `{arg}`");
        } else {
            positional.push(arg.clone());
            i += 1;
        }
    }
    out.thread_id = positional
        .into_iter()
        .next()
        .context("messages requires thread_id")?;
    Ok(out)
}

fn parse_search_args(args: Vec<String>) -> Result<SearchArgs> {
    let mut out = SearchArgs {
        query: String::new(),
        thread_id: None,
        limit: 25,
    };
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = value_at(&args, &mut i, "--thread-id")? {
            out.thread_id = Some(v);
        } else if let Some(v) = value_or_short_at(&args, &mut i, "--limit", "-l")? {
            out.limit = parse_usize(v, "--limit")?;
        } else if arg.starts_with('-') {
            bail!("unknown search argument `{arg}`");
        } else {
            positional.push(arg.clone());
            i += 1;
        }
    }
    out.query = positional
        .into_iter()
        .next()
        .context("search requires query")?;
    Ok(out)
}

fn parse_categorize_args(args: Vec<String>) -> Result<CategorizeArgs> {
    let mut out = CategorizeArgs {
        axis: None,
        limit: 50,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = value_at(&args, &mut i, "--axis")? {
            out.axis = Some(v);
        } else if let Some(v) = value_or_short_at(&args, &mut i, "--limit", "-l")? {
            out.limit = parse_usize(v, "--limit")?;
        } else {
            bail!("unknown categorize argument `{arg}`");
        }
    }
    Ok(out)
}

fn parse_send_args(args: Vec<String>) -> Result<SendArgs> {
    let mut reply_to = None;
    let mut positional = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = value_at(&args, &mut i, "--reply-to")? {
            reply_to = Some(v);
        } else if arg.starts_with('-') {
            bail!("unknown send argument `{arg}`");
        } else {
            positional.push(arg.clone());
            i += 1;
        }
    }
    Ok(SendArgs {
        thread_id: positional
            .first()
            .cloned()
            .context("send requires thread_id")?,
        body: positional.get(1).cloned().context("send requires body")?,
        reply_to,
    })
}

fn parse_listen_args(args: Vec<String>) -> Result<ListenArgs> {
    let mut out = ListenArgs { limit: None };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = value_at(&args, &mut i, "--limit")? {
            out.limit = Some(parse_usize(v, "--limit")?);
        } else {
            bail!("unknown listen argument `{arg}`");
        }
    }
    Ok(out)
}

fn parse_export_args(args: Vec<String>) -> Result<ExportArgs> {
    let mut out = ExportArgs {
        thread_id: None,
        format: ExportFormat::Json,
        output: None,
    };
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = value_at(&args, &mut i, "--thread-id")? {
            out.thread_id = Some(v);
        } else if let Some(v) = value_at(&args, &mut i, "--format")? {
            out.format = ExportFormat::parse(&v)?;
        } else if let Some(v) = value_or_short_at(&args, &mut i, "--output", "-o")? {
            out.output = Some(PathBuf::from(v));
        } else {
            bail!("unknown export argument `{arg}`");
        }
    }
    Ok(out)
}

fn print_help() {
    println!("fbm {version}\n\nUsage: fbm [--config PATH] [--json] <command> [options]\n\nCommands: init, status, sync, threads, messages, search, categorize, send, listen, export, me", version = env!("CARGO_PKG_VERSION"));
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    fca_dir: PathBuf,
    appstate: Option<PathBuf>,
    #[serde(default)]
    auth: AuthConfig,
    database: DatabaseConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthConfig {
    #[serde(default)]
    method: AuthMethod,
    #[serde(default)]
    browser: BrowserKind,
    browser_profile: Option<String>,
    browser_appstate_cache: Option<PathBuf>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            method: AuthMethod::AppState,
            browser: BrowserKind::Auto,
            browser_profile: None,
            browser_appstate_cache: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum AuthMethod {
    #[default]
    AppState,
    Browser,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
enum BrowserKind {
    #[default]
    Auto,
    Firefox,
    Chrome,
    Brave,
    Edge,
    Comet,
    Chromium,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DatabaseConfig {
    path: PathBuf,
    remote_url: Option<String>,
    auth_token: Option<String>,
}

impl Config {
    fn redacted(&self) -> JsonValue {
        json!({
            "fca_dir": self.fca_dir,
            "appstate": self.appstate,
            "auth": {
                "method": self.auth.method,
                "browser": self.auth.browser,
                "browser_profile": self.auth.browser_profile,
                "browser_appstate_cache": self.auth.browser_appstate_cache,
            },
            "database": {
                "path": self.database.path,
                "remote_url": self.database.remote_url,
                "auth_token": self.database.auth_token.as_ref().map(|_| "<redacted>"),
            }
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct BridgeEnvelope {
    ok: bool,
    command: String,
    data: JsonValue,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ThreadRecord {
    #[serde(rename = "threadID")]
    thread_id: String,
    #[serde(rename = "threadName")]
    thread_name: Option<String>,
    #[serde(default, rename = "participantIDs")]
    participant_ids: Vec<String>,
    #[serde(default, rename = "userInfo")]
    user_info: Vec<JsonValue>,
    #[serde(default, rename = "unreadCount")]
    unread_count: Option<i64>,
    #[serde(default, rename = "messageCount")]
    message_count: Option<i64>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default, rename = "isGroup")]
    is_group: Option<bool>,
    #[serde(default, rename = "isArchived")]
    is_archived: Option<bool>,
    #[serde(default)]
    folder: Option<String>,
    #[serde(default)]
    snippet: Option<String>,
    #[serde(flatten)]
    raw_extra: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct MessageRecord {
    #[serde(rename = "messageID")]
    message_id: String,
    #[serde(rename = "threadID")]
    thread_id: String,
    #[serde(rename = "senderID", default)]
    sender_id: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    timestamp: Option<String>,
    #[serde(default)]
    attachments: Vec<JsonValue>,
    #[serde(default, rename = "mentions")]
    mentions: JsonValue,
    #[serde(default, rename = "messageReactions", alias = "reactions")]
    reactions: Vec<JsonValue>,
    #[serde(default, rename = "isUnread")]
    is_unread: Option<bool>,
    #[serde(default, rename = "isGroup")]
    is_group: Option<bool>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(flatten)]
    raw_extra: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Serialize)]
struct ThreadRow {
    thread_id: String,
    name: String,
    participants: usize,
    messages: String,
    unread: String,
    updated: String,
    snippet: String,
}

#[derive(Debug, Serialize)]
struct MessageRow {
    time: String,
    sender: String,
    body: String,
    message_id: String,
}

#[derive(Debug, Serialize)]
struct SearchRow {
    score: String,
    time: String,
    thread_id: String,
    sender: String,
    body: String,
}

#[derive(Debug, Serialize)]
struct CategoryCountRow {
    scope: String,
    axis: String,
    path: String,
    count: i64,
}

#[derive(Debug, Serialize)]
struct CategorizationSummary {
    threads: i64,
    messages: i64,
    category_nodes: i64,
    thread_assignments: i64,
    message_assignments: i64,
    axes: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Copy)]
enum TimeDepth {
    Month,
    #[cfg_attr(not(test), allow(dead_code))]
    Hour,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse()?;
    let config_path = config_path(cli.config.as_deref())?;

    match cli.command {
        Commands::Init(args) => init_command(&config_path, args, cli.json).await,
        Commands::Status => {
            let cfg = load_config(&config_path).await?;
            let db = open_database(&cfg).await?;
            let conn = db.connect()?;
            migrate(&conn).await?;
            let counts = db_counts(&conn).await?;
            print_json_or_table(
                cli.json,
                json!({ "config_path": config_path, "config": cfg.redacted(), "counts": counts }),
                format!(
                    "config: {}\ndb: {}\nthreads: {}\nmessages: {}",
                    config_path.display(),
                    cfg.database.path.display(),
                    counts.0,
                    counts.1
                ),
            )
        }
        Commands::Sync(args) => {
            with_store(&config_path, |cfg, conn| async move {
                sync_command(&cfg, &conn, args, cli.json).await
            })
            .await
        }
        Commands::Threads(args) => {
            with_store(&config_path, |_, conn| async move {
                threads_command(&conn, args, cli.json).await
            })
            .await
        }
        Commands::Messages(args) => {
            with_store(&config_path, |_, conn| async move {
                messages_command(&conn, args, cli.json).await
            })
            .await
        }
        Commands::Search(args) => {
            with_store(&config_path, |_, conn| async move {
                search_command(&conn, args, cli.json).await
            })
            .await
        }
        Commands::Categorize(args) => {
            with_store(&config_path, |_, conn| async move {
                categorize_command(&conn, args, cli.json).await
            })
            .await
        }
        Commands::Send(args) => {
            with_store(&config_path, |cfg, conn| async move {
                send_command(&cfg, &conn, args, cli.json).await
            })
            .await
        }
        Commands::Listen(args) => {
            with_store(&config_path, |cfg, conn| async move {
                listen_command(&cfg, &conn, args).await
            })
            .await
        }
        Commands::Export(args) => {
            with_store(&config_path, |_, conn| async move {
                export_command(&conn, args).await
            })
            .await
        }
        Commands::Me => {
            let cfg = load_config(&config_path).await?;
            let bridge = call_bridge(&cfg, "me", json!({})).await?;
            print_json_or_table(cli.json, bridge.data.clone(), bridge.data.to_string())
        }
    }
}

async fn with_store<F, Fut>(config_path: &Path, f: F) -> Result<()>
where
    F: FnOnce(Config, Connection) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let cfg = load_config(config_path).await?;
    let db = open_database(&cfg).await?;
    let conn = db.connect()?;
    migrate(&conn).await?;
    f(cfg, conn).await
}

async fn init_command(path: &Path, args: InitArgs, json_output: bool) -> Result<()> {
    let existing = if path.exists() && !args.force {
        Some(load_config(path).await?)
    } else {
        None
    };

    let default_data = project_dirs()?.data_dir().to_path_buf();
    fs::create_dir_all(&default_data).await?;

    let requested_appstate = args
        .appstate
        .or_else(|| existing.as_ref().and_then(|c| c.appstate.clone()));
    let auth_method = if args.from_browser || requested_appstate.is_none() {
        AuthMethod::Browser
    } else {
        existing
            .as_ref()
            .map(|c| c.auth.method)
            .unwrap_or(AuthMethod::AppState)
    };
    let auth = AuthConfig {
        method: auth_method,
        browser: if args.browser != BrowserKind::Auto {
            args.browser
        } else {
            existing
                .as_ref()
                .map(|c| c.auth.browser)
                .unwrap_or_default()
        },
        browser_profile: args.browser_profile.or_else(|| {
            existing
                .as_ref()
                .and_then(|c| c.auth.browser_profile.clone())
        }),
        browser_appstate_cache: args.browser_appstate_cache.or_else(|| {
            existing
                .as_ref()
                .and_then(|c| c.auth.browser_appstate_cache.clone())
        }),
    };

    let cfg = Config {
        fca_dir: args
            .fca_dir
            .or_else(|| existing.as_ref().map(|c| c.fca_dir.clone()))
            .unwrap_or(env::current_dir()?)
            .canonicalize()
            .context("failed to canonicalize ws3-fca directory")?,
        appstate: requested_appstate,
        auth,
        database: DatabaseConfig {
            path: args
                .db
                .or_else(|| existing.as_ref().map(|c| c.database.path.clone()))
                .unwrap_or_else(|| default_data.join("fbm.db")),
            remote_url: args.turso_url.or_else(|| {
                existing
                    .as_ref()
                    .and_then(|c| c.database.remote_url.clone())
            }),
            auth_token: args.turso_auth_token.or_else(|| {
                existing
                    .as_ref()
                    .and_then(|c| c.database.auth_token.clone())
            }),
        },
    };

    if !cfg.fca_dir.join("module/index.js").exists() {
        bail!(
            "{} does not look like a ws3-fca checkout: missing module/index.js",
            cfg.fca_dir.display()
        );
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(path, toml::to_string_pretty(&cfg)?).await?;

    let db = open_database(&cfg).await?;
    let conn = db.connect()?;
    migrate(&conn).await?;
    ensure_bridge(&cfg).await?;
    let resolved_appstate = resolve_appstate_path(&cfg).await?;

    print_json_or_table(
        json_output,
        json!({ "config_path": path, "config": cfg.redacted(), "resolved_appstate": resolved_appstate }),
        format!(
            "initialized fbm\nconfig: {}\ndb: {}\nfca: {}\nauth: {:?}\nappstate: {}",
            path.display(),
            cfg.database.path.display(),
            cfg.fca_dir.display(),
            cfg.auth.method,
            resolved_appstate.display()
        ),
    )
}

async fn sync_command(
    cfg: &Config,
    conn: &Connection,
    args: SyncArgs,
    json_output: bool,
) -> Result<()> {
    if args.threads == 0 {
        bail!("--threads must be greater than 0");
    }
    if args.messages == 0 {
        bail!("--messages must be greater than 0");
    }

    let mut synced_threads = 0usize;
    let mut synced_messages = 0usize;
    let mut thread_pages = 0usize;
    let mut history_pages = 0usize;
    let mut history_threads_processed = 0usize;
    let mut history_threads_skipped_complete = 0usize;
    let tag_groups = sync_tag_groups(args.all, &args.tags);
    let appstate = resolve_appstate_path(cfg).await?;

    let thread_ids = if let Some(thread_id) = args.thread_id.clone() {
        vec![thread_id]
    } else {
        let mut ids = Vec::new();
        let mut seen = BTreeSet::new();
        for tag_group in &tag_groups {
            let mut before: Option<i64> = None;

            loop {
                thread_pages += 1;
                let resp = call_bridge_with_appstate(
                    cfg,
                    &appstate,
                    "threads",
                    json!({ "limit": args.threads, "tags": tag_group, "timestamp": before }),
                )
                .await?;
                let threads: Vec<ThreadRecord> = serde_json::from_value(resp.data)?;
                if threads.is_empty() {
                    break;
                }

                let page_len = threads.len();
                before = next_thread_before(&threads);
                for thread in threads {
                    if seen.insert(thread.thread_id.clone()) {
                        ids.push(thread.thread_id.clone());
                        synced_threads += 1;
                    }
                    upsert_thread(conn, &thread).await?;
                }

                let hit_thread_page_cap =
                    args.max_thread_pages > 0 && thread_pages >= args.max_thread_pages;
                if !args.all || hit_thread_page_cap || page_len < args.threads || before.is_none() {
                    break;
                }
            }
        }
        ids
    };

    let full_history = args.full || args.all;
    let max_history_pages = if args.all { 0 } else { args.max_pages };
    for thread_id in thread_ids {
        let remote_message_count = thread_message_count(conn, &thread_id).await?;
        let stored_message_count = stored_message_count(conn, &thread_id).await?;
        if is_thread_history_marked_complete(conn, &thread_id).await?
            || is_history_complete(remote_message_count, stored_message_count)
        {
            history_threads_skipped_complete += 1;
            continue;
        }
        if args.history_threads > 0 && history_threads_processed >= args.history_threads {
            break;
        }
        history_threads_processed += 1;

        let mut before: Option<i64> = earliest_message_timestamp(conn, &thread_id)
            .await?
            .map(|timestamp| timestamp.saturating_sub(1));
        let mut pages = 0usize;
        loop {
            pages += 1;
            let resp = call_bridge_with_appstate(
                cfg,
                &appstate,
                "history",
                json!({ "threadID": thread_id, "amount": args.messages, "timestamp": before }),
            )
            .await?;
            let mut messages: Vec<MessageRecord> = serde_json::from_value(resp.data)?;
            if messages.is_empty() {
                mark_thread_history_state(conn, &thread_id, before, true).await?;
                break;
            }
            history_pages += 1;
            messages.sort_by_key(|m| parse_ts_millis(m.timestamp.as_deref()).unwrap_or_default());
            before = messages
                .first()
                .and_then(|m| parse_ts_millis(m.timestamp.as_deref()))
                .map(|v| v.saturating_sub(1));
            for message in messages.iter() {
                upsert_message(conn, message).await?;
                synced_messages += 1;
            }
            let continue_history = should_continue_history(
                full_history,
                pages,
                max_history_pages,
                messages.len(),
                args.messages,
            );
            let exhausted = full_history && messages.len() < args.messages;
            mark_thread_history_state(conn, &thread_id, before, exhausted).await?;
            if !continue_history {
                break;
            }
        }
    }

    print_json_or_table(
        json_output,
        json!({
            "threads": synced_threads,
            "messages": synced_messages,
            "thread_pages": thread_pages,
            "history_pages": history_pages,
            "history_threads_processed": history_threads_processed,
            "history_threads_skipped_complete": history_threads_skipped_complete,
            "tag_groups": tag_groups,
            "all": args.all,
            "full_history": full_history,
        }),
        format!(
            "synced {synced_threads} threads and {synced_messages} messages ({thread_pages} thread pages, {history_pages} history pages)"
        ),
    )
}

fn is_history_complete(remote_message_count: Option<i64>, stored_message_count: i64) -> bool {
    remote_message_count.is_some_and(|remote| remote <= stored_message_count)
}

fn sync_tag_groups(all: bool, tags: &[String]) -> Vec<Vec<String>> {
    if all && tags == ["INBOX".to_string()] {
        ["INBOX", "ARCHIVED", "OTHER", "PENDING", "SPAM"]
            .into_iter()
            .map(|tag| vec![tag.to_string()])
            .collect()
    } else {
        vec![tags.to_vec()]
    }
}

fn next_thread_before(threads: &[ThreadRecord]) -> Option<i64> {
    threads
        .iter()
        .filter_map(|thread| parse_ts_millis(thread.timestamp.as_deref()))
        .min()
        .map(|timestamp| timestamp.saturating_sub(1))
}

fn should_continue_history(
    full: bool,
    pages_completed: usize,
    max_pages: usize,
    page_len: usize,
    page_size: usize,
) -> bool {
    full && page_len >= page_size && (max_pages == 0 || pages_completed < max_pages)
}

async fn threads_command(conn: &Connection, args: ThreadsArgs, json_output: bool) -> Result<()> {
    let mut sql = "SELECT thread_id, name, participant_ids, message_count, unread_count, updated_at, snippet FROM threads".to_string();
    let mut clauses = Vec::new();
    if !args.archived {
        clauses.push("is_archived = 0".to_string());
    }
    if args.query.is_some() {
        clauses.push(
            "(thread_id LIKE ?1 OR name LIKE ?1 OR participant_names LIKE ?1 OR snippet LIKE ?1)"
                .to_string(),
        );
    }
    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY COALESCE(updated_at, 0) DESC LIMIT ?2");

    let like = args
        .query
        .map(|q| format!("%{q}%"))
        .unwrap_or_else(|| "%".into());
    let mut rows = conn.query(&sql, params![like, args.limit as i64]).await?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        let participants_json: String = row.get(2)?;
        let participants: Vec<String> =
            serde_json::from_str(&participants_json).unwrap_or_default();
        out.push(ThreadRow {
            thread_id: row.get(0)?,
            name: row.get::<Option<String>>(1)?.unwrap_or_default(),
            participants: participants.len(),
            messages: row
                .get::<Option<i64>>(3)?
                .map(|n| n.to_string())
                .unwrap_or_default(),
            unread: row
                .get::<Option<i64>>(4)?
                .map(|n| n.to_string())
                .unwrap_or_default(),
            updated: fmt_ts(row.get::<Option<i64>>(5)?),
            snippet: truncate(&row.get::<Option<String>>(6)?.unwrap_or_default(), 80),
        });
    }
    if json_output {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_rows(&out)?;
    }
    Ok(())
}

async fn messages_command(conn: &Connection, args: MessagesArgs, json_output: bool) -> Result<()> {
    let order = if args.newest { "DESC" } else { "ASC" };
    let sql = format!("SELECT timestamp, sender_id, body, message_id FROM messages WHERE thread_id = ?1 ORDER BY COALESCE(timestamp, 0) {order} LIMIT ?2");
    let mut rows = conn
        .query(&sql, params![args.thread_id, args.limit as i64])
        .await?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        out.push(MessageRow {
            time: fmt_ts(row.get::<Option<i64>>(0)?),
            sender: row.get::<Option<String>>(1)?.unwrap_or_default(),
            body: truncate(&row.get::<Option<String>>(2)?.unwrap_or_default(), 140),
            message_id: row.get(3)?,
        });
    }
    if json_output {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_rows(&out)?;
    }
    Ok(())
}

async fn search_command(conn: &Connection, args: SearchArgs, json_output: bool) -> Result<()> {
    let mut sql = "SELECT rank, timestamp, thread_id, sender_id, body FROM message_fts WHERE message_fts MATCH ?1".to_string();
    if args.thread_id.is_some() {
        sql.push_str(" AND thread_id = ?2 LIMIT ?3");
    } else {
        sql.push_str(" LIMIT ?2");
    }
    let mut rows = if let Some(thread_id) = args.thread_id {
        conn.query(&sql, params![args.query, thread_id, args.limit as i64])
            .await?
    } else {
        conn.query(&sql, params![args.query, args.limit as i64])
            .await?
    };
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        let score: f64 = row.get(0).unwrap_or(0.0);
        out.push(SearchRow {
            score: format!("{score:.2}"),
            time: fmt_ts(row.get::<Option<i64>>(1)?),
            thread_id: row.get::<Option<String>>(2)?.unwrap_or_default(),
            sender: row.get::<Option<String>>(3)?.unwrap_or_default(),
            body: truncate(&row.get::<Option<String>>(4)?.unwrap_or_default(), 180),
        });
    }
    if json_output {
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print_rows(&out)?;
    }
    Ok(())
}

async fn categorize_command(
    conn: &Connection,
    args: CategorizeArgs,
    json_output: bool,
) -> Result<()> {
    let summary = refresh_structured_categories(conn).await?;
    let counts = category_count_rows(conn, args.axis.as_deref(), args.limit).await?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({ "summary": summary, "counts": counts }))?
        );
    } else {
        println!(
            "categorized {} threads and {} messages into {} taxonomy nodes ({} thread facets, {} message facets)",
            summary.threads,
            summary.messages,
            summary.category_nodes,
            summary.thread_assignments,
            summary.message_assignments
        );
        if !counts.is_empty() {
            print_rows(&counts)?;
        }
    }
    Ok(())
}

async fn refresh_structured_categories(conn: &Connection) -> Result<CategorizationSummary> {
    conn.execute_batch(
        r#"
        DELETE FROM category_nodes;
        DELETE FROM thread_categories;
        DELETE FROM message_categories;
        DELETE FROM thread_dimensions;
        DELETE FROM message_dimensions;
        "#,
    )
    .await?;

    refresh_thread_dimensions_and_categories(conn).await?;
    refresh_message_dimensions_and_categories(conn).await?;
    refresh_category_nodes(conn).await?;

    let axes = category_axis_counts(conn).await?;
    Ok(CategorizationSummary {
        threads: scalar_i64(conn, "SELECT COUNT(*) FROM thread_dimensions").await?,
        messages: scalar_i64(conn, "SELECT COUNT(*) FROM message_dimensions").await?,
        category_nodes: scalar_i64(conn, "SELECT COUNT(*) FROM category_nodes").await?,
        thread_assignments: scalar_i64(conn, "SELECT COUNT(*) FROM thread_categories").await?,
        message_assignments: scalar_i64(conn, "SELECT COUNT(*) FROM message_categories").await?,
        axes,
    })
}

async fn refresh_thread_dimensions_and_categories(conn: &Connection) -> Result<()> {
    let mut rows = conn
        .query(
            r#"SELECT t.thread_id, t.folder, t.is_archived, t.is_group, t.participant_ids,
                      t.message_count, t.updated_at, COALESCE(m.stored_messages, 0),
                      COALESCE(h.complete, 0)
               FROM threads t
               LEFT JOIN (SELECT thread_id, COUNT(*) AS stored_messages FROM messages GROUP BY thread_id) m
                    ON m.thread_id = t.thread_id
               LEFT JOIN thread_history_state h ON h.thread_id = t.thread_id"#,
            params![],
        )
        .await?;

    while let Some(row) = rows.next().await? {
        let thread_id: String = row.get(0)?;
        let folder = path_component(
            &row.get::<Option<String>>(1)?
                .unwrap_or_else(|| "unknown".into()),
        );
        let archive_state = if row.get::<i64>(2).unwrap_or_default() != 0 {
            "archived"
        } else {
            "active"
        };
        let thread_kind = if row.get::<i64>(3).unwrap_or_default() != 0 {
            "group"
        } else {
            "direct"
        };
        let participant_ids: Vec<String> =
            serde_json::from_str(&row.get::<Option<String>>(4)?.unwrap_or_else(|| "[]".into()))
                .unwrap_or_default();
        let participant_count = participant_ids.len() as i64;
        let remote_message_count = row.get::<Option<i64>>(5)?;
        let updated_at = row.get::<Option<i64>>(6)?;
        let stored_message_count: i64 = row.get(7)?;
        let history_complete = row.get::<i64>(8).unwrap_or_default() != 0
            || is_history_complete(remote_message_count, stored_message_count);
        let history_state = if history_complete {
            "complete"
        } else {
            "incomplete"
        };
        let representative_count = remote_message_count.unwrap_or(stored_message_count);
        let (activity_year, activity_month, _, _) = time_parts(updated_at);

        conn.execute(
            r#"INSERT OR REPLACE INTO thread_dimensions (
                thread_id, folder, archive_state, thread_kind, participant_count, participant_bucket,
                remote_message_count, stored_message_count, volume_bucket, history_state,
                activity_year, activity_month, updated_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
            params![
                thread_id.clone(),
                folder.clone(),
                archive_state,
                thread_kind,
                participant_count,
                participant_bucket(participant_count as usize),
                remote_message_count,
                stored_message_count,
                count_bucket(representative_count),
                history_state,
                activity_year,
                activity_month,
                now_ms(),
            ],
        )
        .await?;

        insert_thread_category(
            conn,
            &thread_id,
            "source.folder",
            &format!("folder/{folder}"),
        )
        .await?;
        insert_thread_category(
            conn,
            &thread_id,
            "thread.archive",
            &format!("archive/{archive_state}"),
        )
        .await?;
        insert_thread_category(
            conn,
            &thread_id,
            "thread.kind",
            &format!("kind/{thread_kind}"),
        )
        .await?;
        insert_thread_category(
            conn,
            &thread_id,
            "participants.size",
            &format!(
                "participants/{}",
                participant_bucket(participant_count as usize)
            ),
        )
        .await?;
        insert_thread_category(
            conn,
            &thread_id,
            "volume.messages",
            &format!("volume/{}", count_bucket(representative_count)),
        )
        .await?;
        insert_thread_category(
            conn,
            &thread_id,
            "thread.history",
            &format!("history/{history_state}"),
        )
        .await?;
        if let Some(path) = updated_at.and_then(|ts| time_path(ts, TimeDepth::Month)) {
            insert_thread_category(conn, &thread_id, "time.activity", &path).await?;
        }
    }
    Ok(())
}

async fn refresh_message_dimensions_and_categories(conn: &Connection) -> Result<()> {
    let now = now_ms();
    conn.execute(
        r#"INSERT OR REPLACE INTO message_dimensions (
            message_id, thread_id, sender_id, sender_scope, message_kind, text_state, body_bucket,
            attachment_class, reaction_state, mention_state, sent_year, sent_month, sent_day,
            sent_hour, timestamp, updated_at
        )
        SELECT message_id,
               thread_id,
               NULLIF(sender_id, ''),
               CASE WHEN sender_id IS NULL OR sender_id = '' THEN 'unknown' ELSE 'known' END,
               COALESCE(NULLIF(kind, ''), 'unknown'),
               CASE WHEN length(COALESCE(body, '')) = 0 THEN 'empty' ELSE 'present' END,
               CASE WHEN length(COALESCE(body, '')) = 0 THEN '0'
                    WHEN length(body) <= 80 THEN '1_80'
                    WHEN length(body) <= 280 THEN '81_280'
                    ELSE '281_plus' END,
               CASE WHEN attachments IS NULL OR attachments = '[]' OR attachments = '' THEN 'none'
                    WHEN ((attachments LIKE '%"type":"photo"%') + (attachments LIKE '%"type":"video"%') +
                          (attachments LIKE '%"type":"audio"%') + (attachments LIKE '%"type":"file"%') +
                          (attachments LIKE '%"type":"share"%') + (attachments LIKE '%"type":"sticker"%') +
                          (attachments LIKE '%"type":"animated_image"%')) > 1 THEN 'mixed'
                    WHEN attachments LIKE '%"type":"photo"%' THEN 'photo'
                    WHEN attachments LIKE '%"type":"video"%' THEN 'video'
                    WHEN attachments LIKE '%"type":"audio"%' THEN 'audio'
                    WHEN attachments LIKE '%"type":"file"%' THEN 'file'
                    WHEN attachments LIKE '%"type":"share"%' THEN 'share'
                    WHEN attachments LIKE '%"type":"sticker"%' THEN 'sticker'
                    WHEN attachments LIKE '%"type":"animated_image"%' THEN 'animated_image'
                    ELSE 'other' END,
               CASE WHEN reactions IS NULL OR reactions = '[]' OR reactions = '' THEN 'none' ELSE 'present' END,
               CASE WHEN mentions IS NULL OR mentions IN ('{}', '[]', 'null', '') THEN 'none' ELSE 'present' END,
               CAST(strftime('%Y', timestamp / 1000, 'unixepoch') AS INTEGER),
               CAST(strftime('%m', timestamp / 1000, 'unixepoch') AS INTEGER),
               CAST(strftime('%d', timestamp / 1000, 'unixepoch') AS INTEGER),
               CAST(strftime('%H', timestamp / 1000, 'unixepoch') AS INTEGER),
               timestamp,
               ?1
        FROM messages"#,
        params![now],
    )
    .await?;

    conn.execute_batch(
        &format!(
            r#"
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'message.kind', 'kind/' || lower(message_kind), 'derived', 1.0, {now} FROM message_dimensions;
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'message.text', 'text/' || text_state, 'derived', 1.0, {now} FROM message_dimensions;
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'volume.body', 'body/' || body_bucket, 'derived', 1.0, {now} FROM message_dimensions;
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'message.attachment', 'attachment/' || attachment_class, 'derived', 1.0, {now} FROM message_dimensions;
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'message.reactions', 'reactions/' || reaction_state, 'derived', 1.0, {now} FROM message_dimensions;
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'message.mentions', 'mentions/' || mention_state, 'derived', 1.0, {now} FROM message_dimensions;
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'sender.scope', 'sender/' || sender_scope, 'derived', 1.0, {now} FROM message_dimensions;
            INSERT OR REPLACE INTO message_categories(message_id, axis, path, source, confidence, updated_at)
                SELECT message_id, 'time.sent', printf('time/%04d/%02d/%02d/%02d', sent_year, sent_month, sent_day, sent_hour), 'derived', 1.0, {now}
                FROM message_dimensions WHERE sent_year IS NOT NULL;
            "#
        ),
    )
    .await?;
    Ok(())
}

async fn insert_thread_category(
    conn: &Connection,
    thread_id: &str,
    axis: &str,
    path: &str,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO thread_categories(thread_id, axis, path, source, confidence, updated_at) VALUES (?1, ?2, ?3, 'derived', 1.0, ?4)",
        params![thread_id, axis, path, now_ms()],
    )
    .await?;
    Ok(())
}

async fn refresh_category_nodes(conn: &Connection) -> Result<()> {
    let mut rows = conn
        .query(
            r#"SELECT DISTINCT axis, path FROM thread_categories
               UNION
               SELECT DISTINCT axis, path FROM message_categories"#,
            params![],
        )
        .await?;
    let mut nodes = BTreeSet::new();
    while let Some(row) = rows.next().await? {
        let axis: String = row.get(0)?;
        let path: String = row.get(1)?;
        for ancestor in category_ancestors(&path) {
            nodes.insert((axis.clone(), ancestor));
        }
    }
    for (axis, path) in nodes {
        let parts: Vec<&str> = path.split('/').collect();
        let depth = (parts.len() as i64) - 1;
        let parent_path = if parts.len() > 1 {
            Some(parts[..parts.len() - 1].join("/"))
        } else {
            None
        };
        let label = parts.last().copied().unwrap_or_default().to_string();
        conn.execute(
            "INSERT OR IGNORE INTO category_nodes(axis, path, label, parent_path, depth, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, '', ?6)",
            params![axis, path, label, parent_path, depth, now_ms()],
        )
        .await?;
    }
    Ok(())
}

async fn category_axis_counts(conn: &Connection) -> Result<BTreeMap<String, i64>> {
    let mut rows = conn
        .query(
            "SELECT axis, COUNT(*) FROM category_nodes GROUP BY axis ORDER BY axis",
            params![],
        )
        .await?;
    let mut out = BTreeMap::new();
    while let Some(row) = rows.next().await? {
        out.insert(row.get(0)?, row.get(1)?);
    }
    Ok(out)
}

async fn category_count_rows(
    conn: &Connection,
    axis: Option<&str>,
    limit: usize,
) -> Result<Vec<CategoryCountRow>> {
    let mut rows = if let Some(axis) = axis {
        conn.query(
            "SELECT scope, axis, path, item_count FROM v_category_counts WHERE axis = ?1 ORDER BY item_count DESC, path LIMIT ?2",
            params![axis, limit as i64],
        )
        .await?
    } else {
        conn.query(
            "SELECT scope, axis, path, item_count FROM v_category_counts ORDER BY item_count DESC, axis, path LIMIT ?1",
            params![limit as i64],
        )
        .await?
    };
    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        out.push(CategoryCountRow {
            scope: row.get(0)?,
            axis: row.get(1)?,
            path: row.get(2)?,
            count: row.get(3)?,
        });
    }
    Ok(out)
}

fn participant_bucket(count: usize) -> &'static str {
    match count {
        0 | 1 => "1_or_less",
        2 => "2",
        3..=5 => "3_5",
        6..=10 => "6_10",
        11..=25 => "11_25",
        _ => "26_plus",
    }
}

fn count_bucket(count: i64) -> &'static str {
    match count {
        i64::MIN..=0 => "0",
        1..=9 => "1_9",
        10..=99 => "10_99",
        100..=999 => "100_999",
        _ => "1000_plus",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn body_length_bucket(body: &str) -> &'static str {
    match body.chars().count() {
        0 => "0",
        1..=80 => "1_80",
        81..=280 => "81_280",
        _ => "281_plus",
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn attachment_class(raw: &str) -> &'static str {
    let Ok(value) = serde_json::from_str::<JsonValue>(raw) else {
        return "other";
    };
    let Some(items) = value.as_array() else {
        return "other";
    };
    if items.is_empty() {
        return "none";
    }
    let mut kinds = BTreeSet::new();
    for item in items {
        let kind = item
            .get("type")
            .or_else(|| item.get("attachmentType"))
            .or_else(|| item.get("__typename"))
            .and_then(|v| v.as_str())
            .map(path_component)
            .unwrap_or_else(|| "other".into());
        kinds.insert(kind);
    }
    if kinds.len() > 1 {
        "mixed"
    } else {
        match kinds.iter().next().map(|s| s.as_str()) {
            Some("photo") => "photo",
            Some("video") => "video",
            Some("audio") => "audio",
            Some("file") => "file",
            Some("share") => "share",
            Some("sticker") => "sticker",
            Some("animated_image") => "animated_image",
            _ => "other",
        }
    }
}

fn time_parts(ts: Option<i64>) -> (Option<i64>, Option<i64>, Option<i64>, Option<i64>) {
    ts.map(utc_parts)
        .map(|(year, month, day, hour)| {
            (
                Some(year as i64),
                Some(month as i64),
                Some(day as i64),
                Some(hour as i64),
            )
        })
        .unwrap_or((None, None, None, None))
}

fn time_path(ts: i64, depth: TimeDepth) -> Option<String> {
    if ts < 0 {
        return None;
    }
    let (year, month, day, hour) = utc_parts(ts);
    Some(match depth {
        TimeDepth::Month => format!("time/{year:04}/{month:02}"),
        TimeDepth::Hour => format!("time/{year:04}/{month:02}/{day:02}/{hour:02}"),
    })
}

fn category_ancestors(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    (1..=parts.len()).map(|n| parts[..n].join("/")).collect()
}

fn path_component(input: &str) -> String {
    let mut out = String::new();
    let mut last_underscore = false;
    for ch in input.trim().to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_underscore = false;
        } else if !last_underscore {
            out.push('_');
            last_underscore = true;
        }
    }
    let out = out.trim_matches('_').to_string();
    if out.is_empty() {
        "unknown".into()
    } else {
        out
    }
}

async fn send_command(
    cfg: &Config,
    conn: &Connection,
    args: SendArgs,
    json_output: bool,
) -> Result<()> {
    let resp = call_bridge(
        cfg,
        "send",
        json!({ "threadID": args.thread_id, "body": args.body, "replyTo": args.reply_to }),
    )
    .await?;
    if let Ok(message) = serde_json::from_value::<MessageRecord>(resp.data.clone()) {
        upsert_message(conn, &message).await?;
    }
    print_json_or_table(json_output, resp.data.clone(), resp.data.to_string())
}

async fn listen_command(cfg: &Config, conn: &Connection, args: ListenArgs) -> Result<()> {
    let bridge = ensure_bridge(cfg).await?;
    let appstate = resolve_appstate_path(cfg).await?;
    let mut child = Command::new(node_bin())
        .arg(bridge)
        .arg("listen")
        .arg(serde_json::to_string(&bridge_context(cfg, &appstate))?)
        .arg("{}")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start Node bridge")?;

    let stdout = child.stdout.take().context("bridge stdout unavailable")?;
    let mut lines = BufReader::new(stdout).lines();
    let mut count = 0usize;
    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<BridgeEnvelope>(&line) {
            Ok(env) if env.ok && env.command == "event" => {
                if let Ok(message) = serde_json::from_value::<MessageRecord>(env.data.clone()) {
                    upsert_message(conn, &message).await?;
                    count += 1;
                    println!(
                        "[{}] {}: {}",
                        fmt_ts(parse_ts_millis(message.timestamp.as_deref())),
                        message.thread_id,
                        truncate(message.body.as_deref().unwrap_or(""), 120)
                    );
                    if args.limit.is_some_and(|limit| count >= limit) {
                        child.kill().await.ok();
                        break;
                    }
                } else {
                    println!("{}", env.data);
                }
            }
            Ok(env) if !env.ok => bail!("bridge error: {}", env.data),
            Ok(env) => println!("{}", env.data),
            Err(_) => eprintln!("bridge: {line}"),
        }
    }
    Ok(())
}

async fn export_command(conn: &Connection, args: ExportArgs) -> Result<()> {
    let payload = match args.format {
        ExportFormat::Json => export_json(conn, args.thread_id.as_deref()).await?,
        ExportFormat::Markdown => {
            JsonValue::String(export_markdown(conn, args.thread_id.as_deref()).await?)
        }
    };
    let content = match args.format {
        ExportFormat::Json => serde_json::to_string_pretty(&payload)?,
        ExportFormat::Markdown => payload.as_str().unwrap_or_default().to_string(),
    };
    if let Some(path) = args.output {
        fs::write(&path, content).await?;
        println!("exported {}", path.display());
    } else {
        println!("{content}");
    }
    Ok(())
}

async fn open_database(cfg: &Config) -> Result<Database> {
    if let Some(url) = &cfg.database.remote_url {
        let token = cfg
            .database
            .auth_token
            .as_ref()
            .ok_or_else(|| anyhow!("remote Turso/libSQL URL requires auth_token"))?;
        Ok(Builder::new_remote(url.clone(), token.clone())
            .build()
            .await?)
    } else {
        if let Some(parent) = cfg.database.path.parent() {
            fs::create_dir_all(parent).await?;
        }
        Ok(
            Builder::new_local(cfg.database.path.to_string_lossy().to_string())
                .build()
                .await?,
        )
    }
}

async fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS threads (
            thread_id TEXT PRIMARY KEY,
            name TEXT,
            participant_ids TEXT NOT NULL DEFAULT '[]',
            participant_names TEXT NOT NULL DEFAULT '',
            user_info TEXT NOT NULL DEFAULT '[]',
            unread_count INTEGER,
            message_count INTEGER,
            updated_at INTEGER,
            is_group INTEGER NOT NULL DEFAULT 0,
            is_archived INTEGER NOT NULL DEFAULT 0,
            folder TEXT,
            snippet TEXT,
            raw_json TEXT NOT NULL,
            synced_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            sender_id TEXT,
            body TEXT NOT NULL DEFAULT '',
            timestamp INTEGER,
            attachments TEXT NOT NULL DEFAULT '[]',
            mentions TEXT NOT NULL DEFAULT '{}',
            reactions TEXT NOT NULL DEFAULT '[]',
            kind TEXT,
            is_unread INTEGER NOT NULL DEFAULT 0,
            raw_json TEXT NOT NULL,
            synced_at INTEGER NOT NULL,
            FOREIGN KEY(thread_id) REFERENCES threads(thread_id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_thread_ts ON messages(thread_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
        CREATE VIRTUAL TABLE IF NOT EXISTS message_fts USING fts5(
            message_id UNINDEXED,
            thread_id UNINDEXED,
            sender_id,
            body,
            timestamp UNINDEXED
        );
        CREATE TABLE IF NOT EXISTS sync_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at INTEGER NOT NULL,
            completed_at INTEGER,
            threads INTEGER NOT NULL DEFAULT 0,
            messages INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            error TEXT
        );
        CREATE TABLE IF NOT EXISTS thread_history_state (
            thread_id TEXT PRIMARY KEY,
            complete INTEGER NOT NULL DEFAULT 0,
            earliest_message_at INTEGER,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS category_nodes (
            axis TEXT NOT NULL,
            path TEXT NOT NULL,
            label TEXT NOT NULL,
            parent_path TEXT,
            depth INTEGER NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            created_at INTEGER NOT NULL,
            PRIMARY KEY(axis, path)
        );
        CREATE TABLE IF NOT EXISTS thread_dimensions (
            thread_id TEXT PRIMARY KEY,
            folder TEXT NOT NULL,
            archive_state TEXT NOT NULL,
            thread_kind TEXT NOT NULL,
            participant_count INTEGER NOT NULL,
            participant_bucket TEXT NOT NULL,
            remote_message_count INTEGER,
            stored_message_count INTEGER NOT NULL,
            volume_bucket TEXT NOT NULL,
            history_state TEXT NOT NULL,
            activity_year INTEGER,
            activity_month INTEGER,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(thread_id) REFERENCES threads(thread_id)
        );
        CREATE TABLE IF NOT EXISTS message_dimensions (
            message_id TEXT PRIMARY KEY,
            thread_id TEXT NOT NULL,
            sender_id TEXT,
            sender_scope TEXT NOT NULL,
            message_kind TEXT NOT NULL,
            text_state TEXT NOT NULL,
            body_bucket TEXT NOT NULL,
            attachment_class TEXT NOT NULL,
            reaction_state TEXT NOT NULL,
            mention_state TEXT NOT NULL,
            sent_year INTEGER,
            sent_month INTEGER,
            sent_day INTEGER,
            sent_hour INTEGER,
            timestamp INTEGER,
            updated_at INTEGER NOT NULL,
            FOREIGN KEY(message_id) REFERENCES messages(message_id),
            FOREIGN KEY(thread_id) REFERENCES threads(thread_id)
        );
        CREATE TABLE IF NOT EXISTS thread_categories (
            thread_id TEXT NOT NULL,
            axis TEXT NOT NULL,
            path TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(thread_id, axis, path),
            FOREIGN KEY(thread_id) REFERENCES threads(thread_id)
        );
        CREATE TABLE IF NOT EXISTS message_categories (
            message_id TEXT NOT NULL,
            axis TEXT NOT NULL,
            path TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence REAL NOT NULL DEFAULT 1.0,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(message_id, axis, path),
            FOREIGN KEY(message_id) REFERENCES messages(message_id)
        );
        CREATE INDEX IF NOT EXISTS idx_category_nodes_axis_parent ON category_nodes(axis, parent_path);
        CREATE INDEX IF NOT EXISTS idx_thread_categories_axis_path ON thread_categories(axis, path, thread_id);
        CREATE INDEX IF NOT EXISTS idx_message_categories_axis_path ON message_categories(axis, path, message_id);
        CREATE INDEX IF NOT EXISTS idx_thread_dimensions_kind_time ON thread_dimensions(thread_kind, activity_year, activity_month);
        CREATE INDEX IF NOT EXISTS idx_message_dimensions_thread_time ON message_dimensions(thread_id, sent_year, sent_month, sent_day, sent_hour);
        CREATE INDEX IF NOT EXISTS idx_message_dimensions_attachment_time ON message_dimensions(attachment_class, sent_year, sent_month);
        CREATE VIEW IF NOT EXISTS v_thread_structured AS
            SELECT t.thread_id, t.name, t.participant_names, d.folder, d.archive_state, d.thread_kind,
                   d.participant_count, d.participant_bucket, d.remote_message_count,
                   d.stored_message_count, d.volume_bucket, d.history_state,
                   d.activity_year, d.activity_month, t.updated_at
            FROM threads t JOIN thread_dimensions d USING(thread_id);
        CREATE VIEW IF NOT EXISTS v_message_structured AS
            SELECT m.message_id, m.thread_id, d.sender_id, d.sender_scope, d.message_kind,
                   d.text_state, d.body_bucket, d.attachment_class, d.reaction_state,
                   d.mention_state, d.sent_year, d.sent_month, d.sent_day, d.sent_hour,
                   d.timestamp
            FROM messages m JOIN message_dimensions d USING(message_id);
        CREATE VIEW IF NOT EXISTS v_category_counts AS
            SELECT 'thread' AS scope, axis, path, COUNT(*) AS item_count
            FROM thread_categories GROUP BY axis, path
            UNION ALL
            SELECT 'message' AS scope, axis, path, COUNT(*) AS item_count
            FROM message_categories GROUP BY axis, path;
        "#,
    )
    .await?;
    Ok(())
}

async fn upsert_thread(conn: &Connection, thread: &ThreadRecord) -> Result<()> {
    let participant_names = thread
        .user_info
        .iter()
        .filter_map(|u| u.get("name").and_then(|v| v.as_str()))
        .collect::<Vec<_>>()
        .join(", ");
    let raw = serde_json::to_string(thread)?;
    conn.execute(
        r#"INSERT INTO threads (
            thread_id, name, participant_ids, participant_names, user_info, unread_count, message_count,
            updated_at, is_group, is_archived, folder, snippet, raw_json, synced_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
        ON CONFLICT(thread_id) DO UPDATE SET
            name=excluded.name,
            participant_ids=excluded.participant_ids,
            participant_names=excluded.participant_names,
            user_info=excluded.user_info,
            unread_count=excluded.unread_count,
            message_count=excluded.message_count,
            updated_at=excluded.updated_at,
            is_group=excluded.is_group,
            is_archived=excluded.is_archived,
            folder=excluded.folder,
            snippet=excluded.snippet,
            raw_json=excluded.raw_json,
            synced_at=excluded.synced_at"#,
        params![
            thread.thread_id.clone(),
            thread.thread_name.clone().unwrap_or_default(),
            serde_json::to_string(&thread.participant_ids)?,
            participant_names,
            serde_json::to_string(&thread.user_info)?,
            opt_i64(thread.unread_count),
            opt_i64(thread.message_count),
            parse_ts_millis(thread.timestamp.as_deref()),
            bool_i64(thread.is_group),
            bool_i64(thread.is_archived),
            thread.folder.clone().unwrap_or_default(),
            thread.snippet.clone().unwrap_or_default(),
            raw,
            now_ms(),
        ],
    )
    .await?;
    Ok(())
}

async fn upsert_message(conn: &Connection, message: &MessageRecord) -> Result<()> {
    let raw = serde_json::to_string(message)?;
    let ts = parse_ts_millis(message.timestamp.as_deref());
    let body = message.body.clone().unwrap_or_default();
    conn.execute(
        r#"INSERT INTO messages (
            message_id, thread_id, sender_id, body, timestamp, attachments, mentions, reactions, kind, is_unread, raw_json, synced_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
        ON CONFLICT(message_id) DO UPDATE SET
            thread_id=excluded.thread_id,
            sender_id=excluded.sender_id,
            body=excluded.body,
            timestamp=excluded.timestamp,
            attachments=excluded.attachments,
            mentions=excluded.mentions,
            reactions=excluded.reactions,
            kind=excluded.kind,
            is_unread=excluded.is_unread,
            raw_json=excluded.raw_json,
            synced_at=excluded.synced_at"#,
        params![
            message.message_id.clone(),
            message.thread_id.clone(),
            message.sender_id.clone().unwrap_or_default(),
            body,
            ts,
            serde_json::to_string(&message.attachments)?,
            serde_json::to_string(&message.mentions)?,
            serde_json::to_string(&message.reactions)?,
            message.kind.clone().unwrap_or_else(|| "message".into()),
            bool_i64(message.is_unread),
            raw,
            now_ms(),
        ],
    )
    .await?;
    conn.execute(
        "DELETE FROM message_fts WHERE message_id = ?1",
        params![message.message_id.clone()],
    )
    .await?;
    conn.execute(
        "INSERT INTO message_fts(message_id, thread_id, sender_id, body, timestamp) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            message.message_id.clone(),
            message.thread_id.clone(),
            message.sender_id.clone().unwrap_or_default(),
            message.body.clone().unwrap_or_default(),
            ts,
        ],
    )
    .await?;
    Ok(())
}

async fn call_bridge(cfg: &Config, command: &str, payload: JsonValue) -> Result<BridgeEnvelope> {
    let bridge = ensure_bridge(cfg).await?;
    let appstate = resolve_appstate_path(cfg).await?;
    call_bridge_process(cfg, &bridge, &appstate, command, payload).await
}

async fn call_bridge_with_appstate(
    cfg: &Config,
    appstate: &Path,
    command: &str,
    payload: JsonValue,
) -> Result<BridgeEnvelope> {
    let bridge = ensure_bridge(cfg).await?;
    call_bridge_process(cfg, &bridge, appstate, command, payload).await
}

async fn call_bridge_process(
    cfg: &Config,
    bridge: &Path,
    appstate: &Path,
    command: &str,
    payload: JsonValue,
) -> Result<BridgeEnvelope> {
    let output = Command::new(node_bin())
        .arg(bridge)
        .arg(command)
        .arg(serde_json::to_string(&bridge_context(cfg, appstate))?)
        .arg(serde_json::to_string(&payload)?)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .context(
            "failed to run Node bridge; ensure Node.js >= 20/22 and npm install are available",
        )?;
    if !output.status.success() {
        bail!(
            "bridge failed ({command}): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8(output.stdout)?;
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| anyhow!("bridge produced no JSON output"))?;
    let env: BridgeEnvelope = serde_json::from_str(line)?;
    if !env.ok {
        bail!("bridge error ({command}): {}", env.data);
    }
    Ok(env)
}

fn bridge_context(cfg: &Config, appstate: &Path) -> JsonValue {
    json!({
        "fcaDir": cfg.fca_dir,
        "appstate": appstate,
        "options": {
            "online": true,
            "selfListen": false,
            "listenEvents": true,
            "updatePresence": false,
            "autoMarkRead": false,
            "autoReconnect": true,
            "randomUserAgent": false
        }
    })
}

async fn resolve_appstate_path(cfg: &Config) -> Result<PathBuf> {
    match cfg.auth.method {
        AuthMethod::AppState => cfg
            .appstate
            .clone()
            .ok_or_else(|| anyhow!("auth.method=app-state requires appstate path")),
        AuthMethod::Browser => refresh_browser_appstate(cfg).await,
    }
}

async fn refresh_browser_appstate(cfg: &Config) -> Result<PathBuf> {
    let cache = cfg
        .auth
        .browser_appstate_cache
        .clone()
        .unwrap_or(project_dirs()?.data_dir().join("browser-appstate.json"));
    if let Some(parent) = cache.parent() {
        fs::create_dir_all(parent).await?;
    }

    let cookies =
        load_browser_cookies(cfg.auth.browser, cfg.auth.browser_profile.as_deref()).await?;
    let required = ["c_user", "xs"];
    for name in required {
        if !cookies
            .iter()
            .any(|c| c.key == name || c.name.as_deref() == Some(name))
        {
            bail!(
                "browser cookies did not include required Facebook cookie `{name}`; log into facebook.com in the selected browser profile first"
            );
        }
    }
    fs::write(&cache, serde_json::to_string_pretty(&cookies)?).await?;
    Ok(cache)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserCookie {
    key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    value: String,
    domain: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure: Option<bool>,
}

async fn load_browser_cookies(
    browser: BrowserKind,
    profile: Option<&str>,
) -> Result<Vec<BrowserCookie>> {
    let candidates = browser_cookie_candidates(browser, profile)?;
    let mut errors = Vec::new();
    for candidate in candidates {
        let result = match candidate.kind {
            BrowserKind::Firefox => load_firefox_cookies(&candidate.path).await,
            BrowserKind::Chrome
            | BrowserKind::Brave
            | BrowserKind::Edge
            | BrowserKind::Comet
            | BrowserKind::Chromium => load_chromium_cookies(candidate.kind, &candidate.path).await,
            BrowserKind::Auto => unreachable!("auto is expanded into concrete browser candidates"),
        };
        match result {
            Ok(cookies) if !cookies.is_empty() => return Ok(cookies),
            Ok(_) => errors.push(format!(
                "{} had no Facebook cookies",
                candidate.path.display()
            )),
            Err(err) => errors.push(format!("{}: {err:#}", candidate.path.display())),
        }
    }
    bail!(
        "could not load Facebook cookies from browser profiles. Tried:\n{}",
        errors.join("\n")
    )
}

#[derive(Debug, Clone)]
struct CookieDbCandidate {
    kind: BrowserKind,
    path: PathBuf,
}

fn browser_cookie_candidates(
    browser: BrowserKind,
    profile: Option<&str>,
) -> Result<Vec<CookieDbCandidate>> {
    let home = home_dir()?;
    let kinds: Vec<BrowserKind> = match browser {
        BrowserKind::Auto => vec![
            BrowserKind::Firefox,
            BrowserKind::Chrome,
            BrowserKind::Brave,
            BrowserKind::Edge,
            BrowserKind::Comet,
            BrowserKind::Chromium,
        ],
        other => vec![other],
    };
    let mut out = Vec::new();
    for kind in kinds {
        match kind {
            BrowserKind::Firefox => {
                for root in firefox_profile_roots(&home) {
                    collect_profile_cookie_dbs(kind, &root, profile, "cookies.sqlite", &mut out)?;
                }
            }
            BrowserKind::Chrome
            | BrowserKind::Brave
            | BrowserKind::Edge
            | BrowserKind::Comet
            | BrowserKind::Chromium => {
                for root in chromium_profile_roots(&home, kind) {
                    collect_chromium_cookie_dbs(kind, &root, profile, &mut out)?;
                }
            }
            BrowserKind::Auto => {}
        }
    }
    Ok(out)
}

fn firefox_profile_roots(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join("Library/Application Support/Firefox/Profiles"),
        home.join(".mozilla/firefox"),
    ]
}

fn chromium_profile_roots(home: &Path, kind: BrowserKind) -> Vec<PathBuf> {
    match kind {
        BrowserKind::Chrome => vec![
            home.join("Library/Application Support/Google/Chrome"),
            home.join(".config/google-chrome"),
        ],
        BrowserKind::Brave => vec![
            home.join("Library/Application Support/BraveSoftware/Brave-Browser"),
            home.join(".config/BraveSoftware/Brave-Browser"),
        ],
        BrowserKind::Edge => vec![
            home.join("Library/Application Support/Microsoft Edge"),
            home.join(".config/microsoft-edge"),
        ],
        BrowserKind::Comet => vec![
            home.join("Library/Application Support/Comet"),
            home.join(".config/Comet"),
            home.join(".config/comet"),
        ],
        BrowserKind::Chromium => vec![
            home.join("Library/Application Support/Chromium"),
            home.join(".config/chromium"),
        ],
        BrowserKind::Auto | BrowserKind::Firefox => vec![],
    }
}

fn collect_profile_cookie_dbs(
    kind: BrowserKind,
    root: &Path,
    profile: Option<&str>,
    cookie_file: &str,
    out: &mut Vec<CookieDbCandidate>,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !profile_matches(&path, profile) {
            continue;
        }
        let db = path.join(cookie_file);
        if db.exists() {
            out.push(CookieDbCandidate { kind, path: db });
        }
    }
    Ok(())
}

fn collect_chromium_cookie_dbs(
    kind: BrowserKind,
    root: &Path,
    profile: Option<&str>,
    out: &mut Vec<CookieDbCandidate>,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let profile_names = if let Some(profile) = profile {
        vec![profile.to_string()]
    } else {
        vec![
            "Default".into(),
            "Profile 1".into(),
            "Profile 2".into(),
            "Profile 3".into(),
        ]
    };
    for name in profile_names {
        let profile_dir = root.join(&name);
        for db in [
            profile_dir.join("Network/Cookies"),
            profile_dir.join("Cookies"),
        ] {
            if db.exists() {
                out.push(CookieDbCandidate { kind, path: db });
            }
        }
    }
    if profile.is_some() {
        return Ok(());
    }
    for entry in std::fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || !profile_matches(&path, profile) {
            continue;
        }
        for db in [path.join("Network/Cookies"), path.join("Cookies")] {
            if db.exists() && !out.iter().any(|c| c.path == db) {
                out.push(CookieDbCandidate { kind, path: db });
            }
        }
    }
    Ok(())
}

fn profile_matches(path: &Path, profile: Option<&str>) -> bool {
    let Some(profile) = profile else {
        return true;
    };
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == profile || name.contains(profile))
        .unwrap_or(false)
}

async fn copy_cookie_db(path: &Path) -> Result<PathBuf> {
    let dir = project_dirs()?.cache_dir().join("cookie-db");
    fs::create_dir_all(&dir).await?;
    let file_name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("cookies.sqlite");
    let copy = dir.join(format!("{}-{}", now_ms(), file_name));
    fs::copy(path, &copy)
        .await
        .with_context(|| format!("copy cookie DB {}", path.display()))?;
    Ok(copy)
}

async fn load_firefox_cookies(path: &Path) -> Result<Vec<BrowserCookie>> {
    let copy = copy_cookie_db(path).await?;
    let db = Builder::new_local(copy.to_string_lossy().to_string())
        .build()
        .await?;
    let conn = db.connect()?;
    let mut rows = conn
        .query(
            "SELECT name, value, host, path, expiry, isSecure FROM moz_cookies WHERE host LIKE '%facebook.com' OR host LIKE '%messenger.com'",
            (),
        )
        .await?;
    let mut cookies = Vec::new();
    while let Some(row) = rows.next().await? {
        let key: String = row.get(0)?;
        let value: String = row.get(1)?;
        if value.is_empty() {
            continue;
        }
        cookies.push(BrowserCookie {
            name: Some(key.clone()),
            key,
            value,
            domain: row.get(2)?,
            path: row.get::<Option<String>>(3)?.unwrap_or_else(|| "/".into()),
            expires: row.get::<Option<i64>>(4)?.map(|seconds| seconds * 1000),
            secure: row.get::<Option<i64>>(5)?.map(|v| v != 0),
        });
    }
    Ok(dedupe_cookies(cookies))
}

async fn load_chromium_cookies(kind: BrowserKind, path: &Path) -> Result<Vec<BrowserCookie>> {
    let copy = copy_cookie_db(path).await?;
    let db = Builder::new_local(copy.to_string_lossy().to_string())
        .build()
        .await?;
    let conn = db.connect()?;
    let mut rows = conn
        .query(
            "SELECT name, value, host_key, path, expires_utc, is_secure, encrypted_value FROM cookies WHERE host_key LIKE '%facebook.com' OR host_key LIKE '%messenger.com'",
            (),
        )
        .await?;
    let mut cookies = Vec::new();
    let mut decrypt_key: Option<Vec<u8>> = None;
    while let Some(row) = rows.next().await? {
        let key: String = row.get(0)?;
        let mut value: String = row.get::<Option<String>>(1)?.unwrap_or_default();
        let domain: String = row.get(2)?;
        if value.is_empty() {
            let encrypted: Vec<u8> = row.get::<Option<Vec<u8>>>(6)?.unwrap_or_default();
            if !encrypted.is_empty() {
                let key_bytes = match &decrypt_key {
                    Some(key) => key.clone(),
                    None => {
                        let key = chromium_decrypt_key(kind)?;
                        decrypt_key = Some(key.clone());
                        key
                    }
                };
                value = decrypt_chromium_cookie(&encrypted, &key_bytes, &domain).with_context(
                    || format!("decrypt Chromium cookie `{key}` from {}", path.display()),
                )?;
            }
        }
        if value.is_empty() {
            continue;
        }
        cookies.push(BrowserCookie {
            name: Some(key.clone()),
            key,
            value,
            domain,
            path: row.get::<Option<String>>(3)?.unwrap_or_else(|| "/".into()),
            expires: row.get::<Option<i64>>(4)?.and_then(chromium_time_to_ms),
            secure: row.get::<Option<i64>>(5)?.map(|v| v != 0),
        });
    }
    Ok(dedupe_cookies(cookies))
}

fn dedupe_cookies(cookies: Vec<BrowserCookie>) -> Vec<BrowserCookie> {
    let mut map = BTreeMap::new();
    for cookie in cookies {
        map.insert(
            (
                cookie.domain.clone(),
                cookie.path.clone(),
                cookie.key.clone(),
            ),
            cookie,
        );
    }
    map.into_values().collect()
}

fn chromium_time_to_ms(chrome_time: i64) -> Option<i64> {
    if chrome_time <= 0 {
        return None;
    }
    Some((chrome_time / 1000) - 11_644_473_600_000)
}

fn chromium_decrypt_key(kind: BrowserKind) -> Result<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        let service = match kind {
            BrowserKind::Chrome => "Chrome Safe Storage",
            BrowserKind::Brave => "Brave Safe Storage",
            BrowserKind::Edge => "Microsoft Edge Safe Storage",
            BrowserKind::Comet => "Comet Safe Storage",
            BrowserKind::Chromium => "Chromium Safe Storage",
            BrowserKind::Auto | BrowserKind::Firefox => "Chrome Safe Storage",
        };
        let output = StdCommand::new("security")
            .args(["find-generic-password", "-w", "-s", service])
            .output()
            .with_context(|| format!("read macOS Keychain item `{service}`"))?;
        if !output.status.success() {
            bail!(
                "could not read macOS Keychain item `{service}`; allow terminal Keychain access or use Firefox/appstate auth"
            );
        }
        let password = String::from_utf8(output.stdout)?.trim_end().to_string();
        let mut key = [0u8; 16];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), b"saltysalt", 1003, &mut key);
        Ok(key.to_vec())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = kind;
        bail!("encrypted Chromium cookie decryption is currently implemented for macOS; use Firefox or appstate auth")
    }
}

fn decrypt_chromium_cookie(encrypted: &[u8], key: &[u8], host_key: &str) -> Result<String> {
    if encrypted.starts_with(b"v10") || encrypted.starts_with(b"v11") {
        let iv = [b' '; 16];
        let cipher = Aes128CbcDec::new_from_slices(key, &iv)?;
        let mut buf = encrypted[3..].to_vec();
        let plaintext = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|err| anyhow!("invalid Chromium cookie padding: {err:?}"))?;
        return chromium_plaintext_to_string(plaintext.to_vec(), host_key);
    }
    Ok(String::from_utf8(encrypted.to_vec())?)
}

fn chromium_plaintext_to_string(mut plaintext: Vec<u8>, host_key: &str) -> Result<String> {
    if plaintext.len() > 32 {
        let host_hash = Sha256::digest(host_key.as_bytes());
        if plaintext[..32] == host_hash[..] {
            plaintext.drain(..32);
        }
    }
    Ok(String::from_utf8(plaintext)?)
}

async fn ensure_bridge(cfg: &Config) -> Result<PathBuf> {
    let dir = project_dirs()?.cache_dir().join("bridge");
    fs::create_dir_all(&dir).await?;
    let path = dir.join("fbm-bridge.js");
    fs::write(&path, BRIDGE_SOURCE).await?;
    if !cfg.fca_dir.join("node_modules").exists() {
        eprintln!(
            "warning: node_modules not found under {}; run npm install if bridge commands fail",
            cfg.fca_dir.display()
        );
    }
    Ok(path)
}

async fn export_json(conn: &Connection, thread_id: Option<&str>) -> Result<JsonValue> {
    let mut sql = "SELECT raw_json FROM threads".to_string();
    if thread_id.is_some() {
        sql.push_str(" WHERE thread_id = ?1");
    }
    sql.push_str(" ORDER BY COALESCE(updated_at, 0) DESC");
    let mut rows = if let Some(id) = thread_id {
        conn.query(&sql, params![id]).await?
    } else {
        conn.query(&sql, ()).await?
    };
    let mut threads = Vec::new();
    while let Some(row) = rows.next().await? {
        let raw: String = row.get(0)?;
        let mut thread: JsonValue = serde_json::from_str(&raw)?;
        let id = thread
            .get("threadID")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let mut msg_rows = conn
            .query("SELECT raw_json FROM messages WHERE thread_id = ?1 ORDER BY COALESCE(timestamp, 0) ASC", params![id])
            .await?;
        let mut messages = Vec::new();
        while let Some(msg_row) = msg_rows.next().await? {
            let raw: String = msg_row.get(0)?;
            messages.push(serde_json::from_str::<JsonValue>(&raw)?);
        }
        thread["messages"] = JsonValue::Array(messages);
        threads.push(thread);
    }
    Ok(json!({ "exported_at": now_ms(), "threads": threads }))
}

async fn export_markdown(conn: &Connection, thread_id: Option<&str>) -> Result<String> {
    let data = export_json(conn, thread_id).await?;
    let mut md = String::from("# Facebook Messenger export\n\n");
    if let Some(threads) = data.get("threads").and_then(|v| v.as_array()) {
        for thread in threads {
            let id = thread
                .get("threadID")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let name = thread
                .get("threadName")
                .or_else(|| thread.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or(id);
            md.push_str(&format!("## {name} (`{id}`)\n\n"));
            if let Some(messages) = thread.get("messages").and_then(|v| v.as_array()) {
                for msg in messages {
                    let time = fmt_ts(parse_ts_millis(
                        msg.get("timestamp").and_then(|v| v.as_str()),
                    ));
                    let sender = msg.get("senderID").and_then(|v| v.as_str()).unwrap_or("");
                    let body = msg.get("body").and_then(|v| v.as_str()).unwrap_or("");
                    md.push_str(&format!("- **{time}** `{sender}`: {body}\n"));
                }
            }
            md.push('\n');
        }
    }
    Ok(md)
}

async fn db_counts(conn: &Connection) -> Result<(i64, i64)> {
    let threads = scalar_i64(conn, "SELECT COUNT(*) FROM threads").await?;
    let messages = scalar_i64(conn, "SELECT COUNT(*) FROM messages").await?;
    Ok((threads, messages))
}

async fn scalar_i64(conn: &Connection, sql: &str) -> Result<i64> {
    let mut rows = conn.query(sql, ()).await?;
    Ok(rows
        .next()
        .await?
        .map(|r| r.get::<i64>(0).unwrap_or(0))
        .unwrap_or(0))
}

async fn thread_message_count(conn: &Connection, thread_id: &str) -> Result<Option<i64>> {
    let mut rows = conn
        .query(
            "SELECT message_count FROM threads WHERE thread_id = ?1",
            params![thread_id],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .and_then(|row| row.get::<Option<i64>>(0).ok().flatten()))
}

async fn stored_message_count(conn: &Connection, thread_id: &str) -> Result<i64> {
    let mut rows = conn
        .query(
            "SELECT COUNT(*) FROM messages WHERE thread_id = ?1",
            params![thread_id],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .map(|row| row.get::<i64>(0).unwrap_or(0))
        .unwrap_or(0))
}

async fn earliest_message_timestamp(conn: &Connection, thread_id: &str) -> Result<Option<i64>> {
    let mut rows = conn
        .query(
            "SELECT MIN(timestamp) FROM messages WHERE thread_id = ?1",
            params![thread_id],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .and_then(|row| row.get::<Option<i64>>(0).ok().flatten()))
}

async fn is_thread_history_marked_complete(conn: &Connection, thread_id: &str) -> Result<bool> {
    let mut rows = conn
        .query(
            "SELECT complete FROM thread_history_state WHERE thread_id = ?1",
            params![thread_id],
        )
        .await?;
    Ok(rows
        .next()
        .await?
        .and_then(|row| row.get::<i64>(0).ok())
        .is_some_and(|complete| complete != 0))
}

async fn mark_thread_history_state(
    conn: &Connection,
    thread_id: &str,
    earliest_message_at: Option<i64>,
    complete: bool,
) -> Result<()> {
    conn.execute(
        r#"INSERT INTO thread_history_state (thread_id, complete, earliest_message_at, updated_at)
           VALUES (?1, ?2, ?3, ?4)
           ON CONFLICT(thread_id) DO UPDATE SET
             complete=excluded.complete,
             earliest_message_at=COALESCE(excluded.earliest_message_at, thread_history_state.earliest_message_at),
             updated_at=excluded.updated_at"#,
        params![thread_id, if complete { 1 } else { 0 }, earliest_message_at, now_ms()],
    )
    .await?;
    Ok(())
}

fn config_path(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = explicit {
        Ok(path.to_path_buf())
    } else {
        Ok(project_dirs()?.config_dir().join("config.toml"))
    }
}

fn project_dirs() -> Result<AppDirs> {
    let home = home_dir()?;
    #[cfg(target_os = "macos")]
    {
        let base = home.join(format!("Library/Application Support/dev.fbm.{APP_NAME}"));
        Ok(AppDirs {
            config: base.clone(),
            data: base.clone(),
            cache: home.join(format!("Library/Caches/dev.fbm.{APP_NAME}")),
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let config = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join(APP_NAME);
        let data = env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join(APP_NAME);
        let cache = env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".cache"))
            .join(APP_NAME);
        Ok(AppDirs {
            config,
            data,
            cache,
        })
    }
}

fn home_dir() -> Result<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| anyhow!("could not determine home directory"))
}

async fn load_config(path: &Path) -> Result<Config> {
    let text = fs::read_to_string(path).await.with_context(|| {
        format!(
            "missing config {}; run `fbm init --appstate <appstate.json>`",
            path.display()
        )
    })?;
    Ok(toml::from_str(&text)?)
}

fn print_json_or_table(json_output: bool, json_value: JsonValue, text: String) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(&json_value)?);
    } else {
        println!("{text}");
    }
    Ok(())
}

fn node_bin() -> &'static OsStr {
    OsStr::new("node")
}

fn now_ms() -> i64 {
    now_ms_std()
}

fn now_ms_std() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or_default()
}

fn opt_i64(v: Option<i64>) -> Option<i64> {
    v
}

fn bool_i64(v: Option<bool>) -> i64 {
    if v.unwrap_or(false) {
        1
    } else {
        0
    }
}

fn parse_ts_millis(raw: Option<&str>) -> Option<i64> {
    let raw = raw?;
    if let Ok(v) = raw.parse::<i64>() {
        return Some(if raw.len() <= 10 { v * 1000 } else { v });
    }
    parse_rfc3339_utc_millis(raw)
}

fn fmt_ts(ts: Option<i64>) -> String {
    ts.map(format_utc_millis).unwrap_or_default()
}

fn print_rows<T: Serialize>(rows: &[T]) -> Result<()> {
    if rows.is_empty() {
        println!("(no rows)");
        return Ok(());
    }
    let values = rows
        .iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let headers = values
        .first()
        .and_then(|value| value.as_object())
        .map(|object| object.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if headers.is_empty() {
        for value in values {
            println!("{value}");
        }
        return Ok(());
    }
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    let mut cells = Vec::new();
    for value in values {
        let object = value.as_object().context("row was not a JSON object")?;
        let row = headers
            .iter()
            .map(|header| json_cell(object.get(header).unwrap_or(&JsonValue::Null)))
            .collect::<Vec<_>>();
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.chars().count());
        }
        cells.push(row);
    }
    print_table_line(&headers, &widths);
    let divider = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>();
    print_table_line(&divider, &widths);
    for row in cells {
        print_table_line(&row, &widths);
    }
    Ok(())
}

fn print_table_line(cells: &[String], widths: &[usize]) {
    let line = cells
        .iter()
        .enumerate()
        .map(|(idx, cell)| format!("{cell:<width$}", width = widths[idx]))
        .collect::<Vec<_>>()
        .join("  ");
    println!("{line}");
}

fn json_cell(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => String::new(),
        JsonValue::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn parse_rfc3339_utc_millis(raw: &str) -> Option<i64> {
    if raw.len() < 20 || !raw.ends_with('Z') {
        return None;
    }
    let year = raw.get(0..4)?.parse::<i32>().ok()?;
    let month = raw.get(5..7)?.parse::<u32>().ok()?;
    let day = raw.get(8..10)?.parse::<u32>().ok()?;
    let hour = raw.get(11..13)?.parse::<u32>().ok()?;
    let minute = raw.get(14..16)?.parse::<u32>().ok()?;
    let second = raw.get(17..19)?.parse::<u32>().ok()?;
    let days = days_from_civil(year, month, day)?;
    Some((((days * 24 + hour as i64) * 60 + minute as i64) * 60 + second as i64) * 1000)
}

fn format_utc_millis(ts: i64) -> String {
    let (year, month, day, hour) = utc_parts(ts);
    let total_seconds = ts.div_euclid(1000);
    let second_of_day = total_seconds.rem_euclid(86_400);
    let minute = (second_of_day % 3600) / 60;
    let second = second_of_day % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn utc_parts(ts: i64) -> (i32, u32, u32, u32) {
    let total_seconds = ts.div_euclid(1000);
    let days = total_seconds.div_euclid(86_400);
    let second_of_day = total_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (second_of_day / 3600) as u32;
    (year, month, day, hour)
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    (year as i32, m as u32, d as u32)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = year as i64 - if month <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = month as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn truncate(s: &str, max: usize) -> String {
    let mut chars = s.chars();
    let out: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{out}…")
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Result<Self> {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            let seq = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                env::temp_dir().join(format!("fbm-test-{}-{nonce}-{seq}", std::process::id()));
            std::fs::create_dir_all(&path)?;
            Ok(Self(path))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn parses_ms_and_seconds_timestamps() {
        assert_eq!(parse_ts_millis(Some("1710000000000")), Some(1710000000000));
        assert_eq!(parse_ts_millis(Some("1710000000")), Some(1710000000000));
    }

    #[test]
    fn truncates_unicode_safely() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("😀😀😀", 2), "😀😀…");
    }

    #[test]
    fn comet_roots_include_local_application_support_path() {
        let home = Path::new("/Users/example");
        let roots = chromium_profile_roots(home, BrowserKind::Comet);
        assert!(roots.contains(&PathBuf::from(
            "/Users/example/Library/Application Support/Comet"
        )));
    }

    #[test]
    fn all_sync_expands_default_tags_to_reachable_folder_groups() {
        assert_eq!(
            sync_tag_groups(true, &["INBOX".to_string()]),
            vec![
                vec!["INBOX".to_string()],
                vec!["ARCHIVED".to_string()],
                vec!["OTHER".to_string()],
                vec!["PENDING".to_string()],
                vec!["SPAM".to_string()],
            ]
        );
        assert_eq!(
            sync_tag_groups(false, &["INBOX".to_string()]),
            vec![vec!["INBOX".to_string()]]
        );
        assert_eq!(
            sync_tag_groups(true, &["PENDING".to_string()]),
            vec![vec!["PENDING".to_string()]]
        );
    }

    #[test]
    fn thread_pagination_cursor_uses_oldest_timestamp_minus_one() {
        let threads = vec![
            ThreadRecord {
                thread_id: "new".into(),
                thread_name: None,
                participant_ids: vec![],
                user_info: vec![],
                unread_count: None,
                message_count: None,
                timestamp: Some("2000000000000".into()),
                is_group: None,
                is_archived: None,
                folder: None,
                snippet: None,
                raw_extra: BTreeMap::new(),
            },
            ThreadRecord {
                thread_id: "old".into(),
                thread_name: None,
                participant_ids: vec![],
                user_info: vec![],
                unread_count: None,
                message_count: None,
                timestamp: Some("1000000000000".into()),
                is_group: None,
                is_archived: None,
                folder: None,
                snippet: None,
                raw_extra: BTreeMap::new(),
            },
        ];
        assert_eq!(next_thread_before(&threads), Some(999999999999));
    }

    #[test]
    fn history_complete_uses_remote_message_count_when_available() {
        assert!(is_history_complete(Some(10), 10));
        assert!(is_history_complete(Some(10), 12));
        assert!(!is_history_complete(Some(10), 9));
        assert!(!is_history_complete(None, 999));
    }

    #[test]
    fn zero_max_pages_means_unbounded_history() {
        assert!(should_continue_history(true, 100, 0, 200, 200));
        assert!(!should_continue_history(true, 25, 25, 200, 200));
        assert!(!should_continue_history(false, 1, 0, 200, 200));
        assert!(!should_continue_history(true, 1, 0, 199, 200));
    }

    #[test]
    fn strips_chromium_host_hash_cookie_prefix() -> Result<()> {
        let mut plaintext = Sha256::digest(b".facebook.com").to_vec();
        plaintext.extend_from_slice(b"cookie-value");
        assert_eq!(
            chromium_plaintext_to_string(plaintext, ".facebook.com")?,
            "cookie-value"
        );
        Ok(())
    }

    #[test]
    fn thread_record_allows_thread_name_and_raw_name() -> Result<()> {
        let thread: ThreadRecord = serde_json::from_value(json!({
            "threadID": "t1",
            "threadName": "Primary",
            "name": "Raw duplicate",
            "participantIDs": [],
            "userInfo": []
        }))?;
        assert_eq!(thread.thread_name.as_deref(), Some("Primary"));
        assert!(thread.raw_extra.contains_key("name"));
        Ok(())
    }

    #[test]
    fn category_helpers_are_hierarchical_and_orthogonal() {
        assert_eq!(participant_bucket(1), "1_or_less");
        assert_eq!(participant_bucket(2), "2");
        assert_eq!(participant_bucket(8), "6_10");
        assert_eq!(count_bucket(1_500), "1000_plus");
        assert_eq!(body_length_bucket(""), "0");
        assert_eq!(body_length_bucket("hello"), "1_80");
        assert_eq!(attachment_class(r#"[{"type":"photo"}]"#), "photo");
        assert_eq!(
            attachment_class(r#"[{"type":"video"},{"type":"photo"}]"#),
            "mixed"
        );
        assert_eq!(
            time_path(1_710_000_000_000, TimeDepth::Hour).as_deref(),
            Some("time/2024/03/09/16")
        );
        assert_eq!(
            category_ancestors("time/2024/03"),
            vec!["time", "time/2024", "time/2024/03"]
        );
    }

    #[tokio::test]
    async fn categorizes_threads_and_messages_into_queryable_facets() -> Result<()> {
        let dir = TestDir::new()?;
        let db = Builder::new_local(dir.path().join("test.db").to_string_lossy().to_string())
            .build()
            .await?;
        let conn = db.connect()?;
        migrate(&conn).await?;

        let thread = ThreadRecord {
            thread_id: "t1".into(),
            thread_name: Some("Test Thread".into()),
            participant_ids: vec!["u1".into(), "u2".into(), "u3".into()],
            user_info: vec![],
            unread_count: Some(0),
            message_count: Some(2),
            timestamp: Some("1710000000000".into()),
            is_group: Some(true),
            is_archived: Some(false),
            folder: Some("INBOX".into()),
            snippet: None,
            raw_extra: BTreeMap::new(),
        };
        upsert_thread(&conn, &thread).await?;
        mark_thread_history_state(&conn, "t1", Some(1710000000000), true).await?;

        let message = MessageRecord {
            message_id: "m1".into(),
            thread_id: "t1".into(),
            sender_id: Some("u1".into()),
            body: Some("hello structured archive".into()),
            timestamp: Some("1710000000000".into()),
            attachments: vec![json!({"type":"photo", "ID":"a1"})],
            mentions: json!({}),
            reactions: vec![json!({"reaction":"❤"})],
            is_unread: Some(false),
            is_group: Some(true),
            kind: Some("message".into()),
            raw_extra: BTreeMap::new(),
        };
        upsert_message(&conn, &message).await?;

        let summary = refresh_structured_categories(&conn).await?;
        assert_eq!(summary.threads, 1);
        assert_eq!(summary.messages, 1);
        assert!(summary.category_nodes >= 10);

        let mut rows = conn
            .query(
                "SELECT axis, path FROM message_categories WHERE message_id = ?1 ORDER BY axis, path",
                params!["m1"],
            )
            .await?;
        let mut facets = Vec::new();
        while let Some(row) = rows.next().await? {
            facets.push((row.get::<String>(0)?, row.get::<String>(1)?));
        }
        assert!(facets.contains(&("message.attachment".into(), "attachment/photo".into())));
        assert!(facets.contains(&("message.reactions".into(), "reactions/present".into())));
        assert!(facets.contains(&("time.sent".into(), "time/2024/03/09/16".into())));

        let mut rows = conn
            .query(
                "SELECT path, parent_path FROM category_nodes WHERE axis = 'time.sent' AND path = 'time/2024/03/09/16'",
                params![],
            )
            .await?;
        let row = rows.next().await?.expect("time category");
        assert_eq!(row.get::<String>(0)?, "time/2024/03/09/16");
        assert_eq!(
            row.get::<Option<String>>(1)?.as_deref(),
            Some("time/2024/03/09")
        );

        Ok(())
    }

    #[tokio::test]
    async fn imports_firefox_cookie_db_as_appstate() -> Result<()> {
        let dir = TestDir::new()?;
        let db_path = dir.path().join("cookies.sqlite");
        let db = Builder::new_local(db_path.to_string_lossy().to_string())
            .build()
            .await?;
        let conn = db.connect()?;
        conn.execute_batch(
            r#"
            CREATE TABLE moz_cookies (
                name TEXT,
                value TEXT,
                host TEXT,
                path TEXT,
                expiry INTEGER,
                isSecure INTEGER
            );
            INSERT INTO moz_cookies VALUES ('c_user', '123', '.facebook.com', '/', 2000000000, 1);
            INSERT INTO moz_cookies VALUES ('xs', 'token', '.facebook.com', '/', 2000000000, 1);
            INSERT INTO moz_cookies VALUES ('other', 'ignored', '.example.com', '/', 2000000000, 0);
            "#,
        )
        .await?;
        drop(conn);
        drop(db);

        let cookies = load_firefox_cookies(&db_path).await?;
        assert_eq!(cookies.len(), 2);
        assert!(cookies
            .iter()
            .any(|c| c.key == "c_user" && c.value == "123"));
        assert!(cookies.iter().any(|c| c.key == "xs" && c.value == "token"));
        Ok(())
    }

    #[tokio::test]
    async fn stores_and_searches_messages() -> Result<()> {
        let dir = TestDir::new()?;
        let db = Builder::new_local(dir.path().join("test.db").to_string_lossy().to_string())
            .build()
            .await?;
        let conn = db.connect()?;
        migrate(&conn).await?;

        let thread = ThreadRecord {
            thread_id: "t1".into(),
            thread_name: Some("Test Thread".into()),
            participant_ids: vec!["u1".into(), "u2".into()],
            user_info: vec![json!({"id":"u1","name":"Alice"})],
            unread_count: Some(0),
            message_count: Some(1),
            timestamp: Some("1710000000000".into()),
            is_group: Some(false),
            is_archived: Some(false),
            folder: Some("INBOX".into()),
            snippet: Some("hello archive".into()),
            raw_extra: BTreeMap::new(),
        };
        upsert_thread(&conn, &thread).await?;

        let message = MessageRecord {
            message_id: "m1".into(),
            thread_id: "t1".into(),
            sender_id: Some("u1".into()),
            body: Some("hello searchable archive".into()),
            timestamp: Some("1710000000000".into()),
            attachments: vec![],
            mentions: json!({}),
            reactions: vec![],
            is_unread: Some(false),
            is_group: Some(false),
            kind: Some("message".into()),
            raw_extra: BTreeMap::new(),
        };
        upsert_message(&conn, &message).await?;

        let (threads, messages) = db_counts(&conn).await?;
        assert_eq!((threads, messages), (1, 1));

        mark_thread_history_state(&conn, "t1", Some(1710000000000), true).await?;
        assert!(is_thread_history_marked_complete(&conn, "t1").await?);

        let mut rows = conn
            .query(
                "SELECT message_id, body FROM message_fts WHERE message_fts MATCH ?1",
                params!["searchable"],
            )
            .await?;
        let row = rows.next().await?.expect("FTS row");
        assert_eq!(row.get::<String>(0)?, "m1");
        assert_eq!(row.get::<String>(1)?, "hello searchable archive");
        Ok(())
    }
}
