//! Hacker News virtual SMB filesystem example.
//!
//! This mirrors GoSMB's `examples/hnfs`: a read-only share backed by the
//! Hacker News Firebase API. The backend is intentionally an example, not a
//! built-in server dependency.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use smb_server::{
    Access, BackendCapabilities, DirEntry, FileInfo, FileTimes, Handle, OpenIntent, OpenOptions,
    Share, ShareBackend, SmbError, SmbPath, SmbResult, SmbServer,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
const FILETIME_OFFSET: u64 = 116_444_736_000_000_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,smb_server=debug,hnfs_smb_example=debug".into()),
        )
        .init();

    let listen = env_or("SMB_LISTEN", "127.0.0.1:1445").parse()?;
    let share_name = env_or("SMB_SHARE", "HN");
    let limit = env_or("HNFS_LIMIT", "30").parse().unwrap_or(30);
    let cache_ttl = Duration::from_secs(env_or("HNFS_CACHE_TTL_SECS", "60").parse().unwrap_or(60));
    let allow_guest = env_bool("HNFS_GUEST", true);
    let user = std::env::var("HNFS_USER").ok();
    let password = std::env::var("HNFS_PASSWORD").unwrap_or_else(|_| "hn".into());

    let mut builder = SmbServer::builder().listen(listen);
    if let Some(user) = user.as_deref() {
        builder = builder.user(user, &password);
    }

    let share = Share::new(&share_name, HnFs::new(limit, cache_ttl));
    builder = builder.share(if allow_guest {
        share.public_read_only()
    } else if let Some(user) = user.as_deref() {
        share.user(user, Access::Read)
    } else {
        return Err("HNFS_GUEST=false requires HNFS_USER".into());
    });

    let server = builder.build()?;
    let addr = server.bind().await?;
    tracing::info!(%addr, share = %share_name, limit, "serving Hacker News VFS");
    server.serve().await?;
    Ok(())
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => default,
    }
}

#[derive(Clone)]
struct HnFs {
    client: HnClient,
    limit: usize,
}

impl HnFs {
    fn new(limit: usize, cache_ttl: Duration) -> Self {
        Self {
            client: HnClient::new(cache_ttl),
            limit: limit.max(1),
        }
    }

    async fn read_file(&self, path: &SmbPath) -> SmbResult<Bytes> {
        let components = path.components();
        match components {
            [] => Err(SmbError::IsDirectory),
            [name] if name == "README.txt" => Ok(Bytes::from_static(README_TEXT.as_bytes())),
            [list, file] if is_list_dir(list) => self.read_story_file(file).await,
            [dir, file] if dir == "item" && file.ends_with(".json") => {
                let id = file
                    .trim_end_matches(".json")
                    .parse::<u64>()
                    .map_err(|_| SmbError::NotFound)?;
                let item = self.client.item(id).await?;
                pretty_json(&item).map(Bytes::from)
            }
            [dir, file] if dir == "user" && file.ends_with(".json") => {
                let id = file.trim_end_matches(".json");
                if id.is_empty() {
                    return Err(SmbError::NotFound);
                }
                let user = self.client.user(id).await?;
                pretty_json(&user).map(Bytes::from)
            }
            _ => Err(SmbError::NotFound),
        }
    }

    async fn read_story_file(&self, file_name: &str) -> SmbResult<Bytes> {
        let ext = file_name
            .rsplit_once('.')
            .map(|(_, ext)| ext)
            .ok_or(SmbError::NotFound)?;
        if !matches!(ext, "txt" | "url" | "json") {
            return Err(SmbError::NotFound);
        }
        let id = story_id(file_name).ok_or(SmbError::NotFound)?;
        let item = self.client.item(id).await?;
        match ext {
            "url" => {
                let target = story_url(&item);
                Ok(Bytes::from(format!("{target}\n")))
            }
            "json" => pretty_json(&item).map(Bytes::from),
            _ => Ok(Bytes::from(story_text(&item))),
        }
    }

    async fn list_entries(&self, path: &SmbPath) -> SmbResult<Vec<DirEntry>> {
        let entries = match path.components() {
            [] => ROOT_ENTRIES
                .iter()
                .map(|(name, is_dir)| self.info_for(name, 0, *is_dir))
                .collect(),
            [name] if is_list_dir(name) => {
                let stories = self.stories(name).await?;
                let mut entries = Vec::with_capacity(stories.len() * 3);
                for (idx, item) in stories.iter().enumerate() {
                    let prefix = story_prefix(idx + 1, item);
                    entries.push(self.info_for(&format!("{prefix}.txt"), 0, false));
                    entries.push(self.info_for(&format!("{prefix}.url"), 0, false));
                    entries.push(self.info_for(&format!("{prefix}.json"), 0, false));
                }
                entries
            }
            [name] if name == "item" || name == "user" => Vec::new(),
            _ => return Err(SmbError::NotADirectory),
        };
        let mut entries: Vec<_> = entries.into_iter().map(|info| DirEntry { info }).collect();
        entries.sort_by(|a, b| a.info.name.cmp(&b.info.name));
        Ok(entries)
    }

    async fn stories(&self, list_name: &str) -> SmbResult<Vec<HnItem>> {
        let ids = self.client.story_ids(list_name).await?;
        let mut stories = Vec::new();
        for id in ids.into_iter().take(self.limit) {
            if let Ok(item) = self.client.item(id).await
                && item.id != 0
            {
                stories.push(item);
            }
        }
        Ok(stories)
    }

    fn is_dir(&self, path: &SmbPath) -> bool {
        match path.components() {
            [] => true,
            [name] => is_list_dir(name) || name == "item" || name == "user",
            _ => false,
        }
    }

    fn info_for(&self, name: &str, size: u64, is_directory: bool) -> FileInfo {
        let now = filetime(SystemTime::now());
        let attributes = if is_directory {
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE
        };
        FileInfo {
            name: name.rsplit(['\\', '/']).next().unwrap_or(name).to_string(),
            end_of_file: if is_directory { 0 } else { size },
            allocation_size: if is_directory { 0 } else { size },
            creation_time: FILETIME_OFFSET,
            last_access_time: now,
            last_write_time: now,
            change_time: now,
            is_directory,
            file_index: stable_id(name),
            file_attributes: attributes,
        }
    }
}

#[async_trait]
impl ShareBackend for HnFs {
    async fn open(&self, path: &SmbPath, opts: OpenOptions) -> SmbResult<Box<dyn Handle>> {
        if opts.write
            || opts.delete_on_close
            || !matches!(opts.intent, OpenIntent::Open)
            || opts.read && opts.directory && opts.non_directory
        {
            return Err(SmbError::AccessDenied);
        }

        let is_dir = self.is_dir(path);
        if opts.directory && !is_dir {
            return Err(SmbError::NotADirectory);
        }
        if opts.non_directory && is_dir {
            return Err(SmbError::IsDirectory);
        }
        if is_dir {
            let info = self.info_for(path.file_name().unwrap_or("\\"), 0, true);
            let entries = self.list_entries(path).await?;
            return Ok(Box::new(HnHandle::Directory { info, entries }));
        }

        let data = self.read_file(path).await?;
        let info = self.info_for(
            path.file_name().ok_or(SmbError::NotFound)?,
            data.len() as u64,
            false,
        );
        Ok(Box::new(HnHandle::File { data, info }))
    }

    async fn unlink(&self, _path: &SmbPath) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn rename(&self, _from: &SmbPath, _to: &SmbPath) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            is_read_only: true,
            case_sensitive: false,
        }
    }
}

enum HnHandle {
    File {
        data: Bytes,
        info: FileInfo,
    },
    Directory {
        info: FileInfo,
        entries: Vec<DirEntry>,
    },
}

#[async_trait]
impl Handle for HnHandle {
    async fn read(&self, offset: u64, len: u32) -> SmbResult<Bytes> {
        let HnHandle::File { data, .. } = self else {
            return Err(SmbError::IsDirectory);
        };
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(data.len());
        let end = start.saturating_add(len as usize).min(data.len());
        Ok(data.slice(start..end))
    }

    async fn write(&self, _offset: u64, _data: &[u8]) -> SmbResult<u32> {
        Err(SmbError::AccessDenied)
    }

    async fn flush(&self) -> SmbResult<()> {
        Ok(())
    }

    async fn stat(&self) -> SmbResult<FileInfo> {
        match self {
            HnHandle::File { info, .. } | HnHandle::Directory { info, .. } => Ok(info.clone()),
        }
    }

    async fn set_times(&self, _times: FileTimes) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn truncate(&self, _len: u64) -> SmbResult<()> {
        Err(SmbError::AccessDenied)
    }

    async fn list_dir(&self, _pattern: Option<&str>) -> SmbResult<Vec<DirEntry>> {
        match self {
            HnHandle::Directory { entries, .. } => Ok(entries.clone()),
            HnHandle::File { .. } => Err(SmbError::NotADirectory),
        }
    }

    async fn close(self: Box<Self>) -> SmbResult<()> {
        Ok(())
    }
}

#[derive(Clone)]
struct HnClient {
    base: Arc<str>,
    ttl: Duration,
    http: reqwest::Client,
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

#[derive(Clone)]
struct CacheEntry {
    expires: SystemTime,
    data: Bytes,
}

impl HnClient {
    fn new(ttl: Duration) -> Self {
        Self {
            base: Arc::from("https://hacker-news.firebaseio.com/v0"),
            ttl: ttl.max(Duration::from_secs(1)),
            http: reqwest::Client::builder()
                .user_agent("rust-smb-server-hnfs-example/0.1")
                .timeout(Duration::from_secs(10))
                .build()
                .expect("valid reqwest client"),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn story_ids(&self, list_name: &str) -> SmbResult<Vec<u64>> {
        let api_name = match list_name {
            "top" => "topstories",
            "new" => "newstories",
            "best" => "beststories",
            "ask" => "askstories",
            "show" => "showstories",
            "jobs" => "jobstories",
            _ => return Err(SmbError::NotFound),
        };
        self.get_json(&format!("/{api_name}.json")).await
    }

    async fn item(&self, id: u64) -> SmbResult<HnItem> {
        if id == 0 {
            return Err(SmbError::NotFound);
        }
        let item: HnItem = self.get_json(&format!("/item/{id}.json")).await?;
        if item.id == 0 {
            return Err(SmbError::NotFound);
        }
        Ok(item)
    }

    async fn user(&self, id: &str) -> SmbResult<HnUser> {
        if id.is_empty() {
            return Err(SmbError::NotFound);
        }
        let user: HnUser = self.get_json(&format!("/user/{id}.json")).await?;
        if user.id.is_empty() {
            return Err(SmbError::NotFound);
        }
        Ok(user)
    }

    async fn get_json<T: DeserializeOwned>(&self, endpoint: &str) -> SmbResult<T> {
        let bytes = self.get_bytes(endpoint).await?;
        serde_json::from_slice(&bytes).map_err(|_| SmbError::NotFound)
    }

    async fn get_bytes(&self, endpoint: &str) -> SmbResult<Bytes> {
        let now = SystemTime::now();
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| other("cache lock poisoned"))?;
            if let Some(entry) = cache.get(endpoint)
                && now < entry.expires
            {
                return Ok(entry.data.clone());
            }
        }

        let url = format!("{}{}", self.base, endpoint);
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| other(format!("HN API request failed: {e}")))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(SmbError::NotFound);
        }
        if !status.is_success() {
            return Err(SmbError::AccessDenied);
        }
        let data = response
            .bytes()
            .await
            .map_err(|e| other(format!("HN API read failed: {e}")))?;
        if data.len() > 4 << 20 {
            return Err(SmbError::AccessDenied);
        }

        let mut cache = self
            .cache
            .lock()
            .map_err(|_| other("cache lock poisoned"))?;
        cache.insert(
            endpoint.to_string(),
            CacheEntry {
                expires: now + self.ttl,
                data: data.clone(),
            },
        );
        Ok(data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HnItem {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    deleted: bool,
    #[serde(default, rename = "type")]
    item_type: String,
    #[serde(default)]
    by: String,
    #[serde(default)]
    time: i64,
    #[serde(default)]
    text: String,
    #[serde(default)]
    dead: bool,
    #[serde(default)]
    parent: u64,
    #[serde(default)]
    poll: u64,
    #[serde(default)]
    kids: Vec<u64>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    score: i64,
    #[serde(default)]
    title: String,
    #[serde(default)]
    parts: Vec<u64>,
    #[serde(default)]
    descendants: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HnUser {
    #[serde(default)]
    id: String,
    #[serde(default)]
    created: i64,
    #[serde(default)]
    karma: i64,
    #[serde(default)]
    about: String,
    #[serde(default)]
    submitted: Vec<u64>,
}

fn is_list_dir(name: &str) -> bool {
    matches!(name, "top" | "new" | "best" | "ask" | "show" | "jobs")
}

fn story_prefix(index: usize, item: &HnItem) -> String {
    format!("{index:03}-{}-{}", slug(&item.title), item.id)
}

fn story_id(file_name: &str) -> Option<u64> {
    let stem = file_name
        .rsplit_once('.')
        .map_or(file_name, |(stem, _)| stem);
    let (_, id) = stem.rsplit_once('-')?;
    id.parse().ok()
}

fn story_text(item: &HnItem) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}\n", clean_text(&item.title)));
    out.push_str(&format!("HN: {}\n", hn_item_url(item.id)));
    if let Some(url) = item.url.as_deref().filter(|url| !url.is_empty()) {
        out.push_str(&format!("URL: {url}\n"));
    }
    if !item.by.is_empty() {
        out.push_str(&format!("By: {}\n", item.by));
    }
    if item.score != 0 {
        out.push_str(&format!("Score: {}\n", item.score));
    }
    out.push_str(&format!("Comments: {}\n", item.descendants));
    if item.time != 0 {
        out.push_str(&format!("Time: {}\n", hn_time(item.time)));
    }
    if !item.text.is_empty() {
        out.push_str(&format!("\n{}\n", clean_text(&item.text)));
    }
    out
}

fn story_url(item: &HnItem) -> String {
    item.url
        .as_deref()
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| hn_item_url(item.id))
}

fn hn_time(seconds: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(seconds) {
        Ok(time) => time
            .format(&Rfc3339)
            .unwrap_or_else(|_| seconds.to_string()),
        Err(_) => seconds.to_string(),
    }
}

fn hn_item_url(id: u64) -> String {
    format!("https://news.ycombinator.com/item?id={id}")
}

fn pretty_json<T: Serialize>(value: &T) -> SmbResult<Vec<u8>> {
    let mut data = serde_json::to_vec_pretty(value).map_err(|_| SmbError::NotFound)?;
    data.push(b'\n');
    Ok(data)
}

fn slug(title: &str) -> String {
    let mut slug = String::new();
    let mut previous_was_separator = false;
    for ch in clean_text(title).trim().chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            slug.push(ch);
            previous_was_separator = matches!(ch, '.' | '_' | '-');
        } else {
            if !previous_was_separator {
                slug.push('-');
                previous_was_separator = true;
            }
        }
    }
    let mut slug = slug.trim_matches(['-', '.', '_']).to_string();
    if slug.is_empty() {
        slug = "untitled".into();
    }
    if slug.len() > 72 {
        slug.truncate(72);
        slug = slug.trim_end_matches(['-', '.', '_']).to_string();
    }
    if slug.is_empty() {
        "untitled".into()
    } else {
        slug
    }
}

fn clean_text(value: &str) -> String {
    html_unescape(&strip_tags(value))
}

fn strip_tags(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut in_tag = false;
    for ch in value.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
}

fn stable_id(name: &str) -> u64 {
    let digest = Sha1::digest(name.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(bytes).max(1)
}

fn filetime(t: SystemTime) -> u64 {
    let duration = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    FILETIME_OFFSET + duration.as_secs() * 10_000_000 + u64::from(duration.subsec_nanos() / 100)
}

fn other(message: impl Into<String>) -> SmbError {
    SmbError::Io(io::Error::other(message.into()))
}

const ROOT_ENTRIES: &[(&str, bool)] = &[
    ("README.txt", false),
    ("top", true),
    ("new", true),
    ("best", true),
    ("ask", true),
    ("show", true),
    ("jobs", true),
    ("item", true),
    ("user", true),
];

const README_TEXT: &str = "Rust SMB Hacker News VFS\n\
\n\
This is an unofficial, read-only demo backed by the public Hacker News Firebase API.\n\
\n\
Directories:\n\
  top/    current top stories\n\
  new/    newest stories\n\
  best/   best stories\n\
  ask/    Ask HN stories\n\
  show/   Show HN stories\n\
  jobs/   job posts\n\
\n\
Story directories expose three readable files per item. The trailing HN item ID\n\
is the durable identity; the rank and title slug are display-only.\n\
  .txt   human-readable summary\n\
  .url   original story URL, or the HN item URL when no external URL exists\n\
  .json  raw API item data\n\
\n\
Direct lookups:\n\
  item/<id>.json\n\
  user/<username>.json\n\
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn story_prefix_uses_rank_title_and_stable_id() {
        let got = story_prefix(
            7,
            &HnItem {
                id: 123_456,
                title: "Hello, Stable World!".into(),
                ..empty_item()
            },
        );
        assert_eq!(got, "007-Hello-Stable-World-123456");
    }

    #[test]
    fn story_id_ignores_rank_and_title_slug() {
        for name in [
            "007-Hello-Stable-World-123456.txt",
            "001-Renamed-Story-123456.url",
            "999-title-with-2026-in-it-123456.json",
        ] {
            assert_eq!(story_id(name), Some(123_456));
        }
    }

    #[test]
    fn slug_strips_tags_unescapes_html_and_has_fallback() {
        assert_eq!(slug("<b>AT&amp;T launches</b>"), "AT-T-launches");
        assert_eq!(slug(" <i> </i> "), "untitled");
    }

    #[test]
    fn stable_ids_are_nonzero_and_repeatable() {
        assert_eq!(stable_id("top"), stable_id("top"));
        assert_ne!(stable_id("top"), 0);
    }

    #[test]
    fn story_url_falls_back_for_missing_or_empty_url() {
        assert_eq!(
            story_url(&HnItem {
                id: 42,
                url: None,
                ..empty_item()
            }),
            "https://news.ycombinator.com/item?id=42"
        );
        assert_eq!(
            story_url(&HnItem {
                id: 42,
                url: Some(String::new()),
                ..empty_item()
            }),
            "https://news.ycombinator.com/item?id=42"
        );
        assert_eq!(
            story_url(&HnItem {
                id: 42,
                url: Some("https://example.com/story".into()),
                ..empty_item()
            }),
            "https://example.com/story"
        );
    }

    #[test]
    fn story_text_uses_gosmb_time_and_empty_url_rules() {
        let text = story_text(&HnItem {
            id: 42,
            title: "<b>Launch</b>".into(),
            by: "alice".into(),
            time: 1_609_459_200,
            text: "hello &amp; goodbye".into(),
            url: Some(String::new()),
            score: 10,
            descendants: 2,
            ..empty_item()
        });

        assert!(text.starts_with("Launch\nHN: https://news.ycombinator.com/item?id=42\n"));
        assert!(!text.contains("URL: \n"));
        assert!(text.contains("By: alice\n"));
        assert!(text.contains("Score: 10\n"));
        assert!(text.contains("Comments: 2\n"));
        assert!(text.contains("Time: 2021-01-01T00:00:00Z\n"));
        assert!(text.ends_with("\nhello & goodbye\n"));
    }

    fn empty_item() -> HnItem {
        HnItem {
            id: 0,
            deleted: false,
            item_type: String::new(),
            by: String::new(),
            time: 0,
            text: String::new(),
            dead: false,
            parent: 0,
            poll: 0,
            kids: Vec::new(),
            url: None,
            score: 0,
            title: String::new(),
            parts: Vec::new(),
            descendants: 0,
        }
    }
}
