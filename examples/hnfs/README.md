# Hacker News VFS Example

This example exposes public Hacker News data as a read-only SMB share. It uses
the public Hacker News Firebase API and the `smb-server` `ShareBackend` trait.

```sh
cargo run -p hnfs-smb-example
```

Environment variables:

- `SMB_LISTEN`, default `127.0.0.1:1445`
- `SMB_SHARE`, default `HN`
- `HNFS_LIMIT`, default `30`
- `HNFS_CACHE_TTL_SECS`, default `60`
- `HNFS_GUEST`, default `true`
- `HNFS_USER` / `HNFS_PASSWORD`, optional authenticated user

The share layout mirrors the GoSMB example:

```text
README.txt
top/
new/
best/
ask/
show/
jobs/
item/
user/
```

Story listings expose `.txt`, `.url`, and `.json` files. The trailing Hacker
News item ID is the stable identity; rank and title slug are display-only.
