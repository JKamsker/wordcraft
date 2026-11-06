# wordcraft-server

Serves the WordCraft web app (the wasm build of `apps/wordcraft-web`) and stores the documents it
opens and saves. Documents can live in a directory, in memory, or (as those backends land) in S3,
Azure Blob, Google Cloud Storage, FTP/FTPS or SMB.

## Quick start

```sh
# once: build the web app (writes dist/web at the repository root)
rustup target add wasm32-unknown-unknown
cargo install trunk
(cd apps/wordcraft-web && trunk build --release)

# run from the repository root
cargo run --release -p wordcraft-server
# open http://127.0.0.1:8780/
```

`/` is a file browser (no JavaScript): create, upload, download, delete, and open a document in the
editor at `/app/?file=<path>`. Without a web build, `/app/` shows how to make one.

## Options

| Option | Default | Meaning |
|---|---|---|
| `--listen <addr>` | `127.0.0.1:8780` | address and port |
| `--storage <url>` | `dir://./documents` (env `WORDCRAFT_STORAGE`) | where documents live |
| `--web-root <dir>` | `dist/web` | the web build served at `/app/` |
| `--max-bytes <n>` | `256M` | largest document accepted or served (`K`, `M`, `G` are binary) |
| `--auth <user:pass>` | none (env `WORDCRAFT_SERVER_AUTH`) | HTTP Basic auth on every route |
| `--help` | | usage |

`WORDCRAFT_LOG` sets the log level (`error`, `warn`, `info`, `debug`, `trace`; default `info`).
Logs go to stderr. Ctrl-C or SIGTERM shuts the server down gracefully.

Storage URLs: `dir:///srv/docs`, `file:///srv/docs` or a plain path (a directory, created if
missing); `memory:` (lost on exit); `s3://bucket/prefix`, `az://container/prefix`,
`gs://bucket/prefix`; `ftp://user@host:21/folder`, `ftps://…`; `smb://user@host/share/folder`.
Remote backends take their secrets from environment variables (see each backend's module docs
in `src/storage/`), not from the URL.

## HTTP API

The web app uses these routes; they are a contract.

| Route | Result |
|---|---|
| `GET /api/files` | `{"storage": "…", "files": [{"path": "a/b.docx", "size": 123, "modified": "…"}]}` |
| `GET /api/files/{path}` | the bytes, `application/octet-stream`, `Cache-Control: no-store` |
| `PUT /api/files/{path}` | stores the raw request body, `204` |
| `DELETE /api/files/{path}` | removes the file, `204` |

Errors: invalid path `400`, missing `404`, too large `413`, storage failure `502` (the detail is
logged, not returned). Paths are relative and `/`-separated; `..`, backslashes, control and
reserved characters are refused.

## Security

- The server listens on localhost by default. Before exposing it, set `--auth` (prefer the
  environment variable: command-line arguments are visible to other users) and put it behind a
  TLS-terminating reverse proxy. Basic auth is not encryption.
- Browsers reuse the Basic credentials for the web app's same-origin requests.
- Writes whose `Sec-Fetch-Site` is not `same-origin` or `none` are refused, so another site cannot
  change documents with the browser's remembered credentials.
- Every response has `X-Content-Type-Options: nosniff`; downloads are `Content-Disposition:
  attachment`; the file browser sends a Content-Security-Policy that allows no scripts.
- The directory backend refuses symbolic links anywhere in a path, skips them (and hidden files)
  in listings, and writes through a temporary file renamed into place.
- All links are relative, so the server works under a reverse-proxy sub-path (serve it at
  `/prefix/`, with the trailing slash).
