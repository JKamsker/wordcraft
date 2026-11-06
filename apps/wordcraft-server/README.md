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
| `--oidc-issuer <url>` … | none | OpenID Connect sign-in, see [below](#openid-connect-authentik-keycloak) |
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
| `GET /api/me` | `{"mode": "oidc"\|"basic"\|"none", "authenticated": bool, "user": {"id", "name", "email" (or null), "groups": […]} or null, "logout": "auth/logout" or null}` |

With Basic auth, `/api/me` reports `mode: "basic"` and the user name as both `id` and `name`
(`email: null`, `groups: []`); without auth, `mode: "none"`, `authenticated: false`, `user: null`.
With OpenID Connect and no session, it answers like every other API route: `401`
`{"error": "unauthenticated", "login": "auth/login"}` (the path is relative to the server root).

Errors: invalid path `400`, missing `404`, too large `413`, storage failure `502` (the detail is
logged, not returned). Paths are relative and `/`-separated; `..`, backslashes, control and
reserved characters are refused.

## OpenID Connect (Authentik, Keycloak…)

Instead of `--auth`, the server can sign people in with an OpenID Connect provider (Authorization
Code flow with PKCE S256). Every route but `/auth/*` then needs a session: pages redirect to the
provider and come back to the same page; the API answers `401` with the JSON above. Scripts can
send `Authorization: Bearer <access token>` instead; the server checks it at the provider's userinfo
endpoint (cached for a minute).

| Option | Environment | Meaning |
|---|---|---|
| `--oidc-issuer <url>` | `WORDCRAFT_OIDC_ISSUER` | the issuer; discovery is `<issuer>/.well-known/openid-configuration` |
| `--oidc-client-id <id>` | `WORDCRAFT_OIDC_CLIENT_ID` | the client ID |
| (environment only) | `WORDCRAFT_OIDC_CLIENT_SECRET` | the client secret (`client_secret_basic`); unset for a public client |
| `--public-url <url>` | `WORDCRAFT_PUBLIC_URL` | the URL users open; required. The redirect URI is `<public url>auth/callback` |
| `--oidc-scopes <s>` | `WORDCRAFT_OIDC_SCOPES` | default `openid profile email`; must include `openid` |
| `--oidc-allowed-groups a,b` | `WORDCRAFT_OIDC_ALLOWED_GROUPS` | only members of one of these groups (the `groups` claim) |
| `--oidc-allowed-emails a,b` | `WORDCRAFT_OIDC_ALLOWED_EMAILS` | only these (verified) e-mail addresses; with both lists, either match is enough |
| `--per-user-storage` | `WORDCRAFT_PER_USER_STORAGE=1` | each user sees only `users/<id>/` of the storage |
| `--session-hours <n>` | `WORDCRAFT_SESSION_HOURS` | how long a sign-in lasts, default 12 |

`--auth` and `--oidc-issuer` cannot be combined. The provider's endpoints must be https (plain http
is accepted only when the issuer itself is `http://localhost` or `127.0.0.1`, for development).

### Authentik

1. **Applications ▸ Providers ▸ Create ▸ OAuth2/OpenID Provider.** Client type *Confidential*;
   redirect URI `https://<host>/auth/callback` (strict; with a sub-path, `https://<host>/<path>/auth/callback`);
   pick a signing key (RS256) so ID tokens are signed. The default scope mappings (`openid`,
   `profile`, `email`) are enough: Authentik's `profile` mapping includes the user's `groups`.
2. **Applications ▸ Applications ▸ Create.** Name it, choose a slug (e.g. `wordcraft`) and the provider
   above. Bind users or groups to it if only some people may use it.
3. Copy the client ID and secret from the provider. The issuer is
   `https://<authentik>/application/o/<slug>/`.

```sh
export WORDCRAFT_OIDC_CLIENT_SECRET='…'   # from the provider; never on the command line
wordcraft-server --listen 127.0.0.1:8780 --storage dir:///srv/wordcraft \
  --oidc-issuer https://auth.example.com/application/o/wordcraft/ \
  --oidc-client-id 'AbC123…' \
  --public-url https://docs.example.com/ \
  --oidc-allowed-groups 'WordCraft users' --per-user-storage
```

Keycloak: a client with *Client authentication* on and *Standard flow* enabled, valid redirect URI
`https://<host>/auth/callback`; the issuer is `https://<keycloak>/realms/<realm>`. Add a *Group
Membership* mapper (claim `groups`, *Full group path* off) for `--oidc-allowed-groups`. Entra ID: the
issuer is `https://login.microsoftonline.com/<tenant>/v2.0`; groups need the optional `groups` claim.

How it works and what it checks:

- Sign-in state, nonce and PKCE verifier come from the operating system's random generator; the
  pending sign-in lives in memory for 10 minutes and is bound to the browser by an HttpOnly
  `wordcraft_login` cookie, checked and used once at the callback.
- The ID token's `iss`, `aud` (and `azp` with several audiences), `exp`/`iat`/`nbf` (2 minutes of
  clock skew) and `nonce` are checked. Its signature is verified against the provider's JWKS (RS*,
  PS*, ES256/ES384) or the client secret (HS*); unsigned tokens are refused when the provider
  publishes keys. A provider without a `jwks_uri` is accepted with TLS standing in for the
  signature (OIDC Core 3.1.3.7), since the token comes straight from the token endpoint over https.
- The userinfo `sub` must match the ID token's. The name shown is `name`, else `preferred_username`,
  else `email`, else `sub`.
- Sessions are 32 random bytes in a `wordcraft_session` cookie (HttpOnly, SameSite=Lax, `Path` from
  the public URL, `Secure` when it is https), held in memory: a restart signs everyone out.
- `next` must be a relative path on this server, or an absolute path under the public URL's path;
  anything else (`//host`, `https:`, backslashes, `..`) goes to the file browser, so the sign-in
  cannot redirect elsewhere.
- Sign out (`POST /auth/logout`, a button in the file browser) ends the session and, when the
  provider has an `end_session_endpoint`, its session too, coming back to the public URL (register
  it as a post-logout redirect URI).
- Bearer tokens are any access token the provider's userinfo endpoint accepts, including ones
  issued to other applications of the same provider; the allowlists apply to them too.
- With `--per-user-storage`, the folder is the user's `sub` when it is plain lower-case ASCII, else
  `h-` and its SHA-256, so it is always a valid path and cannot collide.
- Tokens, codes, secrets and cookies are never logged.

## Security

- The server listens on localhost by default. Before exposing it, set `--auth` or OpenID Connect (prefer the
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
