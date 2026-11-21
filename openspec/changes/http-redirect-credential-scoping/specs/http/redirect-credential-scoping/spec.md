# Spec Delta

## Purpose

Defines origin-scoped credential, header, and cookie handling during HTTP redirect traversal across `HTTPFileSystem`, its file handles, and its metadata and range helpers so cross-origin redirects cannot leak credentials while preserving legitimate same-origin and CDN redirect workflows.

## ADDED Requirements

### Requirement: Origin-scoped credential forwarding across HTTP redirects
The HTTP filesystem SHALL forward caller-configured authentication (`auth`), session or request cookies, and non-allowlisted custom headers on redirect hops only while every hop stays on the same normalized `(scheme, host, port)` origin as the initial request (or the configured `base_url` origin, when `base_url` is set). Once any hop targets a different origin, credentials and non-allowlisted headers MUST be dropped permanently for all remaining hops in that redirect chain.

#### Scenario: Same-origin redirect preserves credentials and headers
- **WHEN** a request to `https://origin-a.example/start` configured with `BasicAuth`, a custom header `X-API-Key`, and cookies receives a `302` redirect to `https://origin-a.example/final`
- **THEN** the follow-up request to `https://origin-a.example/final` includes the `Authorization` credential, `X-API-Key`, and cookies

#### Scenario: Explicit default port matches omitted default port as same origin
- **WHEN** a request to `https://origin-a.example:443/start` with credentials receives a `302` redirect to `https://origin-a.example/final`
- **THEN** the redirect is treated as same-origin and the follow-up request preserves credentials and headers

#### Scenario: Cross-origin host change strips credentials and custom headers
- **WHEN** a request configured with credentials via `client_kwargs["auth"]`, `client_kwargs["headers"]`, `client_kwargs["cookies"]`, or `storage_options` `headers` (with per-request `storage_options["auth"]` handled by `aiohttp`) receives a redirect to a different host (including protocol-relative `Location: //other.example/...`)
- **THEN** the redirected request omits `Authorization`, `Proxy-Authorization`, `Cookie`, and non-allowlisted custom headers such as `X-API-Key`

#### Scenario: Cross-origin port change strips credentials
- **WHEN** a request to `http://127.0.0.1:8001/start` with credentials receives a redirect to `http://127.0.0.1:8002/final`
- **THEN** the redirected request omits credentials, cookies, and non-allowlisted custom headers

#### Scenario: HTTPS to HTTP scheme downgrade strips credentials
- **WHEN** a request to `https://origin-a.example/start` with credentials receives a redirect to `http://origin-a.example/final`
- **THEN** the redirected request omits credentials, cookies, and non-allowlisted custom headers

#### Scenario: Bounce-back redirect does not re-attach credentials
- **WHEN** a request to `https://origin-a.example/start` redirects to `https://other.example/hop` and that hop redirects back to `https://origin-a.example/final`
- **THEN** neither `https://other.example/hop` nor the final request to `https://origin-a.example/final` receives credentials, cookies, or non-allowlisted custom headers

#### Scenario: Configured base_url scopes session credentials to base_url origin
- **WHEN** `HTTPFileSystem` is configured with `client_kwargs={"base_url": "https://origin-a.example/", "auth": ..., "headers": {"X-API-Key": ...}, "cookies": {...}}` and issues a request to `https://origin-b.example/file`
- **THEN** the session-level credentials, cookies, and non-safe session headers are not attached to the request to `https://origin-b.example/file`

### Requirement: Safe non-credential headers preserved across cross-origin redirects
When a redirect crosses origins, the HTTP filesystem SHALL preserve standard non-credential headers (`Range`, `Accept`, `Accept-Encoding`, `Accept-Language`, `User-Agent`, `Cache-Control`, `Content-Encoding`, `Content-Language`, `Content-Length`, `Content-Type`, `If-Match`, `If-Modified-Since`, `If-None-Match`, `If-Range`, `If-Unmodified-Since`) while stripping all other headers.

#### Scenario: Byte-range read survives cross-origin redirect without leaking credentials
- **WHEN** a seekable file read or ranged `cat_file` sends `Range` alongside `BasicAuth`, session cookies, or `X-API-Key` to an authenticated origin that redirects to a cross-origin CDN
- **THEN** the redirected CDN request includes `Range` and `Accept-Encoding: identity` and omits `Authorization`, `Cookie`, and `X-API-Key`

#### Scenario: Metadata probe preserves Accept-Encoding identity across cross-origin redirect
- **WHEN** `info` probes an authenticated URL with `Accept-Encoding: identity` and follows a cross-origin redirect
- **THEN** the redirected probe includes `Accept-Encoding: identity` and omits credentials and non-allowlisted headers

#### Scenario: User-Agent and Accept headers survive cross-origin redirect
- **WHEN** a caller configures `User-Agent` and `Accept` alongside `X-API-Key` and follows a cross-origin redirect
- **THEN** the redirected request preserves `User-Agent` and `Accept` while stripping `X-API-Key`

### Requirement: Safe redirect Location handling and RFC-compliant method/body forwarding
The HTTP filesystem SHALL handle relative `Location` resolution, malformed and non-HTTP redirect rejection via standard client redirect errors, and RFC-compliant method and body handling across `301`, `302`, `303`, `307`, and `308` redirects.

#### Scenario: Relative Location resolves against current URL
- **WHEN** a request to `https://origin-a.example/dir/a` receives a `302` response with `Location: ../b`
- **THEN** the follow-up request targets `https://origin-a.example/b` as a same-origin request preserving credentials

#### Scenario: Malformed or non-HTTP redirect Location raises client redirect error
- **WHEN** a server returns a redirect whose `Location` is malformed (such as `http://[::1`) or uses a non-HTTP scheme (such as `file:///etc/passwd` or `ftp://other.example/data`)
- **THEN** the redirect hook does not fail with a raw `ValueError` and the HTTP client rejects the redirect with an `aiohttp.ClientError` without issuing a follow-up request

#### Scenario: 303 or POST 301/302 switches to GET and drops body
- **WHEN** a `POST` upload receives a `301`, `302`, or `303` redirect
- **THEN** the follow-up request uses `GET`, drops the request body, and removes `Content-Length`

#### Scenario: 307/308 preserves method and replayable body across redirects
- **WHEN** a `PUT` upload with a replayable `bytes` body receives a `307` or `308` cross-origin redirect
- **THEN** the follow-up request preserves `PUT`, body bytes, `Content-Length`, and `Content-Type` while stripping credentials

### Requirement: Uniform coverage across HTTP filesystem operations without mutating caller options
All HTTP filesystem operations (`ls`, `cat_file`, `get_file`, `put_file`, `pipe_file`, `exists`, `info`, buffered file reads, streaming file reads, and async streaming reads) MUST enforce origin-scoped redirect handling consistently, combining `auth` with an explicit `Authorization` header MUST raise `ValueError`, and initializing `HTTPFileSystem` MUST NOT mutate caller-supplied `client_kwargs` or nested header dicts.

#### Scenario: All read, metadata, write, and streaming entry points strip credentials on cross-origin redirect
- **WHEN** `open` (buffered or streaming), `open_async`, `cat_file`, `get_file`, `put_file`, `pipe_file`, `exists`, `ls`, or `info` follows a cross-origin redirect with configured credentials
- **THEN** none of those entry points forward `Authorization`, session cookies, or non-allowlisted headers to the redirect target

#### Scenario: Caller client_kwargs and headers dictionaries are not mutated
- **WHEN** a caller constructs `HTTPFileSystem(client_kwargs=ck)` with `auth`, `headers`, and `cookies` in `ck` and triggers session creation
- **THEN** `ck` and `ck["headers"]` retain all original keys and values unchanged

#### Scenario: Combining auth with Authorization header raises ValueError
- **WHEN** a caller supplies both `auth=aiohttp.BasicAuth(...)` and an explicit `Authorization` header in `client_kwargs` (or `storage_options`) and issues a request
- **THEN** session preparation (for `client_kwargs`) or `aiohttp` (for `storage_options`) raises `ValueError`
