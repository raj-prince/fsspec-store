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
- **WHEN** a request configured with credentials via `client_kwargs["auth"]`, `client_kwargs["headers"]`, `client_kwargs["cookies"]`, or `storage_options` `headers` receives a redirect to a different host
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
- **WHEN** `HTTPFileSystem` is configured with `client_kwargs={"base_url": "https://origin-a.example/", "auth": ...}` and issues a request to `https://origin-b.example/file`
- **THEN** the session-level credentials are not attached to the request to `https://origin-b.example/file`

### Requirement: Safe non-credential headers preserved across cross-origin redirects
When a redirect crosses origins, the HTTP filesystem SHALL preserve standard non-credential protocol headers (`Range`, `Accept`, `Accept-Encoding`, `Accept-Language`, `User-Agent`, `Cache-Control`, `If-None-Match`, `If-Modified-Since`, `If-Range`) so range reads, metadata probes, caching, and content negotiation continue to function against redirected CDNs and storage endpoints.

#### Scenario: Byte-range read survives cross-origin redirect without leaking credentials
- **WHEN** a seekable file read or ranged `cat_file` sends `Range` alongside `BasicAuth` or `X-API-Key` to an authenticated origin that redirects to a cross-origin CDN
- **THEN** the redirected CDN request includes the `Range` header and omits `Authorization` and `X-API-Key`

#### Scenario: Metadata probe preserves Accept-Encoding identity across cross-origin redirect
- **WHEN** `info` probes an authenticated URL with `Accept-Encoding: identity` and follows a cross-origin redirect
- **THEN** the redirected probe includes `Accept-Encoding: identity` and omits credentials and non-allowlisted headers

#### Scenario: User-Agent and Accept headers survive cross-origin redirect
- **WHEN** a caller configures `User-Agent` and `Accept` alongside `X-API-Key` and follows a cross-origin redirect
- **THEN** the redirected request preserves `User-Agent` and `Accept` while stripping `X-API-Key`

### Requirement: Bounded HTTP redirect traversal and protocol safety
The HTTP filesystem SHALL follow `301`, `302`, `303`, `307`, and `308` redirects containing a `Location` header while honoring `allow_redirects`, `max_redirects`, relative `Location` resolution, non-HTTP scheme rejection, query parameter clearing after the first hop, and RFC-compliant method and body handling.

#### Scenario: Caller disables redirects with allow_redirects=False
- **WHEN** a request specifies `allow_redirects=False` and the server responds with a `302` redirect
- **THEN** the HTTP filesystem does not follow the redirect and returns or handles the `302` response directly

#### Scenario: Exceeding max_redirects raises TooManyRedirects
- **WHEN** a server returns more consecutive redirects than `max_redirects` (default 10)
- **THEN** intermediate redirect responses are released and `TooManyRedirects` is raised

#### Scenario: Relative Location resolves against current URL
- **WHEN** a request to `https://origin-a.example/dir/a` receives a `302` response with `Location: ../b`
- **THEN** the follow-up request targets `https://origin-a.example/b` as a same-origin request

#### Scenario: Non-HTTP redirect scheme is rejected
- **WHEN** a server returns a redirect whose `Location` uses a non-HTTP scheme such as `file:///etc/passwd` or `ftp://other.example/data`
- **THEN** the HTTP filesystem rejects the redirect with a client redirect error without issuing a follow-up request

#### Scenario: Query params are not re-appended on redirect hops
- **WHEN** a request specifies `params={"a": "1"}` and receives a redirect to `/next?b=2`
- **THEN** the follow-up request targets `/next?b=2` without re-appending `a=1`

#### Scenario: 303 or POST 301/302 switches to GET and drops body
- **WHEN** a `POST` upload receives a `301`, `302`, or `303` redirect (or any non-`HEAD` request receives `303`)
- **THEN** the follow-up request uses `GET`, drops the request body, and removes `Content-Length` and `Content-Type`

#### Scenario: 307/308 preserves method and replayable body or fails on consumed stream
- **WHEN** a `PUT` or `POST` upload receives a `307` or `308` redirect
- **THEN** a replayable `bytes` body preserves the method, body, `Content-Type`, and `Content-Length`, whereas a non-replayable consumed stream fails with a payload error instead of sending an empty body

### Requirement: Uniform coverage across HTTP filesystem operations without mutating caller options
All HTTP filesystem operations (`ls`, `cat_file`, `get_file`, `put_file`, `pipe_file`, `exists`, `info`, buffered file reads, streaming file reads, async streaming reads, and standalone range and info helpers) MUST enforce origin-scoped redirect handling consistently, and initializing `HTTPFileSystem` MUST NOT mutate caller-supplied `client_kwargs`.

#### Scenario: All read, metadata, and streaming entry points strip credentials on cross-origin redirect
- **WHEN** `open` (buffered or streaming), `open_async`, `cat_file`, `get_file`, `exists`, `ls`, or `info` follows a cross-origin redirect with configured credentials
- **THEN** none of those entry points forward credentials, session cookies, or non-allowlisted headers to the redirect target

#### Scenario: Caller client_kwargs dictionary is not mutated
- **WHEN** a caller constructs `HTTPFileSystem(client_kwargs=ck)` with `auth`, `headers`, and `cookies` in `ck` and triggers session creation
- **THEN** `ck` retains all original keys and values unchanged
