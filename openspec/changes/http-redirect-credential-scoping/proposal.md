# Proposal

## Why

Security audit finding b/587564573 (S02-C02, P2/S2, CWE-522) identified that `HTTPFileSystem` leaks credentials across cross-origin HTTP redirects. Upstream PR #2246 (`995c16b`) added an `aiohttp.TraceConfig.on_request_redirect` hook for custom headers, but `upstream/master` remains vulnerable: `client_kwargs["auth"]` is re-applied by `aiohttp` after origin changes or bounce-backs, unscoped `client_kwargs["cookies"]` are stored under `CookieJar`'s wildcard key and sent to every origin, and PR #2246's redirect hook misclassifies explicit default ports (such as `:443`) and raises raw `ValueError`s on malformed or non-HTTP `Location` headers.

## What Changes

- Normalize `BasicAuth` in `client_kwargs` and `storage_options` into `Authorization` headers (raising `ValueError` on conflict with an explicit `Authorization` header, without mutating caller dicts) so `aiohttp` never retains `_default_auth` across cross-origin or bounce-back redirects.
- Hoist unscoped `client_kwargs["cookies"]` into `Cookie` headers (keeping domain-scoped `Morsel` cookies in `CookieJar` and respecting `DummyCookieJar`) so session cookies are stripped on cross-origin redirects.
- Add `base_url` origin scoping via `TraceConfig.on_request_start` so session-level credentials and non-safe headers are omitted on direct requests to non-`base_url` origins.
- Harden `_strip_headers_on_cross_origin_redirect` with normalized `(scheme, host, port)` origin comparison, guards for malformed/non-HTTP `Location` headers, `content-length` in `_REDIRECT_SAFE_HEADERS` for `307`/`308` body redirects, and clean `self.kwargs` merging in `_pipe_file`.
- **BREAKING**: `client_kwargs["auth"]` and unscoped `client_kwargs["cookies"]` are no longer forwarded across cross-origin redirects or to non-`base_url` origins; update `HTTPFileSystem` docstrings and add unit/integration tests across read, write, metadata, and streaming entry points.

## Capabilities

### New Capabilities

- `http/redirect-credential-scoping`: Origin-scoped credential, header, and cookie handling across HTTP redirects in `HTTPFileSystem` and its file handle and metadata helpers.

### Modified Capabilities

## Impact

- Affected code in `filesystem_spec`: `fsspec/implementations/http.py` and `fsspec/implementations/tests/test_http.py` (building on `upstream/master` PR #2246 `995c16b`).
- Out of scope: Experimental blocking implementation `fsspec/implementations/http_sync.py`.
- Dependency compatibility: Uses `aiohttp.TraceConfig` and `multidict.CIMultiDict`, keeping `pyproject.toml`'s `aiohttp !=4.0.0a0, !=4.0.0a1` constraint unchanged.
