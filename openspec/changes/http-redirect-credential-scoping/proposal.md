# Proposal

## Why

Security audit finding b/587564573 (S02-C02, P2/S2, CWE-522) identified that `HTTPFileSystem` leaks credentials across cross-origin HTTP redirects. Because `HTTPFileSystem.set_session` creates a single `aiohttp.ClientSession` directly from `client_kwargs` without a `base_url` and leaves redirect following to `aiohttp`, a cross-origin redirect leaks credentials through three verified paths in `aiohttp` 3.14.3: session-level `client_kwargs["auth"]` is cleared on origin change and immediately re-applied at the top of the next redirect iteration, non-standard API-key headers (such as `X-API-Key` or `Private-Token`) from either `client_kwargs` or `storage_options` are never stripped, and session-level `client_kwargs["cookies"]` are stored without a domain and sent to every origin.

## What Changes

- Route all HTTP requests in `fsspec/implementations/http.py` (`HTTPFileSystem`, `HTTPFile`, `HTTPStreamFile`, `AsyncStreamFile`, `_file_info`, and `get_range`) through a centralized, bounded redirect-following helper using `allow_redirects=False` per hop while honoring caller `allow_redirects` and `max_redirects`.
- Hoist session-level `auth`, `headers`, and `cookies` out of `aiohttp.ClientSession` defaults (without mutating the caller's `client_kwargs` dict) so `aiohttp` cannot silently re-inject them on subsequent hops, and attach them per hop only while the request remains on its initial origin (or the configured `base_url` origin).
- Compare origins using normalized `(scheme, host, port)` rather than raw `yarl.URL.origin()` equality (which treats explicit default ports such as `:443` as distinct from omitted ports), and permanently drop credentials for the rest of a redirect chain once any hop leaves the initial origin to block cross-origin leaks, `https` to `http` downgrades, and bounce-back redirects.
- **BREAKING**: On cross-origin redirects, strip `auth`, session/per-request `cookies`, and all caller-supplied headers except a small RFC-safe non-credential allowlist (`Range`, `Accept`, `Accept-Encoding`, `Accept-Language`, `User-Agent`, `Cache-Control`, `If-None-Match`, `If-Modified-Since`, `If-Range`, plus `Content-Type` and `Content-Length` when preserving a 307/308 body). Workloads relying on credentials or arbitrary custom headers crossing origins will no longer have them forwarded to third-party origins.
- Preserve standard redirect semantics across hops, including relative `Location` resolution, non-HTTP scheme rejection, query `params` clearing after the initial hop, 301/302/303 method and body rewriting, 307/308 body replay guards for non-replayable streams, and response connection cleanup on intermediate hops.
- Update `HTTPFileSystem` docstrings to document origin-scoped credential handling and note that custom `get_client` factories that embed credentials directly inside a pre-built `ClientSession` remain caller-managed.
- Add comprehensive unit tests covering same-origin redirects, cross-origin redirects (host, port, and scheme downgrade), bounce-back redirects, `client_kwargs` (`auth`, `headers`, `cookies`), `storage_options` credential headers, `base_url` scoping, and cross-origin CDN `Range` and `Accept-Encoding` preservation.

## Capabilities

### New Capabilities

- `http/redirect-credential-scoping`: Origin-scoped credential, header, and cookie handling across HTTP redirects in `HTTPFileSystem` and its file handle and metadata helpers.

### Modified Capabilities

## Impact

- Affected code in `filesystem_spec`: `fsspec/implementations/http.py` (all 12 HTTP request call sites across `HTTPFileSystem`, `HTTPFile`, `HTTPStreamFile`, `AsyncStreamFile`, `_file_info`, and `get_range`), `fsspec/implementations/tests/test_http.py`, and test server fixtures in `fsspec/tests/conftest.py` if cross-origin test helpers are shared.
- Out of scope: Experimental blocking implementation `fsspec/implementations/http_sync.py`.
- Dependency compatibility: Removes reliance on `aiohttp` version-specific redirect stripping or `aiohttp` 3.12+ client middlewares, maintaining compatibility with `pyproject.toml`'s `aiohttp !=4.0.0a0, !=4.0.0a1` constraint.
- Downstream and caller behavior: Same-origin redirects keep full credentials and headers, and common cross-origin CDN/presigned-URL redirects (GitHub Releases, HuggingFace, S3/GCS signed URLs) continue supporting byte-range reads (`Range`) and size inspection (`Accept-Encoding: identity`) without leaking origin credentials.
