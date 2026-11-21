# Design

## Context

See `proposal.md` for motivation (b/587564573, CWE-522) and `specs/http/redirect-credential-scoping/spec.md` for requirements.

On `upstream/master` (`ee067dc`), PR #2246 (`995c16b`) introduced `_strip_headers_on_cross_origin_redirect` on `TraceConfig.on_request_redirect`, mutating `aiohttp`'s live `params.headers` (`CIMultiDict`) in place across `aiohttp`'s native redirect loop. Three gaps remained:
1. `client_kwargs["auth"]` stays on `ClientSession._default_auth` and is re-applied by `aiohttp` 3.14.3 after origin change when `base_url` is unset (and on bounce-back even with `base_url`).
2. Unscoped `client_kwargs["cookies"]` are stored under `CookieJar`'s wildcard `("", "")` key and sent to every origin.
3. `_strip_headers_on_cross_origin_redirect` used `yarl.URL.origin()` (false-mismatching explicit default ports like `:443` vs omitted ports) and called `yarl.URL(location)` without catching `ValueError` on malformed or non-HTTP `Location` headers.

## Goals / Non-Goals

**Goals:**
- Reuse `aiohttp`'s native redirect loop, retry wrapper (`_with_retries`), and `TraceConfig` across all `aiohttp` 3.x versions with zero dependency bumps.
- Eliminate cross-origin and bounce-back leaks for `client_kwargs["auth"]`, `storage_options["auth"]`, `client_kwargs["cookies"]`, and custom headers.
- Scope session credentials and non-safe headers to `base_url`'s normalized origin when configured.

**Non-Goals:**
- Replacing `aiohttp`'s redirect loop with a custom per-hop loop.
- Modifying experimental `fsspec/implementations/http_sync.py`.
- Inspecting private attributes on `ClientSession` objects built by a custom `get_client` that hardcodes credentials outside `client_kwargs`.

## Decisions

### 1. Normalize `BasicAuth` into `Authorization` header (`_normalize_basic_auth`)
- Convert `aiohttp.BasicAuth` in `client_kwargs["auth"]` and `storage_options["auth"]` (copied `request_options`) into `headers["Authorization"] = auth.encode()`, raising `ValueError` if an `Authorization` header is already present.
- Rationale: Removes `session._default_auth` so `aiohttp` cannot re-apply it on cross-origin or bounce-back redirects, brings `auth` under `on_request_redirect` across all `aiohttp` 3.x versions, and avoids `aiohttp` 3.14 `DeprecationWarning`s.
- Alternative rejected: Passing per-request `auth=` to all 12 call sites (still warns on 3.14 and fails on older `aiohttp`).

### 2. Hoist unscoped `client_kwargs["cookies"]` (`_hoist_unscoped_cookies`)
- In `_prepare_session_kwargs`, unless `cookie_jar` is `aiohttp.DummyCookieJar`, encode unscoped cookies via `SimpleCookie` into `headers["Cookie"]` (preserving any existing `Cookie` header) while leaving domain-scoped `Morsel` cookies in `cookies` for `CookieJar`.
- Rationale: `aiohttp.ClientRequest.update_cookies` merges `headers["Cookie"]` with domain-scoped server cookies, while `on_request_redirect` strips `Cookie` on cross-origin hops.

### 3. Normalized `(scheme, host, port)` origin check & `base_url` guard
- `_url_origin(url)` returns `(url.scheme.lower(), url.host.lower() if url.host is not None else None, url.port)`, leveraging `yarl.URL.port` to resolve `:80`/`:443` and fixing `yarl.URL.origin()`'s `explicit_port` mismatch.
- `_strip_headers_on_cross_origin_redirect` parses `Location`/`URI` with `getattr(session, "_requote_redirect_url", True)` inside `try ... except ValueError`, exits early on non-HTTP(S) schemes so `aiohttp` raises `NonHttpUrlRedirectClientError`, resolves relative/protocol-relative URLs with `params.url.join(...)`, and strips headers outside `_REDIRECT_SAFE_HEADERS` (which includes `"content-length"` for `307`/`308` body redirects).
- `_make_base_url_origin_guard` attaches an `on_request_start` hook when `base_url` is configured, stripping non-safe session-default header values on requests to other origins while keeping explicit per-call overrides intact.

### 4. Consistent `self.kwargs` merging in `_pipe_file`
- Merge `kw = self.kwargs.copy(); kw.update(kwargs)` and copy headers into `CIMultiDict(kw.pop("headers", {}) or ())` before setting `Content-Length`, ensuring `storage_options` apply without mutating caller dicts.

## Risks / Trade-offs

- **[Breaking cross-origin `BasicAuth` / session `cookies`]** -> Callers relying on session `auth` or unscoped `cookies` crossing origins will have them stripped; same-origin redirects and standard CDN headers (`Range`, `Accept-Encoding`, `User-Agent`, `Content-Length`, etc.) continue working and behavior is documented in `HTTPFileSystem` docstrings.
- **[Custom `get_client` embedding credentials directly]** -> Credentials hardcoded inside a custom `get_client` bypass `_prepare_session_kwargs`; documented in `HTTPFileSystem.__init__`.
