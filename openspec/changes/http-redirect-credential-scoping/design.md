# Design

## Context

See `proposal.md` for motivation (b/587564573, CWE-522) and `specs/http/redirect-credential-scoping/spec.md` for behavioral requirements.

In `fsspec/implementations/http.py`, `HTTPFileSystem` lazily creates a single `aiohttp.ClientSession` via `self.get_client(loop=self.loop, **self.client_kwargs)` without setting `base_url`, stores cleaned `storage_options` in `self.kwargs`, and issues HTTP requests across 12 separate call sites:

- `HTTPFileSystem`: `_ls_real`, `_cat_file`, `_get_file`, `_put_file`, `_exists`, `_pipe_file`, and `_info` (via `_file_info`)
- File handles: `HTTPFile.async_fetch_all`, `HTTPFile.async_fetch_range`, `HTTPStreamFile.__init__`, `AsyncStreamFile.read`
- Module helpers: `_file_info` (also called by `_file_size`) and `get_range`

Every call site currently delegates redirect following to `aiohttp`. In `aiohttp` 3.14.3, `ClientSession._request` clears local `auth` on origin change and then re-applies `self._default_auth` at the top of the next redirect iteration when `self._base_url` is unset; it never strips non-standard headers (such as `X-API-Key`); and `ClientSession(cookies=...)` populates `CookieJar` under an empty-domain `("", "")` key sent to every origin. Additionally, `pyproject.toml` declares `aiohttp !=4.0.0a0, !=4.0.0a1` without a minimum version pin, so `fsspec` cannot rely on `aiohttp` 3.12+ client middlewares or version-specific redirect stripping.

## Goals / Non-Goals

**Goals:**
- Enforce origin-scoped forwarding of `auth`, `cookies`, and headers across all 12 HTTP request call sites through a single shared redirect loop in `fsspec/implementations/http.py`.
- Prevent `aiohttp.ClientSession` from re-injecting `client_kwargs` credentials (`auth`, `headers`, `cookies`) on redirect hops while keeping the caller's `client_kwargs` dict unmutated.
- Support both one-shot context-managed responses (`_cat_file`, `_get_file`, `_ls_real`, `_info`, `_exists`, `_put_file`, `_pipe_file`, `HTTPFile`, `get_range`) and long-lived streaming responses (`HTTPStreamFile`, `AsyncStreamFile`) without leaking intermediate redirect connections.
- Remain compatible across all supported `aiohttp` 3.x versions.

**Non-Goals:**
- Modifying experimental `fsspec/implementations/http_sync.py`.
- Inspecting or mutating private attributes (`_default_auth`, `_default_headers`, `_cookie_jar`) on a `ClientSession` built by an arbitrary user-supplied `get_client` that hardcodes credentials outside `client_kwargs`.
- Introducing new public configuration knobs (such as a custom cross-origin header allowlist parameter) unless upstream `fsspec` review explicitly requests an escape hatch.

## Decisions

### 1. Hoist `auth`, `headers`, and `cookies` out of `ClientSession` defaults

Passing `allow_redirects=False` to `session.request()` is insufficient on its own: if `auth`, `headers`, or `cookies` remain on `ClientSession`, `aiohttp` still re-attaches `_default_auth`, `_default_headers`, and unscoped `("", "")` shared cookies on hop 2.

During `HTTPFileSystem.__init__` (or `set_session`), copy `self.client_kwargs` into an internal `_session_client_kwargs` dict without mutating `self.client_kwargs` (preserving caller dicts, `AbstractFileSystem` instance caching, and pickling). Pop `auth`, `headers`, and `cookies` from `_session_client_kwargs` into internal attributes (`_session_auth`, `_session_headers`, `_session_cookies`), and record `_base_url` / `_base_url_origin` if `base_url` is present in `client_kwargs`. Pass only `_session_client_kwargs` to `self.get_client(loop=self.loop, ...)`.

- **Alternatives considered:**
  - *Move only `auth` to per-request kwargs and keep `aiohttp` redirects:* Leaves custom API-key headers (`X-API-Key`), session `cookies`, and older `aiohttp` versions vulnerable.
  - *Use `aiohttp` client middlewares:* Unavailable before `aiohttp` 3.12 and lacks redirect-chain origin state.

### 2. Normalized `(scheme, host, port)` origin check with monotonic latch

Define a helper `_url_origin(url: yarl.URL) -> tuple[str, str | None, int | None]` returning `(url.scheme.lower(), url.host.lower() if url.host else None, url.port)`. Because `yarl.URL.port` normalizes default ports (`80` for `http`, `443` for `https`), this avoids a verified `yarl` quirk where `yarl.URL("https://Example.COM:443/a").origin() == yarl.URL("https://example.com/b").origin()` evaluates to `False` due to `explicit_port=443` vs `None`.

Resolve relative initial URLs against `_base_url` (when configured) before determining `initial_origin`. Initialize a monotonic boolean `send_credentials`:
- If `_base_url_origin` is set: `send_credentials = (initial_origin == _base_url_origin)`
- Otherwise: `send_credentials = True`

On every redirect hop, compute `next_origin = _url_origin(next_url)`. If `next_origin != initial_origin`, latch `send_credentials = False` permanently for the remainder of the redirect chain. Once latched to `False`, credentials are never re-attached even if a later hop redirects back to `initial_origin` (defeating `trusted -> attacker -> trusted` bounce-back).

### 3. Strict RFC-safe header allowlist on cross-origin hops

Merge headers case-insensitively (using `multidict.CIMultiDict`, already a direct dependency of `aiohttp`) in precedence order:
1. `_session_headers` (from `client_kwargs["headers"]`)
2. `self.kwargs.get("headers")` (from `storage_options`)
3. Per-call `kwargs.get("headers")` (including operation-added headers like `Range`, `Accept-Encoding: identity`, `Content-Length`)

When `send_credentials` is `True`, attach merged headers, effective `auth` (per-call `auth` taking precedence over `_session_auth`), and effective `cookies` (merged per-call and `_session_cookies`).

When `send_credentials` transitions to `False`:
- Drop `auth` (`None`) and `cookies` (`None`).
- Filter headers to retain only names in `_CROSS_ORIGIN_SAFE_HEADERS` (`range`, `accept`, `accept-encoding`, `accept-language`, `user-agent`, `cache-control`, `if-none-match`, `if-modified-since`, `if-range`), plus `_BODY_HEADERS` (`content-type`, `content-length`) solely when the redirect preserves the request body.
- Strip any userinfo embedded in the URL on redirect if present.

- **Alternatives considered:**
  - *Denylist (`Authorization`, `Proxy-Authorization`, `Cookie` plus regex patterns):* Brittle against arbitrary API-key header names (`Ocp-Apim-Subscription-Key`, `X-Goog-Api-Key`, `Private-Token`, etc.) and fails to close CWE-522 by construction.
  - *Strip all headers including `Range` and `User-Agent`:* Breaks `HTTPFile` byte-range reads against redirected CDNs/presigned URLs, breaks `_file_info` uncompressed size detection (`Accept-Encoding: identity`), and breaks hosts requiring `User-Agent`.

### 4. Centralized `_request_with_redirects` helper and `HTTPFileSystem._request`

Implement a module-level async helper `_request_with_redirects(session, method, url, *, session_auth=None, session_headers=None, session_cookies=None, base_url=None, **kwargs) -> aiohttp.ClientResponse` and a thin `HTTPFileSystem._request(self, method, url, **kwargs)` method that ensures `session = await self.set_session()`, encodes the URL, and forwards `self._session_auth`, `self._session_headers`, `self._session_cookies`, and `self._base_url`.

Key mechanics inside `_request_with_redirects`:
- Extract `allow_redirects` (default `True`), `max_redirects` (default `10`), `params`, `headers`, `auth`, `cookies`, `data`, and `json` from `kwargs` (operating on copies so caller dicts are never mutated).
- Loop per hop calling `await session.request(method, current_url, allow_redirects=False, ...)`.
- If `not allow_redirects` or `resp.status not in (301, 302, 303, 307, 308)`: return `resp` directly.
- Look up `Location` (or `URI` fallback). If absent, return `resp` directly.
- Record `resp` in `history`, check `len(history) >= max_redirects` (closing `resp` and raising `aiohttp.TooManyRedirects(history[0].request_info, tuple(history))`).
- Release `resp` (`resp.release()`) before advancing to the next hop; on any parse/scheme/payload error, call `resp.close()` before raising.
- Parse redirect target with `yarl.URL(r_url, encoded=...)`; accept only schemes in `("http", "https", "")`, rejecting other schemes with `getattr(aiohttp, "NonHttpUrlRedirectClientError", aiohttp.ClientError)`. Resolve empty-scheme relative URLs via `current_url.join(parsed_redirect)`.
- Clear `params = None` after hop 0 so original query parameters are not re-appended to redirect URLs.
- Apply RFC 9110 method/body transition rules:
  - `303` (unless `method == "HEAD"`) or `301`/`302` with `method == "POST"`: switch `method = "GET"`, set `data = None`, `json = None`, and remove `Content-Length` and `Content-Type`.
  - `307`/`308` or non-`POST` `301`/`302`: preserve method and replayable body (`bytes`, `bytearray`, `memoryview`, `str`, `json`); if `data` is a non-replayable iterator/async-generator/stream (such as `_put_file`'s `gen_chunks()`), raise `aiohttp.ClientPayloadError`.

Call-site integration across all 12 sites:
- `HTTPFileSystem._ls_real`, `_cat_file`, `_get_file`, `_put_file`, `_exists`, `_pipe_file`: use `async with await self._request(...) as r:` (also fixing `_ls_real` to pass merged `kw` rather than `self.kwargs`, and `_pipe_file` to merge `self.kwargs`).
- `HTTPFile.async_fetch_all` and `HTTPFile.async_fetch_range`: call `await self.fs._request("GET", self.url, ...)` when using `self.fs` (or `_request_with_redirects(self.session, ...)` if `self.session` was overridden independently).
- `HTTPStreamFile.__init__` and `AsyncStreamFile.read`: call `r = await self.fs._request("GET", self.url, ...)` and keep `r` open until `close()`; if `_raise_not_found_for_status(r, url)` raises, close `r` before propagating so no unclosed response leaks.
- `_file_info` and `get_range`: route through `_request_with_redirects` (passing `HTTPFileSystem`'s hoisted session credentials when invoked from `HTTPFileSystem._info`, while remaining directly callable with a plain `session` argument).

Note on `HTTPFile` / `HTTPStreamFile` / `AsyncStreamFile` with explicit `session` parameter: if a caller passes a custom `session` different from `self.fs._session`, pass that `session` to `_request_with_redirects` alongside `self.fs`'s hoisted credentials (only when `session is self.fs._session`, avoiding applying `fs` defaults onto an unrelated injected session).

## Risks / Trade-offs

- **[Breaking behavior on cross-origin credentials or custom headers]** -> Callers relying on `BasicAuth`, cookies, or custom non-allowlisted headers being sent to a different origin after a redirect will see those stripped. Mitigation: same-origin redirects keep all credentials and headers unchanged, standard CDN/protocol headers (`Range`, `Accept-Encoding`, `User-Agent`, `Accept`, `If-*`) survive cross-origin redirects, and the security rationale is documented in `HTTPFileSystem` docstrings.
- **[Custom `get_client` pre-configuring `ClientSession(auth=..., headers=...)` directly]** -> Because `HTTPFileSystem` does not mutate private `aiohttp` attributes, session defaults baked inside a custom `get_client` body cannot be hoisted automatically. Mitigation: document in `HTTPFileSystem.__init__` that credentials should be supplied through `client_kwargs` / `storage_options` (or scoped with `base_url` in custom factories).
- **[Redirect loop parity with `aiohttp` edge cases]** -> Maintaining a custom redirect loop risks subtle drift on `history`, encoding, or exception types across `aiohttp` versions. Mitigation: follow `aiohttp`'s exact status-code set, `TooManyRedirects` / `ClientPayloadError` / redirect-error conventions, use `getattr` fallbacks for newer exception classes, and cover every edge case with unit tests.
- **[Local repository branch hygiene]** -> The working checkout is currently on `dircache_bug` (branched from Aug 2026 `master`, behind audited tag `2026.9.0`). Mitigation: create implementation changes on a fresh branch off up-to-date `master` / `2026.9.0`.
