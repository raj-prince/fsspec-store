# Tasks

## 1. Core Origin & Redirect Request Engine

- [ ] 1.1 Implement `_url_origin`, `_CROSS_ORIGIN_SAFE_HEADERS`, `_BODY_HEADERS`, case-insensitive header merging and cross-origin filtering, and `_request_with_redirects` in `fsspec/implementations/http.py` (supporting `allow_redirects`, `max_redirects`, monotonic origin latch, relative `Location` resolution, non-HTTP scheme rejection, `params` clearing, `301`/`302`/`303`/`307`/`308` method and body rules, and intermediate response cleanup); verify with unit tests in `fsspec/implementations/tests/test_http.py` covering same-origin, explicit-default-port, host/port/scheme cross-origin, bounce-back, relative `Location`, non-HTTP scheme, `allow_redirects=False`, `max_redirects`, query `params`, and `301`/`302`/`303`/`307`/`308` body handling via `pytest fsspec/implementations/tests/test_http.py -k redirect`.

## 2. Session Credential Hoisting & `HTTPFileSystem._request`

- [ ] 2.1 Update `HTTPFileSystem.__init__` and `HTTPFileSystem.set_session` in `fsspec/implementations/http.py` to copy `self.client_kwargs` without mutation, hoist `auth`, `headers`, and `cookies` off `aiohttp.ClientSession` defaults, record optional `base_url` origin, and add `HTTPFileSystem._request`; verify with unit tests confirming caller `client_kwargs` is unmutated, `ClientSession` receives no hoisted credential defaults, and `base_url` scopes session credentials to the configured origin (`pytest fsspec/implementations/tests/test_http.py -k "client_kwargs or base_url"`).
- [ ] 2.2 Update `HTTPFileSystem` docstrings in `fsspec/implementations/http.py` to document origin-scoped credential and header handling across redirects and caller responsibility when a custom `get_client` embeds credentials directly into a `ClientSession`; verify docstring formatting and lint compliance with `ruff check fsspec/implementations/http.py`.

## 3. Migrate All Request Call Sites in `http.py`

- [ ] 3.1 Route `HTTPFileSystem._ls_real`, `_cat_file`, `_get_file`, `_put_file`, `_exists`, `_pipe_file`, and `_info` (along with standalone `_file_info` and `get_range`) through `HTTPFileSystem._request` / `_request_with_redirects` (including merging per-call `kw` in `_ls_real` and `self.kwargs` in `_pipe_file`); verify with cross-origin two-server tests in `fsspec/implementations/tests/test_http.py` exercising `client_kwargs["auth"]`, `client_kwargs["headers"]`, `client_kwargs["cookies"]`, and `storage_options` `headers` (including `X-API-Key`) across all filesystem methods and confirming `Accept-Encoding: identity` survives cross-origin `info` redirects while credentials are stripped.
- [ ] 3.2 Route `HTTPFile.async_fetch_all`, `HTTPFile.async_fetch_range`, `HTTPStreamFile.__init__`, and `AsyncStreamFile.read` through `self.fs._request` / `_request_with_redirects` (ensuring open streaming responses are closed if status validation raises); verify with cross-origin tests covering seekable `HTTPFile` byte-range reads (`Range` preserved, credentials stripped), `HTTPStreamFile` (`block_size=0`), and `AsyncStreamFile` (`open_async`) via `pytest fsspec/implementations/tests/test_http.py`.

## 4. Full Verification & Regression Suite

- [ ] 4.1 Run the complete HTTP test suite and linter (`pytest fsspec/implementations/tests/test_http.py` and `ruff check fsspec/implementations/http.py fsspec/implementations/tests/test_http.py`) on a clean implementation branch based on up-to-date `master` / `2026.9.0` and verify all tests pass with no regressions or unclosed-response warnings.

## Workflow follow-up

- Archive `http-redirect-credential-scoping` in `fsspec-store` (`openspec archive http-redirect-credential-scoping --store fsspec-store`) after implementation and PR review are complete.
