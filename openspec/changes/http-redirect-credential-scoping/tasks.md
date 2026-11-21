# Tasks

## 1. Hardened Origin Comparison & Redirect Trace Hook

- [x] 1.1 Implement `_url_origin`, convert `_REDIRECT_SAFE_HEADERS` to a `frozenset` including `"content-length"`, and harden `_strip_headers_on_cross_origin_redirect` in `fsspec/implementations/http.py`; verify with `venv/bin/pytest fsspec/implementations/tests/test_http.py -k "redirect or url_origin"`.

## 2. Session Credential Normalization and `base_url` Origin Scoping

- [x] 2.1 Implement `_normalize_basic_auth` (for `client_kwargs["auth"]`), `_hoist_unscoped_cookies`, `_make_base_url_origin_guard`, `_prepare_session_kwargs`, and non-mutating `self.kwargs` merging in `_pipe_file` (leaving per-request `storage_options["auth"]` to `aiohttp`); verify with `venv/bin/pytest fsspec/implementations/tests/test_http.py -k "client_kwargs or redirect or base_url"`.
- [x] 2.2 Update `HTTPFileSystem` class and `__init__` docstrings in `fsspec/implementations/http.py` to document origin-scoped `auth`, cookie, and header handling and custom `get_client` responsibility; verify with `test_docstring` and AST/line-length checks.

## 3. End-to-End Entry-Point & Safe-Header Verification

- [x] 3.1 Add `two_origin_servers` fixture and single-purpose AAA parameterized tests in `fsspec/implementations/tests/test_http.py` covering `_url_origin`, redirect header filtering, malformed/non-HTTP `Location` handling, `client_kwargs` immutability, `auth`+`Authorization` conflict, same-origin vs. cross-origin/bounce-back redirects, `Morsel`/`DummyCookieJar` cookie handling, `base_url` scoping, read operations (`cat_file`, range, `get_file`, `info`, `exists`, `ls`, `open` buffered/stream via `_run_read_op`), `pipe_file` (`307`/`308`), `put_file` (`302`/`303`), and `open_async`; verify via `venv/bin/pytest fsspec/implementations/tests/test_http.py -k cross_origin`.

## 4. Full Regression Verification

- [x] 4.1 Run `venv/bin/pytest fsspec/implementations/tests/test_http.py -q` (180 passed) and verify zero added lines >88 chars on branch `fix/http-redirect-credential-scoping` (commit `9f07c2a`).

## Workflow follow-up

- Archive `http-redirect-credential-scoping` in `fsspec-store` (`openspec archive http-redirect-credential-scoping --store fsspec-store`) after implementation and PR review are complete.
