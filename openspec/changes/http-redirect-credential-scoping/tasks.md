# Tasks

## 1. Hardened Origin Comparison & Redirect Trace Hook

- [x] 1.1 Implement `_url_origin`, convert `_REDIRECT_SAFE_HEADERS` to a `frozenset` including `"content-length"`, and harden `_strip_headers_on_cross_origin_redirect` in `fsspec/implementations/http.py`; verify with `venv/bin/pytest fsspec/implementations/tests/test_http.py -k "redirect or url_origin"`.

## 2. Session & Request Credential Normalization and `base_url` Origin Scoping

- [x] 2.1 Implement `_normalize_basic_auth`, `_hoist_unscoped_cookies`, `_make_base_url_origin_guard`, `_prepare_session_kwargs`, `storage_options["auth"]` normalization, and non-mutating `self.kwargs` merging in `_pipe_file`; verify with `venv/bin/pytest fsspec/implementations/tests/test_http.py -k "client_kwargs or redirect or base_url"`.
- [x] 2.2 Update `HTTPFileSystem` class and `__init__` docstrings in `fsspec/implementations/http.py` to document origin-scoped `auth`, cookie, and header handling and custom `get_client` responsibility; verify with `test_docstring` and AST/line-length checks.

## 3. End-to-End Entry-Point & Safe-Header Verification

- [x] 3.1 Add `two_origin_servers` fixture and end-to-end cross-origin tests in `fsspec/implementations/tests/test_http.py` covering `cat_file`, `get_file`, `info`, `exists`, `ls`, `put_file`, `pipe_file` (`307`/`308`/`303`/`302`), `HTTPFile`, `HTTPStreamFile`, `AsyncStreamFile`, `allow_redirects=False`, and `max_redirects`; verify via `venv/bin/pytest fsspec/implementations/tests/test_http.py -k cross_origin`.

## 4. Full Regression Verification

- [x] 4.1 Run `venv/bin/pytest fsspec/implementations/tests/test_http.py` (146 passed) and verify zero added lines >88 chars on branch `fix/http-redirect-credential-scoping`.

## Workflow follow-up

- Archive `http-redirect-credential-scoping` in `fsspec-store` (`openspec archive http-redirect-credential-scoping --store fsspec-store`) after implementation and PR review are complete.
