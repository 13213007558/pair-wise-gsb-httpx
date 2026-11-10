# Feedback task starting environment

Upstream: https://github.com/encode/httpx
Upstream commit: `b5addb64f0161ff6bfe94c124ef76f6a1fba5254`
Prepared on macOS with CPython 3.12.11. No external database, queue, or cloud account is required.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_auth.py tests/test_config.py tests/test_asgi.py tests/test_wsgi.py tests/client/test_event_hooks.py tests/client/test_redirects.py -k 'not test_SSLContext_with_get_request and not test_event_hooks_raising_exception'
```

Scope note: In-memory auth/config/ASGI/WSGI/hooks/redirect tests; excludes both tests using the upstream fixed-port server fixture: test_SSLContext_with_get_request and test_event_hooks_raising_exception. No application source or test was changed.

Observed baseline (2026-11-10): `110 passed, 2 deselected in 0.15s`
Whole-command wall time: 0.497 seconds, exit code 0. First installation excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
