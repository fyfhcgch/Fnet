# AGENTS.md

Fnet is a stdlib-only Python CTF/forensics traffic analyser. One core (`fnet/app.py`) powers both the local WebUI and the headless CLI; `tshark` does all protocol parsing. User-facing docs, UI strings and log assertions are in Chinese — keep them consistent.

## Commands

- Runtime needs Python >= 3.10 and `tshark` on `PATH`. **No third-party Python package is needed to run Fnet**; avoid adding one.
- Run from the repo root: `python3 -m fnet --no-browser`.
- Headless: `python3 -m fnet -C capture.pcapng --features checkBox_10,webshell.decrypt --param key=value`.
- Introspection: `--list-features`, `--list-tools`, `--doctor`.
- Isolate dev runs with `FNET_HOME=/tmp/fnet-dev ...`; otherwise config/logs/cache go to XDG dirs (`~/.cache/fnet/jobs/<id>/`, `~/.local/state/fnet/logs/`).
- Tests: `python3 -m unittest discover -s tests -v`
  - One test: `python3 -m unittest tests.test_codec.CodecTest.test_base64 -v`
  - One file: `python3 -m unittest discover -s tests -p 'test_crypto.py'`
- Full suite needs `tshark`: `test_features` skips without it, but `test_api` does not.
- `tests/data/*.pcap` are tracked fixtures. Regenerate intentionally with `python3 scripts/make_samples.py`; that needs scapy (`python3 -m pip install -e '.[samples]'`).
- No lint/typecheck/formatter/CI config exists. Don't invent a lint command.

## Architecture

- `fnet/app.py:build()` wires `Config`, `ToolBox`, `JobManager`, `PluginManager`, `FnetApp`. WebUI, CLI and tests share it; don't create parallel wiring.
- `fnet/report.py` renders `report.txt`/`report.md`/`report.html` with the standard library only; it must HTML-escape all capture-derived text. `GET /api/report` reuses it for live and restored jobs.
- `fnet/features/registry.py:FEATURES` is the only feature catalogue: currently exactly **54 features / 14 categories / 2 defaults**. `tests/test_registry.py` and `tests/test_api.py` assert those counts; the WebUI sidebar renders straight from `GET /api/meta`, so there is no static checkbox spec to maintain. Log inputs (`.log`/`.txt`/`.jsonl`/`.csv`) are parsed by `fnet/utils/logfile.py` and default to the four `log` features instead of the two pcap defaults.
- Optional acceleration layer: `fnet/utils/accel.py` may use third-party deps **only** via the pyproject `accel` extras (`numba`/`cupy`); it probes cuda → cpu-jit → pure Python at runtime and silently falls back, so the stdlib-only core promise is unchanged. Never import accel deps unconditionally in feature code.
- Handlers are module-level functions taking `FeatureContext`, registered as `"module.function"`. Use `tshark_rows`/`table`/`csv_rows` from `fnet/features/common.py` instead of spawning tshark directly. Report with `ctx.report`, save artifacts with `ctx.write_output`, and call `ctx.check_cancel()` inside loops.
- Notable discoveries are also recorded with `ctx.add_finding(kind, summary, frame=..., detail=...)`; `fnet/findings.py` defines the record shape and `JobManager` writes `findings.json`/`findings.csv` per job and serves them via `GET /api/findings`. Keep the log line and the finding in sync.
- `GET /api/packet` (see `fnet/services.py`) resolves a job's pcap via `JobManager.pcap_for()` and returns frame context or a pcapng clip under `<job>/frames/`. Frame numbers in logs and the findings table are rendered as clickable `.frame-link` buttons; `open_wireshark` is a fixed POST action that only launches the configured Wireshark binary.
- Checkbox IDs are sparse fixed identifiers (`checkBox_10` … `checkBox_56`), not sequential. Never renumber or “tidy” them.
- Not every handler has a checkbox: `webshell.decrypt` and `flows.http_login` are valid selections via `--features` or `POST /api/analyze`.
- Adding/removing a feature means updating `FEATURES`, the exact-count tests, and `docs/FEATURES.md`/README. Trust `FEATURES` over prose when they disagree.
- WebUI is stdlib `ThreadingHTTPServer` in `fnet/webui/server.py`; the SPA is `fnet/webui/static/{index.html,app.js,style.css}`. All `/api/*` except `/api/health` require `X-Fnet-Token` (or `?token=`). The token is generated per process and substituted into `index.html` as `__TOKEN__`. Errors are `{"ok": false, "error": "..."}`.
- `fnet/tools/runner.py` resolves/runs external tools. `TShark.fields()` silently drops field names the installed tshark doesn't know and re-inserts empty columns to preserve positions. Keep subprocess calls argument-array/shell-free for Windows compatibility.
- Keep the version in sync in `pyproject.toml` and `fnet/__init__.py` (`__version__`).
- Path contract: `FNET_HOME` relocates user config/logs/cache, `FNET_ASSETS` overrides bundled assets, `FNET_TOOLS` adds portable helper binaries.

## Testing gotchas

- Job/API tests that write outputs must patch **both** `fnet.jobs.CACHE_DIR` and `fnet.paths.CACHE_DIR` to a temp dir (see `tests/test_api.py`); patching one leaks files into the real cache.
- A failing handler is logged and the job continues by design. Assert on log text/artifacts, not on raised exceptions.
- For manual HTTP checks, fetch `/`, extract the injected token, then send `X-Fnet-Token`; `/api/health` is the only public endpoint.
