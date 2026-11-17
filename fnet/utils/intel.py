"""Optional online IOC enrichment (VirusTotal / AlienVault OTX).

默认完全离线：只有用户在配置文件 ``[intel]`` 节里显式填写了 API key
才会发出网络请求；key 仅保存在内存与用户配置文件里，绝不写入日志、
findings 或报告。所有请求走 :mod:`urllib.request`，保持 stdlib-only。

查询结果归一化为统一的 dict：

* ``value`` / ``type`` —— 指标本身（ip / domain / hash）
* ``provider`` —— ``vt`` 或 ``otx``
* ``ok`` —— 请求与解析是否成功
* ``malicious`` —— 按阈值判定（VT 恶意引擎数、OTX pulse 数）
* ``score`` —— 人类可读的判定摘要（中文）
* ``detail`` —— 归一化统计（不含任何凭据信息）
* ``error`` —— 失败原因（已做 key 脱敏）
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from fnet import findings as findings_mod

#: VirusTotal v3 endpoints.  ``vt_base``/``otx_base`` are parameters so the
#: tests can point the client at a local ``http.server`` instead.
VT_BASE = "https://www.virustotal.com/api/v3"
OTX_BASE = "https://otx.alienvault.com/api/v1"

#: VT 公共 API 配额是 4 req/min —— 请求间隔不得低于 15 秒。
VT_MIN_INTERVAL = 15.0

#: URL-safe User-Agent；不含任何版本指纹之外的敏感信息。
USER_AGENT = "fnet-intel/1.0"

_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,12}$",
    re.IGNORECASE)

#: report.ioc_rows 的中文类别 → 归一化指标类型。
IOC_ROW_KINDS = {"IP": "ip", "域名": "domain",
                 "MD5": "hash", "SHA1": "hash", "SHA256": "hash"}


# -- helpers -----------------------------------------------------------
def detect_type(value: str) -> str:
    """Classify an indicator as ``ip`` / ``hash`` / ``domain`` (else ``""``)."""
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if _MD5_RE.fullmatch(text) or _SHA1_RE.fullmatch(text) \
            or _SHA256_RE.fullmatch(text):
        return "hash"
    if _DOMAIN_RE.match(text):
        return "domain"
    return ""


def redact(text: str, *secrets: str) -> str:
    """Remove any configured API key from an error message or log line."""
    out = str(text or "")
    for secret in secrets:
        if secret and str(secret) in out:
            out = out.replace(str(secret), "[redacted]")
    return out


class RateLimiter:
    """Minimal-interval limiter shared across threads (wall-clock based)."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = max(0.0, float(min_interval))
        self._lock = threading.Lock()
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            delay = self.min_interval - (now - self._last)
            if delay > 0:
                time.sleep(delay)
                now = time.monotonic()
            self._last = now


# -- provider queries --------------------------------------------------
def _fetch_json(url: str, headers: dict[str, str],
                timeout: float, limiter: RateLimiter | None = None,
                secrets: tuple[str, ...] = ()) -> dict:
    """GET a JSON document, raising ``IntelError`` on any failure."""
    if limiter is not None:
        limiter.wait()
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(4 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            with exc:
                detail = exc.read(2000).decode("utf-8", "replace")
        except OSError:
            pass
        raise IntelError(f"HTTP {exc.code}: {redact(detail, *secrets)[:200]}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise IntelError(redact(str(exc), *secrets))
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        raise IntelError(f"响应不是合法 JSON: {redact(str(exc), *secrets)}")
    if not isinstance(data, dict):
        raise IntelError("响应结构异常：顶层不是 JSON 对象")
    return data


class IntelError(Exception):
    """Raised when an online lookup fails (network/HTTP/parse)."""


def query_vt(value: str, ioc_type: str, api_key: str, *, timeout: float = 10.0,
             base: str = VT_BASE, limiter: RateLimiter | None = None) -> dict:
    """Query VirusTotal v3 and return a normalised verdict dict."""
    paths = {"ip": "ip_addresses", "domain": "domains", "hash": "files"}
    section = paths.get(ioc_type)
    if not section:
        return _bad_type(value, ioc_type, "vt")
    url = f"{base}/{section}/{urllib.parse.quote(value)}"
    try:
        data = _fetch_json(
            url, {"x-apikey": api_key, "User-Agent": USER_AGENT},
            timeout, limiter, secrets=(api_key,))
    except IntelError as exc:
        return _failed(value, ioc_type, "vt", str(exc))
    attributes = data.get("data") or {}
    if not isinstance(attributes, dict):
        attributes = {}
    attributes = attributes.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}
    if not isinstance(stats, dict):
        stats = {}
    malicious = _to_int(stats.get("malicious"))
    suspicious = _to_int(stats.get("suspicious"))
    harmless = _to_int(stats.get("harmless"))
    undetected = _to_int(stats.get("undetected"))
    total = malicious + suspicious + harmless + undetected
    return {
        "value": value, "type": ioc_type, "provider": "vt", "ok": True,
        "malicious": None,  # filled in by the caller's threshold
        "malicious_engines": malicious,
        "suspicious_engines": suspicious,
        "engines_total": total,
        "reputation": _to_int(attributes.get("reputation")),
        "score": f"VT: {malicious}/{total} 引擎判定恶意"
                 + (f"，{suspicious} 可疑" if suspicious else ""),
        "detail": {"malicious": malicious, "suspicious": suspicious,
                   "harmless": harmless, "undetected": undetected},
        "error": "",
    }


def query_otx(value: str, ioc_type: str, api_key: str, *, timeout: float = 10.0,
              base: str = OTX_BASE, limiter: RateLimiter | None = None) -> dict:
    """Query AlienVault OTX ``/general`` and return a normalised verdict dict."""
    paths = {"ip": "IPv4", "domain": "domain", "hash": "file"}
    section = paths.get(ioc_type)
    if not section:
        return _bad_type(value, ioc_type, "otx")
    url = f"{base}/indicators/{section}/{urllib.parse.quote(value)}/general"
    try:
        data = _fetch_json(
            url, {"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT},
            timeout, limiter, secrets=(api_key,))
    except IntelError as exc:
        return _failed(value, ioc_type, "otx", str(exc))
    pulse_info = data.get("pulse_info") or {}
    if not isinstance(pulse_info, dict):
        pulse_info = {}
    pulses = pulse_info.get("pulses") or []
    if not isinstance(pulses, list):
        pulses = []
    names = [str(p.get("name") or "") for p in pulses if isinstance(p, dict)][:5]
    count = _to_int(pulse_info.get("count")) or len(pulses)
    score = f"OTX: {count} 个 pulse" if count else "OTX: 无 pulse 关联"
    return {
        "value": value, "type": ioc_type, "provider": "otx", "ok": True,
        "malicious": None,
        "pulses": count,
        "pulse_names": names,
        "score": score,
        "detail": {"pulses": count, "names": names},
        "error": "",
    }


# -- client ------------------------------------------------------------
def _to_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _bad_type(value: str, ioc_type: str, provider: str) -> dict:
    return {"value": value, "type": ioc_type or "", "provider": provider,
            "ok": False, "malicious": None, "score": "", "detail": {},
            "error": f"无法识别指标类型: {value}"}


def _failed(value: str, ioc_type: str, provider: str, error: str) -> dict:
    return {"value": value, "type": ioc_type, "provider": provider,
            "ok": False, "malicious": None, "score": "", "detail": {},
            "error": error}


class IntelClient:
    """Offline-unless-configured IOC lookup client.

    构造时不传任何 key（默认行为）则 :attr:`enabled` 为 ``False``，
    :meth:`lookup` 直接返回离线结果且**不产生任何网络行为**。
    """

    def __init__(self, *, vt_key: str = "", otx_key: str = "",
                 provider: str = "", vt_min_malicious: int = 3,
                 otx_min_pulses: int = 1, timeout: float = 10.0,
                 vt_interval: float = VT_MIN_INTERVAL,
                 vt_base: str = VT_BASE, otx_base: str = OTX_BASE) -> None:
        self.vt_key = str(vt_key or "").strip()
        self.otx_key = str(otx_key or "").strip()
        self.provider = str(provider or "").strip().lower()
        self.vt_min_malicious = max(0, int(vt_min_malicious))
        self.otx_min_pulses = max(0, int(otx_min_pulses))
        self.timeout = max(1.0, float(timeout))
        self.vt_base = vt_base.rstrip("/")
        self.otx_base = otx_base.rstrip("/")
        self._vt_limiter = RateLimiter(vt_interval)
        self._otx_limiter = RateLimiter(0.0)
        #: value -> normalised result; avoids re-querying the same IOC.
        self.cache: dict[str, dict] = {}
        self.queries = 0

    # -- construction --------------------------------------------------
    @classmethod
    def from_config(cls, config) -> "IntelClient":
        """Build from the ``[intel]`` config section (offline by default)."""
        return cls(
            vt_key=config.get("vt_api_key", "intel"),
            otx_key=config.get("otx_api_key", "intel"),
            provider=config.get("provider", "intel"),
            vt_min_malicious=config.get_int("vt_min_malicious", "intel", 3),
            otx_min_pulses=config.get_int("otx_min_pulses", "intel", 1),
            timeout=config.get_float("timeout", "intel", 10.0),
            vt_interval=config.get_float("vt_interval", "intel",
                                         VT_MIN_INTERVAL),
        )

    @property
    def enabled(self) -> bool:
        """True only when the user explicitly configured at least one key."""
        return bool(self.vt_key or self.otx_key)

    def _secrets(self) -> tuple[str, ...]:
        return (self.vt_key, self.otx_key)

    def _apply_thresholds(self, result: dict) -> dict:
        if not result.get("ok"):
            return result
        provider = result.get("provider")
        if provider == "vt":
            engines = result.get("malicious_engines") or 0
            result["malicious"] = engines >= self.vt_min_malicious \
                and engines > 0
        elif provider == "otx":
            pulses = result.get("pulses") or 0
            result["malicious"] = pulses >= self.otx_min_pulses and pulses > 0
        return result

    # -- lookups -------------------------------------------------------
    def lookup(self, value: str, ioc_type: str | None = None,
               providers: list[str] | None = None) -> list[dict]:
        """Look one indicator up on every configured provider.

        没有配置任何 key 时返回单个离线占位结果，零网络请求。
        """
        value = str(value or "").strip()
        kind = ioc_type or detect_type(value)
        if not kind:
            return [_bad_type(value, ioc_type or "", "intel")]
        wanted = providers or self._active_providers()
        if not wanted:
            return [{"value": value, "type": kind, "provider": "intel",
                     "ok": False, "malicious": None, "score": "",
                     "detail": {},
                     "error": "未配置情报 API，保持离线（[intel] 节填写 "
                              "api key 后启用）"}]
        results: list[dict] = []
        cache_key = f"{kind}:{value.lower()}"
        cached = self.cache.get(cache_key)
        if cached is None:
            cached = {}
            for provider in wanted:
                self.queries += 1
                if provider == "vt" and self.vt_key:
                    result = query_vt(value, kind, self.vt_key,
                                      timeout=self.timeout,
                                      base=self.vt_base,
                                      limiter=self._vt_limiter)
                elif provider == "otx" and self.otx_key:
                    result = query_otx(value, kind, self.otx_key,
                                       timeout=self.timeout,
                                       base=self.otx_base,
                                       limiter=self._otx_limiter)
                else:
                    continue
                cached[provider] = self._apply_thresholds(result)
        else:
            cached = dict(cached)
        results.extend(cached.values())
        self.cache[cache_key] = {
            provider: dict(result) for provider, result in cached.items()}
        return results

    def _active_providers(self) -> list[str]:
        if self.provider in ("vt", "otx"):
            keys = {"vt": self.vt_key, "otx": self.otx_key}
            return [name for name in (self.provider,) if keys.get(name)]
        wanted: list[str] = []
        if self.vt_key:
            wanted.append("vt")
        if self.otx_key:
            wanted.append("otx")
        return wanted

    def lookup_many(self, values) -> list[dict]:
        """Look a list of indicators up, skipping unknown types."""
        results: list[dict] = []
        for value in values or []:
            results.extend(self.lookup(value))
        return results

    def query_ioc_rows(self, rows) -> list[dict]:
        """Query the output of :func:`fnet.report.ioc_rows` offline rows.

        每行是 ``(kind, value, count, feature)``；URL 不参与在线查询
        （VT/OTX 均不直接支持 URL 泛查，提取其主机名即可另行命中）。
        """
        values: list[str] = []
        seen: set[str] = set()
        for row in rows or []:
            if not row:
                continue
            kind, value = row[0], row[1]
            if IOC_ROW_KINDS.get(str(kind)) is None:
                continue
            key = f"{kind}:{str(value).lower()}"
            if key in seen:
                continue
            seen.add(key)
            values.append(str(value))
        return self.lookup_many(values)


# -- findings write-back -------------------------------------------------
def enrich_findings(results, findings: list | None = None,
                    *, feature: str = "intel") -> list[dict]:
    """Append one finding per malicious intel verdict; return the added items.

    Pure function over a findings list, so callers (CLI / future
    JobManager wiring / plugin) can invoke it without touching
    :mod:`fnet.jobs`.  Benign verdicts are recorded at ``debug`` level,
    query failures at ``debug``; only genuinely malicious IOCs surface
    at ``warn``.  Results never contain the API key, so nothing secret
    can leak into findings or reports here.
    """
    added: list[dict] = []
    for result in results or []:
        if not isinstance(result, dict) or not result.get("ok"):
            continue
        level = "warn" if result.get("malicious") else "debug"
        provider = result.get("provider") or "intel"
        item = findings_mod.make(
            "other",
            f"情报: {result.get('value')} ({result.get('score') or '未知判定'})",
            detail=json.dumps(result.get("detail") or {},
                              ensure_ascii=False, sort_keys=True),
            level=level,
            feature=f"{feature}.{provider}",
        )
        added.append(item)
        if findings is not None:
            findings.append(item)
    return added


def enrich_job(job, client: IntelClient, *, limit: int = 50) -> int:
    """Query IOCs for an analysed job and append findings in place.

    Expected job shape: ``job.findings`` (list) plus ``job.log`` with the
    usual ``info``/``warn`` methods — i.e. exactly
    :class:`fnet.jobs.Job`.  Suggested wiring point (kept out of this
    module on purpose): call it in ``JobManager._run_job`` right before
    ``_write_findings(job)`` so the enriched records land in the same
    ``findings.json``/``findings.csv`` flush::

        if intel_client.enabled:
            enrich_job(job, intel_client)

    Returns the number of findings appended; offline clients append
    nothing and log a single debug line.
    """
    findings_list = getattr(job, "findings", None)
    log = getattr(job, "log", None)
    if findings_list is None:
        return 0
    if not client.enabled:
        if log is not None:
            log.debug("在线情报未配置，保持离线")
        return 0
    from fnet.report import ioc_rows  # local import avoids a cycle at load
    rows = ioc_rows(findings_list)
    if not rows:
        return 0
    results = client.query_ioc_rows(rows[:limit])
    added = enrich_findings(results, findings_list)
    malicious = sum(1 for result in results
                    if result.get("ok") and result.get("malicious"))
    failed = sum(1 for result in results if not result.get("ok"))
    if log is not None:
        message = (f"在线情报查询 {len(results)} 个 IOC："
                   f"{malicious} 恶意，{failed} 失败，"
                   f"新增结果 {len(added)} 条")
        if malicious:
            log.warn(message)
        else:
            log.info(message)
    return len(added)
