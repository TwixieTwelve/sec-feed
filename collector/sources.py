"""Универсальные загрузчики источников.

Модуль ничего не знает о конкретных сайтах: URL, селекторы, пути полей,
запросы и репозитории приходят из config/feeds.yaml через main.py.
Каждая fetch_*-функция возвращает список словарей
    {title, url, summary, published(datetime|None), tags[], cve?{...}}
Поля source/category проставляет main.py.
"""
from __future__ import annotations

import html
import os
import re
import time
import warnings
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

import feedparser
import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from dateutil import parser as dateparser

SUMMARY_LEN = 300

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

_session = requests.Session()
_timeout = 20


class SourceEmpty(Exception):
    """Источник ответил, но полезных данных в ответе нет."""


def configure(settings: dict) -> None:
    global _timeout
    _timeout = settings.get("request_timeout", 20)
    _session.headers["User-Agent"] = settings.get("user_agent", "sec-feed/1.0")


# --------------------------------------------------------------------------
# Утилиты
# --------------------------------------------------------------------------
def http_get(url, params=None, headers=None):
    r = _session.get(url, params=params, headers=headers, timeout=_timeout)
    r.raise_for_status()
    return r


def parse_date(value) -> datetime | None:
    if not value:
        return None
    try:
        if isinstance(value, time.struct_time):
            dt = datetime(*value[:6], tzinfo=timezone.utc)
        elif isinstance(value, datetime):
            dt = value
        else:
            dt = dateparser.parse(str(value))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None


def clean_text(raw, limit: int = SUMMARY_LEN) -> str:
    if not raw:
        return ""
    raw = str(raw)
    text = BeautifulSoup(raw, "html.parser").get_text(" ") if "<" in raw else raw
    text = re.sub(r"\s+", " ", html.unescape(text)).strip()
    if len(text) > limit:
        text = text[:limit].rsplit(" ", 1)[0] + "…"
    return text


def item(title, url, summary="", published=None, tags=None, cve=None) -> dict:
    out = {
        "title": clean_text(title, 300),
        "url": (url or "").strip(),
        "summary": clean_text(summary),
        "published": parse_date(published),
        "tags": [str(t) for t in (tags or []) if t][:8],
    }
    if cve:
        out["cve"] = cve
    return out


def dig(obj, path: str):
    """Значение по пути вида 'a.0.b' (индексы списков — числами)."""
    for part in path.split("."):
        if obj is None:
            return None
        if isinstance(obj, list):
            try:
                obj = obj[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


# --------------------------------------------------------------------------
# RSS / Atom
# --------------------------------------------------------------------------
def fetch_rss(url: str) -> list[dict]:
    r = http_get(url)
    feed = feedparser.parse(r.content)
    if not feed.entries:
        reason = f"не RSS/Atom ({r.headers.get('Content-Type', '?')})" if feed.bozo else "фид пуст"
        raise SourceEmpty(reason)
    out = []
    for e in feed.entries:
        summary = e.get("summary") or (e.content[0].get("value", "") if e.get("content") else "")
        published = e.get("published_parsed") or e.get("updated_parsed") or e.get("published")
        tags = [t.get("term") for t in e.get("tags", [])]
        out.append(item(e.get("title"), e.get("link"), summary, published, tags))
    return out


def discover_feed(site: str) -> str | None:
    """RSS autodiscovery по <link rel="alternate">."""
    soup = BeautifulSoup(http_get(site).text, "html.parser")
    for link in soup.select('link[rel="alternate"]'):
        kind = link.get("type") or ""
        if ("rss" in kind or "atom" in kind) and link.get("href"):
            return urljoin(site, link["href"])
    return None


# --------------------------------------------------------------------------
# HTML по CSS-селекторам
# --------------------------------------------------------------------------
def fetch_html(url: str, selectors: dict, base_url: str | None = None) -> list[dict]:
    """selectors: item (обязательно), title, link, date, summary.
    Если title совпадает с несколькими элементами, берётся самый длинный текст."""
    soup = BeautifulSoup(http_get(url).text, "html.parser")
    blocks = soup.select(selectors["item"])
    if not blocks:
        raise SourceEmpty(f"селектор {selectors['item']!r} ничего не нашёл")
    base = base_url or url
    out = []
    for b in blocks:
        titles = [t.get_text(" ", strip=True) for t in b.select(selectors.get("title", "a"))]
        title = max(titles, key=len, default="")
        link = b.select_one(selectors.get("link", "a[href]"))
        if not title or link is None or not link.get("href"):
            continue
        published = None
        if selectors.get("date") and (d := b.select_one(selectors["date"])):
            published = d.get("datetime") or d.get_text(strip=True)
        summary = ""
        if selectors.get("summary") and (s := b.select_one(selectors["summary"])):
            summary = s.get_text(" ", strip=True)
        out.append(item(title, urljoin(base, link["href"]), summary, published))
    return out


# --------------------------------------------------------------------------
# Произвольный JSON с маппингом полей
# --------------------------------------------------------------------------
def fetch_json(url: str, mapping: dict, items_path: str | None = None) -> list[dict]:
    """mapping: {title, url, summary?, published?, tags?} → пути полей в записи."""
    data = http_get(url).json()
    rows = dig(data, items_path) if items_path else data
    if not rows:
        raise SourceEmpty("пустой JSON")
    out = []
    for row in rows:
        get = lambda key: dig(row, mapping[key]) if mapping.get(key) else None  # noqa: E731
        tags = get("tags")
        out.append(item(get("title"), get("url"), get("summary"), get("published"),
                        tags if isinstance(tags, list) else []))
    return out


# --------------------------------------------------------------------------
# GitHub (публичный API; GITHUB_TOKEN из окружения — необязателен)
# --------------------------------------------------------------------------
def _gh(path: str, params=None):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    r = _session.get(f"https://api.github.com{path}", params=params, headers=headers, timeout=_timeout)
    if r.status_code in (403, 429) and r.headers.get("X-RateLimit-Remaining") == "0":
        raise RuntimeError("исчерпан лимит GitHub API (можно задать GITHUB_TOKEN)")
    r.raise_for_status()
    return r.json()


def fetch_github_search(query: str, since_days: int = 90, sort: str = "updated",
                        per_page: int = 20) -> list[dict]:
    """В query можно использовать {since} — подставится дата N дней назад."""
    since = (datetime.now(timezone.utc) - timedelta(days=since_days)).date().isoformat()
    data = _gh("/search/repositories", {"q": query.replace("{since}", since), "sort": sort,
                                        "order": "desc", "per_page": per_page})
    out = []
    for repo in data.get("items", []):
        desc = repo.get("description") or ""
        title = f"{repo['full_name']} — {desc}" if desc else repo["full_name"]
        summary = f"★{repo.get('stargazers_count', 0)} · {repo.get('language') or '—'} · {desc}"
        out.append(item(title, repo["html_url"], summary, repo.get("created_at"),
                        repo.get("topics", [])))
    return out


def fetch_github_releases(repo: str, per_page: int = 5) -> list[dict]:
    data = _gh(f"/repos/{repo}/releases", {"per_page": per_page})
    if not data:
        raise SourceEmpty("у репозитория нет релизов")
    out = []
    for rel in data:
        if rel.get("draft"):
            continue
        name = rel.get("name") or rel.get("tag_name")
        title = f"{repo} {rel.get('tag_name')}" + (f" — {name}" if name != rel.get("tag_name") else "")
        tags = ["release"] + (["prerelease"] if rel.get("prerelease") else [])
        out.append(item(title, rel["html_url"], rel.get("body") or "",
                        rel.get("published_at") or rel.get("created_at"), tags))
    return out


# --------------------------------------------------------------------------
# CVE-фиды
# --------------------------------------------------------------------------
def nvd_link(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def fetch_cve_kev(url: str) -> list[dict]:
    data = http_get(url).json()
    out = []
    for v in data.get("vulnerabilities", []):
        cve_id = v["cveID"]
        product = f"{v.get('vendorProject', '')} {v.get('product', '')}".strip()
        tags = ["KEV"]
        if v.get("knownRansomwareCampaignUse") == "Known":
            tags.append("ransomware")
        out.append(item(
            f"{cve_id}: {v.get('vulnerabilityName') or product}", nvd_link(cve_id),
            v.get("shortDescription"), v.get("dateAdded"), tags,
            cve={"id": cve_id, "kev": True, "product": product},
        ))
    return out


def _nvd_cvss(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            score = m.get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def fetch_cve_nvd(url: str, days: int = 3, min_cvss: float = 0.0,
                  page_size: int = 2000, page_delay: float = 6) -> list[dict]:
    """Недавно опубликованные CVE. Без ключа NVD ограничивает частоту — пауза между страницами."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
              "resultsPerPage": page_size, "startIndex": 0}
    out = []
    while True:
        data = http_get(url, params=params).json()
        for wrap in data.get("vulnerabilities", []):
            c = wrap["cve"]
            if c.get("vulnStatus") == "Rejected":
                continue
            cvss = _nvd_cvss(c.get("metrics", {}))
            kev = bool(c.get("cisaExploitAdd"))
            if not kev and (cvss is None or cvss < min_cvss):
                continue
            desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
            tags = [f"CVSS {cvss}"] if cvss is not None else []
            out.append(item(
                f"{c['id']}: {clean_text(desc, 120)}", nvd_link(c["id"]), desc,
                c.get("published"), tags,
                cve={"id": c["id"], "kev": kev, "cvss": cvss},
            ))
        total = data.get("totalResults", 0)
        params["startIndex"] += data.get("resultsPerPage", page_size) or page_size
        if params["startIndex"] >= total:
            break
        time.sleep(page_delay)
    return out


_SEVERITY = {"low": 1, "medium": 2, "moderate": 2, "high": 3, "critical": 4}


def fetch_github_advisories(params: dict | None = None, min_severity: str = "low") -> list[dict]:
    data = _gh("/advisories", params or {})
    floor = _SEVERITY.get(min_severity, 1)
    out = []
    for a in data:
        sev = (a.get("severity") or "").lower()
        if _SEVERITY.get(sev, 0) < floor:
            continue
        packages = sorted({(v.get("package") or {}).get("name") or "" for v in a.get("vulnerabilities", [])} - {""})
        cve_id = a.get("cve_id")
        score = (a.get("cvss") or {}).get("score")
        tags = [sev] + packages[:3]
        cve = {"id": cve_id, "kev": False, "cvss": score, "product": ", ".join(packages[:3])} if cve_id else None
        title = f"{cve_id or a['ghsa_id']}: {a.get('summary', '')}"
        out.append(item(title, a.get("html_url"), a.get("description") or a.get("summary"),
                        a.get("published_at"), tags, cve=cve))
    return out


# --------------------------------------------------------------------------
# EPSS — обогащение
# --------------------------------------------------------------------------
def enrich_epss(cve_ids, url: str = "https://api.first.org/data/v1/epss",
                batch_size: int = 50) -> dict[str, dict]:
    """Возвращает {cve_id: {"epss": float, "percentile": float}}. Принимает один id или список."""
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]
    ids = sorted(set(cve_ids))
    result = {}
    for i in range(0, len(ids), batch_size):
        chunk = ids[i:i + batch_size]
        data = http_get(url, params={"cve": ",".join(chunk), "limit": len(chunk)}).json()
        for row in data.get("data", []):
            result[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
    return result
