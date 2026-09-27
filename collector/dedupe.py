"""Дедупликация: по нормализованному URL, по CVE-id внутри категории
и по похожести заголовков (Жаккар по множествам токенов)."""
from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TRACKING = re.compile(r"^(utm_|fbclid$|gclid$|mc_|ref$|ref_src$|source$)")
STOPWORDS = {"a", "an", "the", "and", "or", "of", "in", "on", "for", "to", "with", "by",
             "is", "are", "as", "at", "from", "new", "how", "its", "it", "via", "into"}
SIMILARITY = 0.75
MIN_TOKENS = 4


def normalize_url(url: str) -> str:
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip().lower()
    host = p.netloc.lower().removeprefix("www.")
    query = urlencode(sorted((k, v) for k, v in parse_qsl(p.query) if not TRACKING.match(k)))
    path = p.path.rstrip("/") or "/"
    return urlunsplit(("https", host, path, query, ""))


def title_tokens(title: str) -> frozenset:
    words = re.findall(r"[a-z0-9]+(?:-[a-z0-9]+)*", title.lower())
    return frozenset(w for w in words if w not in STOPWORDS and len(w) > 1)


def item_key(it: dict) -> str:
    cve = it.get("cve") or {}
    return f"{it['category']}:{cve['id']}" if cve.get("id") else normalize_url(it["url"])


def item_id(it: dict) -> str:
    return hashlib.sha1(item_key(it).encode()).hexdigest()[:12]


def _merge(dst: dict, src: dict) -> None:
    for s in src.get("sources", [src["source"]]):
        if s not in dst["sources"]:
            dst["sources"].append(s)
    dst["tags"] = list(dict.fromkeys(dst.get("tags", []) + src.get("tags", [])))
    if len(src.get("summary", "")) > len(dst.get("summary", "")):
        dst["summary"] = src["summary"]
    if src.get("published") and (not dst.get("published") or src["published"] < dst["published"]):
        dst["published"] = src["published"]
    if src.get("first_seen") and (not dst.get("first_seen") or src["first_seen"] < dst["first_seen"]):
        dst["first_seen"] = src["first_seen"]
    for k in ("title_ru", "summary_ru"):
        if src.get(k) and not dst.get(k):
            dst[k] = src[k]
    if src.get("cve"):
        a, b = dst.setdefault("cve", {}), src["cve"]
        for k, v in b.items():
            if k in ("kev", "poc"):
                a[k] = bool(a.get(k)) or bool(v)
            elif v is not None and a.get(k) in (None, ""):
                a[k] = v


def dedupe(items: list[dict]) -> list[dict]:
    by_key: dict[str, dict] = {}
    for it in items:
        it.setdefault("sources", [it["source"]])
        key = item_key(it)
        if key in by_key:
            _merge(by_key[key], it)
        else:
            by_key[key] = it

    # Похожие заголовки: кандидаты через инвертированный индекс токенов.
    result, index = [], {}
    for it in by_key.values():
        toks = title_tokens(it["title"])
        dup = None
        if len(toks) >= MIN_TOKENS and not it.get("cve"):
            for cand in {i for t in toks for i in index.get(t, ())}:
                other = result[cand]
                otoks = title_tokens(other["title"])
                if other.get("cve") or len(otoks) < MIN_TOKENS:
                    continue
                if len(toks & otoks) / len(toks | otoks) >= SIMILARITY:
                    dup = other
                    break
        if dup:
            _merge(dup, it)
            continue
        for t in toks:
            index.setdefault(t, []).append(len(result))
        result.append(it)

    for it in result:
        it["id"] = item_id(it)
    return result
