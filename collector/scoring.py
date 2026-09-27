"""Оценка важности. Все слова, веса и пороги — из секции `scoring:` в feeds.yaml."""
from __future__ import annotations

import re
from datetime import datetime


def _compile(phrases):
    return {p: re.compile(r"(?<![\w-])" + re.escape(p.lower()) + r"(?![\w-])") for p in phrases}


class Scorer:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.default_weight = cfg.get("keyword_weight", 8)
        self.keywords = {k: (w if w is not None else self.default_weight)
                         for k, w in (cfg.get("keywords") or {}).items()}
        self.kw_re = _compile(self.keywords)
        self.products_re = _compile(cfg.get("popular_products") or [])

    def _text(self, it) -> str:
        parts = [it.get("title", ""), it.get("summary", ""), " ".join(it.get("tags", []))]
        if it.get("cve"):
            parts.append(it["cve"].get("product") or "")
        return " ".join(parts).lower()

    def score(self, it: dict, now: datetime) -> dict:
        c = self.cfg
        text = self._text(it)
        score = (c.get("category_base") or {}).get(it["category"], 0)

        matched = [k for k, rx in self.kw_re.items() if rx.search(text)]
        score += min(sum(self.keywords[k] for k in matched), c.get("keyword_cap", 50))

        cve = it.get("cve")
        badges = []
        if cve:
            w = c.get("cve") or {}
            if cve.get("kev"):
                score += w.get("kev", 0); badges.append("KEV")
            epss = cve.get("epss")
            if epss is not None and epss > w.get("epss_threshold", 0.5):
                score += w.get("epss", 0); badges.append("EPSS")
            if cve.get("poc"):
                score += w.get("poc", 0); badges.append("PoC")
            if any(rx.search(text) for rx in self.products_re.values()):
                score += w.get("popular_product", 0)
            cvss = cve.get("cvss")
            if cvss is not None:
                score += w.get("cvss_critical", 0) if cvss >= 9 else w.get("cvss_high", 0) if cvss >= 7 else 0

        published = it.get("published")
        if published:
            age_days = max((now - published).total_seconds() / 86400, 0)
            decay = c.get("fresh_decay_days", 14)
            score += c.get("fresh_max", 15) * max(0.0, 1 - age_days / decay)

        importance = int(round(max(0, min(100, score))))
        it["importance"] = importance
        it["is_hot"] = bool((cve and cve.get("kev") and cve.get("poc"))
                            or importance > c.get("hot_threshold", 80))
        tags = list(dict.fromkeys(badges + it.get("tags", []) + matched[:5]))
        it["tags"] = tags[:10]
        return it
