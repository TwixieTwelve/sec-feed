"""Точка входа: собрать все источники из config/feeds.yaml → обработать → public/data.json."""
from __future__ import annotations

import json
import os
import logging
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dedupe  # noqa: E402
import llm  # noqa: E402
import sources as S  # noqa: E402
import translate  # noqa: E402
from scoring import Scorer  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config" / "feeds.yaml"
OUTPUT = ROOT / "public" / "data.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("main")


# Тип источника → вызов универсальной fetch-функции с параметрами из конфига.
def _rss(src):
    try:
        return S.fetch_rss(src["url"])
    except Exception as err:
        if src.get("selectors"):
            log.warning("  %s: RSS не отвечает (%s) → html по селекторам", src["name"], err)
            return S.fetch_html(src.get("html_url", src["url"]), src["selectors"], src.get("base_url"))
        if src.get("site") and (alt := S.discover_feed(src["site"])) and alt != src["url"]:
            log.warning("  %s: RSS не отвечает (%s) → найден %s", src["name"], err, alt)
            return S.fetch_rss(alt)
        raise


FETCHERS = {
    "rss": _rss,
    "html": lambda s: S.fetch_html(s["url"], s["selectors"], s.get("base_url")),
    "json": lambda s: S.fetch_json(s["url"], s["fields"], s.get("items_path")),
    "github_search": lambda s: S.fetch_github_search(s["query"], s.get("since_days", 90),
                                                     s.get("sort", "updated"), s.get("max_items", 20)),
    "github_releases": lambda s: S.fetch_github_releases(s["repo"], s.get("max_items", 5) + 2),
    "github_advisories": lambda s: S.fetch_github_advisories(s.get("params"), s.get("min_severity", "low")),
    "cve_kev": lambda s: S.fetch_cve_kev(s["url"]),
    "cve_nvd": lambda s: S.fetch_cve_nvd(s["url"], s.get("days", 3), s.get("min_cvss", 0.0),
                                         s.get("page_size", 2000), s.get("page_delay", 6)),
}


def _matches(it, words) -> bool:
    text = f"{it['title']} {it['summary']}".lower()
    return any(w.lower() in text for w in words)


def collect_source(src, settings, now):
    """Запуск одного источника + фильтры. Возвращает (items, status)."""
    t0 = time.monotonic()
    status = {"name": src["name"], "type": src["type"], "category": src["category"]}
    try:
        items = FETCHERS[src["type"]](src)
        raw_count = len(items)
        cutoff = now - timedelta(days=src.get("max_age_days", settings.get("max_age_days", 30)))
        items = [i for i in items if i["title"] and i["url"] and (i["published"] is None or i["published"] >= cutoff)]
        if src.get("include_keywords"):
            items = [i for i in items if _matches(i, src["include_keywords"])]
        if src.get("exclude_keywords"):
            items = [i for i in items if not _matches(i, src["exclude_keywords"])]
        items.sort(key=lambda i: i["published"] or now, reverse=True)
        items = items[: src.get("max_items", settings.get("max_items_per_source", 40))]
        for i in items:
            i["source"], i["category"] = src["name"], src["category"]
        status.update(ok=True, fetched=raw_count, kept=len(items))
        if raw_count and not items:
            status["note"] = "ответ есть, но всё старше max_age_days / отфильтровано"
        log.info("  OK   %-34s %4d получено → %3d оставлено", src["name"], raw_count, len(items))
    except S.SourceEmpty as e:
        items = []
        status.update(ok=True, fetched=0, kept=0, note=str(e))
        log.warning("  EMPTY %-33s %s", src["name"], e)
    except Exception as e:  # noqa: BLE001 — любой сбой источника не роняет запуск
        items = []
        status.update(ok=False, error=f"{type(e).__name__}: {e}"[:300])
        log.error("  FAIL %-34s %s: %s", src["name"], type(e).__name__, str(e)[:200])
    status["seconds"] = round(time.monotonic() - t0, 1)
    return items, status


def load_previous(now, retention_days):
    if not OUTPUT.exists():
        return []
    try:
        data = json.loads(OUTPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("не удалось прочитать прошлый data.json: %s", e)
        return []
    cutoff = now - timedelta(days=retention_days)
    out = []
    for it in data.get("items", []):
        it["published"] = S.parse_date(it.get("published"))
        it["first_seen"] = S.parse_date(it.get("first_seen"))
        if (it["published"] or now) >= cutoff:
            out.append(it)
    return out


def enrich(items, cfg_list):
    for enr in cfg_list or []:
        if enr.get("enabled", True) is False:
            continue
        if enr["type"] == "epss":
            ids = [i["cve"]["id"] for i in items if i.get("cve", {}).get("id")]
            if not ids:
                continue
            try:
                scores = S.enrich_epss(ids, enr.get("url", "https://api.first.org/data/v1/epss"),
                                       enr.get("batch_size", 50))
                for i in items:
                    if (cid := i.get("cve", {}).get("id")) in scores:
                        i["cve"]["epss"] = round(scores[cid]["epss"], 4)
                        i["cve"]["epss_percentile"] = round(scores[cid]["percentile"], 4)
                log.info("EPSS: %d/%d CVE обогащено", len(scores), len(set(ids)))
            except Exception as e:  # noqa: BLE001
                log.error("EPSS недоступен: %s", e)
        else:
            log.warning("неизвестный тип обогащения %r — пропущен", enr["type"])


def select(items, settings):
    items.sort(key=lambda i: (i["importance"], i["published"] or datetime.min.replace(tzinfo=timezone.utc)),
               reverse=True)
    per_cat, out = {}, []
    cap = settings.get("max_per_category", 150)
    for it in items:
        if per_cat.get(it["category"], 0) >= cap:
            continue
        per_cat[it["category"]] = per_cat.get(it["category"], 0) + 1
        out.append(it)
        if len(out) >= settings.get("max_items_total", 500):
            break
    out.sort(key=lambda i: (i["is_hot"], i["importance"],
                            i["published"] or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
    return out


def serialize(it):
    iso = lambda d: d.isoformat().replace("+00:00", "Z") if d else None  # noqa: E731
    out = {
        "id": it["id"], "title": it["title"], "url": it["url"], "summary": it.get("summary", ""),
        "source": it["source"], "sources": it["sources"], "category": it["category"],
        "published": iso(it.get("published")), "first_seen": iso(it.get("first_seen")),
        "importance": it["importance"], "is_hot": it["is_hot"], "tags": it.get("tags", []),
    }
    if it.get("cve"):
        out["cve"] = it["cve"]
    if it.get("llm_summarized"):
        out["llm_summarized"] = True
    if it.get("title_ru"):
        out["title_ru"] = it["title_ru"]
        out["summary_ru"] = it.get("summary_ru", "")
    return out


def main():
    cfg = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    settings = cfg.get("settings", {})
    S.configure(settings)
    now = datetime.now(timezone.utc)

    fresh, statuses = [], []
    log.info("Сбор источников…")
    for src in cfg.get("sources", []):
        if src.get("enabled", True) is False:
            reason = src.get("disabled_reason", "выключен в конфиге")
            log.warning("  SKIP %-34s недоступен: %s", src["name"], reason)
            statuses.append({"name": src["name"], "type": src["type"], "category": src["category"],
                             "ok": False, "skipped": True, "note": reason})
            continue
        if src["type"] not in FETCHERS:
            log.error("  FAIL %-34s неизвестный type %r", src["name"], src["type"])
            statuses.append({"name": src["name"], "type": src["type"], "category": src["category"],
                             "ok": False, "error": f"unknown type {src['type']}"})
            continue
        items, status = collect_source(src, settings, now)
        fresh.extend(items)
        statuses.append(status)

    for it in fresh:
        it["first_seen"] = now
        it["sources"] = [it["source"]]
    previous = load_previous(now, settings.get("retention_days", 45))
    # Свежие идут первыми: при слиянии их данные (включая first_seen) дополняются прошлыми.
    items = dedupe.dedupe(fresh + previous)
    log.info("После дедупа: %d (свежих %d, из прошлого data.json %d)", len(items), len(fresh), len(previous))

    enrich(items, cfg.get("enrichment"))

    if llm.enabled():
        for it in [i for i in items if not i.get("llm_summarized")][: int(os.environ.get("LLM_MAX_ITEMS", 30))]:
            it["summary"] = llm.summarize(it)
            it["llm_summarized"] = True

    scorer = Scorer(cfg.get("scoring", {}))
    for it in items:
        scorer.score(it, now)

    translate_cfg = cfg.get("translate", {})
    if translate.enabled(translate_cfg):
        # Переводим самые важные элементы без перевода первыми — бесплатная квота ограничена,
        # накопится за несколько запусков. Порядок самого items не меняем.
        candidates = sorted(items, key=lambda i: (i["is_hot"], i["importance"]), reverse=True)
        n = translate.translate_items(candidates, translate_cfg)
        if n:
            log.info("Перевод: %d новых элементов на русском", n)

    items = select(items, settings)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "items": [serialize(i) for i in items],
        "sources_status": statuses,
    }
    OUTPUT.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    ok = sum(1 for s in statuses if s.get("ok"))
    log.info("Готово: %d элементов, hot: %d, источников OK %d/%d → %s",
             len(items), sum(i["is_hot"] for i in items), ok, len(statuses), OUTPUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
