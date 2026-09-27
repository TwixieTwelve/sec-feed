"""Опциональный перевод заголовка/описания на русский. Включён по умолчанию.
Основной провайдер — MyMemory (бесплатно, без ключа, https://mymemory.translated.net),
у него маленькая дневная квота без email. Если MyMemory отказал (лимит/таймаут),
вторым пробуется публичный endpoint Google Translate (тоже без ключа) — просто
подстраховка, а не основной провайдер.

Переводятся только НОВЫЕ элементы (у которых ещё нет title_ru), не больше
max_items_per_run за один запуск — это укладывается в бесплатную квоту и
даёт переводу «накопиться» за несколько запусков. Приоритет отдаётся
самым важным элементам (это решает main.py, передавая уже отсортированный список).

Любой сбой (таймаут, лимит, недоступность) — не ошибка сборки: элемент
просто остаётся на английском до следующего запуска. После нескольких
неудач подряд модуль перестаёт пытаться (провайдер, видимо, недоступен),
чтобы не тратить время на заведомо обречённые запросы.

Отключить: enabled: false в config/feeds.yaml (секция translate) или
переменная окружения TRANSLATE_ENABLED=0.
"""
from __future__ import annotations

import logging
import os
import re
import time

import requests

log = logging.getLogger("translate")

# MyMemory иногда возвращает 200 с текстом-предупреждением вместо перевода
# (исчерпана дневная квота, слишком длинный текст и т.п.) — это тоже сбой.
_WARNING_RE = re.compile(r"MYMEMORY WARNING|QUERY LENGTH LIMIT|INVALID LANGPAIR|AMOUNT OF WORDS", re.I)
MAX_CONSECUTIVE_FAILURES = 5
MAX_TEXT_LEN = 480  # у MyMemory лимит ~500 байт на запрос
REQUEST_DELAY = 0.4  # пауза между запросами: у бесплатного MyMemory жёсткий лимит запросов/сек


def enabled(cfg: dict) -> bool:
    env = os.environ.get("TRANSLATE_ENABLED")
    if env is not None:
        return env == "1"
    return cfg.get("enabled", True)


def _translate_mymemory(text: str, url: str, langpair: str, timeout: float, email: str | None) -> str:
    params = {"q": text[:MAX_TEXT_LEN], "langpair": langpair}
    if email:
        params["de"] = email
    r = requests.get(url, params=params, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    if data.get("responseStatus") not in (200, "200"):
        raise RuntimeError(f"responseStatus={data.get('responseStatus')}")
    out = (data.get("responseData") or {}).get("translatedText", "").strip()
    if not out or _WARNING_RE.search(out):
        raise RuntimeError(out or "пустой ответ провайдера")
    return out


def _translate_google(text: str, langpair: str, timeout: float) -> str:
    src, tgt = langpair.split("|", 1)
    r = requests.get(
        "https://translate.googleapis.com/translate_a/single",
        params={"client": "gtx", "sl": src, "tl": tgt, "dt": "t", "q": text[:MAX_TEXT_LEN]},
        timeout=timeout,
    )
    r.raise_for_status()
    segments = r.json()[0]
    out = "".join(seg[0] for seg in segments if seg and seg[0]).strip()
    if not out:
        raise RuntimeError("пустой ответ Google")
    return out


def _translate_text(text: str, url: str, langpair: str, timeout: float, email: str | None) -> str:
    text = (text or "").strip()
    if not text:
        return text
    errors = []
    try:
        return _translate_mymemory(text, url, langpair, timeout, email)
    except Exception as e:  # noqa: BLE001
        errors.append(f"mymemory: {e}")
    try:
        return _translate_google(text, langpair, timeout)
    except Exception as e:  # noqa: BLE001
        errors.append(f"google: {e}")
    raise RuntimeError("; ".join(errors))


def translate_items(items: list[dict], cfg: dict) -> int:
    """items — список кандидатов БЕЗ перевода, уже отсортированный по приоритету
    вызывающим кодом (важные — первыми). Мутирует элементы (title_ru/summary_ru).
    Возвращает число фактически переведённых элементов."""
    url = cfg.get("url", "https://api.mymemory.translated.net/get")
    langpair = cfg.get("langpair", "en|ru")
    timeout = cfg.get("timeout", 8)
    email = os.environ.get("TRANSLATE_EMAIL") or cfg.get("email")
    max_items = cfg.get("max_items_per_run", 80)

    done = failures = 0
    for it in items:
        if done >= max_items:
            break
        if it.get("title_ru"):
            continue
        try:
            it["title_ru"] = _translate_text(it["title"], url, langpair, timeout, email)
            time.sleep(REQUEST_DELAY)
            it["summary_ru"] = (_translate_text(it["summary"], url, langpair, timeout, email)
                                if it.get("summary") else "")
            time.sleep(REQUEST_DELAY)
            done += 1
            failures = 0
        except Exception as e:  # noqa: BLE001 — сбой перевода не должен ронять сборку
            failures += 1
            log.warning("  перевод не удался (%s): %s", it["title"][:60], e)
            if "429" in str(e):  # всплеск лимита запросов/сек — не квота на день, стоит переждать
                time.sleep(2.0)
            if failures >= MAX_CONSECUTIVE_FAILURES:
                log.error("  переводчик недоступен (%d ошибок подряд) — прекращаю на этом запуске", failures)
                break
    return done
