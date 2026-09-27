"""Опциональная LLM-суммаризация. По умолчанию ВЫКЛЮЧЕНА и ничего не вызывает.

Как подключить позже:
  1. Реализуйте _call_llm(prompt) ниже для своего провайдера (HTTP-запрос через requests).
  2. Положите ключ в секрет репозитория (Settings → Secrets → Actions), например LLM_API_KEY.
  3. В .github/workflows/build.yml раскомментируйте env: LLM_ENABLED: "1" и LLM_API_KEY.
  Локально: LLM_ENABLED=1 LLM_API_KEY=... python collector/main.py
Суммаризируются только новые элементы (у которых ещё нет llm_summary), не больше LLM_MAX_ITEMS за запуск.
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("llm")


def enabled() -> bool:
    return os.environ.get("LLM_ENABLED") == "1"


def _call_llm(prompt: str) -> str:
    # Заглушка: сюда добавляется вызов API выбранного провайдера.
    raise NotImplementedError("LLM-провайдер не подключён, см. docstring llm.py")


def summarize(item: dict) -> str:
    """Возвращает краткое описание. При выключенном LLM — исходный summary без вызовов."""
    if not enabled():
        return item.get("summary", "")
    prompt = ("Summarize for a red team operator in 1-2 sentences (max 300 chars): "
              f"{item.get('title', '')}\n\n{item.get('summary', '')}")
    try:
        return _call_llm(prompt).strip()[:300] or item.get("summary", "")
    except Exception as e:  # noqa: BLE001 — сбой LLM не должен ронять сборку
        log.warning("LLM summarize failed: %s", e)
        return item.get("summary", "")
