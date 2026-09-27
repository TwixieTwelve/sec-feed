# sec-feed

Персональный агрегатор security-новостей для red team и пентеста.
Python-сборщик в GitHub Actions каждые 3 часа собирает источники из `config/feeds.yaml`.
Потом он оценивает важность элементов, убирает дубли и пишет `public/data.json`.
Статический дашборд на GitHub Pages читает этот файл.
Платные сервисы и обязательные API-ключи не нужны.

```
collector/   main.py (точка входа) · sources.py (загрузчики) · scoring.py · dedupe.py · llm.py
config/      feeds.yaml — источники, ключевые слова, веса скоринга
public/      index.html · app.js · style.css · data.json (генерируется)
```

## 1. Локальный запуск сборщика

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python collector/main.py
```

Лог показывает статус каждого источника:
- `OK`: источник ответил;
- `EMPTY`: ответ пришёл, но данных в нём нет;
- `FAIL`: ошибка (сбор остальных источников продолжается);
- `SKIP`: источник выключен в конфиге.

Результат записывается в `public/data.json`. Там же, в поле `sources_status`, лежит статус по каждому источнику.

Без токена GitHub API даёт 60 запросов в час. Если часто запускаете сборщик локально, передайте токен:
`GITHUB_TOKEN=$(gh auth token) python collector/main.py`.

Посмотреть дашборд локально:

```bash
cd public && python3 -m http.server 48213
# открыть http://localhost:48213
```

## 2. Как добавить источник

Допишите блок в `sources:` в `config/feeds.yaml`. Код менять не нужно.

```yaml
# RSS/Atom. site — необязательный: если фид сломается, RSS будет найден на сайте автоматически.
- name: My Blog
  type: rss
  category: offensive_research
  url: https://example.com/feed/
  site: https://example.com/

# HTML-страница без RSS: разбор по CSS-селекторам.
- name: Some Blog
  type: html
  category: writeups
  url: https://example.com/blog
  selectors: {item: "article", title: "h2 a", link: "h2 a", date: "time", summary: "p"}

# Произвольный JSON: пути полей через точку, индексы списков — числами.
- name: Some JSON
  type: json
  category: writeups
  url: https://example.com/data.json
  items_path: data
  fields: {title: title, url: links.0.href, published: date, tags: labels}

# GitHub: поиск репозиториев ({since} = дата since_days дней назад) и релизы.
- {name: X search, type: github_search, category: ai_pentest, query: "topic created:>{since}", since_days: 90, sort: stars}
- {name: Tool, type: github_releases, category: tools_c2, repo: owner/name, max_age_days: 180}
```

Остальные типы: `cve_kev`, `cve_nvd`, `github_advisories`. Примеры есть в `feeds.yaml`.

Общие поля:
- `max_items` — сколько элементов брать из источника;
- `max_age_days` — отбрасывать элементы старше N дней;
- `include_keywords` / `exclude_keywords` — фильтр по заголовку и описанию;
- `enabled: false` + `disabled_reason` — выключить источник; в логе он будет помечен как недоступный.

Ключевые слова, их веса, CVE-сигналы и список популярных продуктов лежат в секции `scoring:` того же файла.

## 3. Включить GitHub Pages

1. Запушьте репозиторий на GitHub.
2. **Settings → Pages → Build and deployment → Source: GitHub Actions**.
3. **Settings → Actions → General → Workflow permissions → Read and write permissions**.
4. **Actions → build → Run workflow**, чтобы запустить первый прогон вручную.

Дальше workflow запускается сам: каждые 3 часа, при пуше в `main` и вручную.
Он коммитит обновлённый `data.json` с пометкой `[skip ci]` и деплоит папку `public`.
Адрес сайта: `https://<user>.github.io/<repo>/`.

## 4. Подключить LLM (по умолчанию выключен)

`collector/llm.py` — заглушка. Пока не задано `LLM_ENABLED=1`, `summarize()` возвращает исходное описание и никуда не обращается.

Чтобы подключить:
1. Реализуйте `_call_llm(prompt)` в `llm.py`: HTTP-запрос к API выбранного провайдера через `requests`. Ключ берите из `os.environ["LLM_API_KEY"]`.
2. Добавьте секрет `LLM_API_KEY` в **Settings → Secrets and variables → Actions**.
3. В `build.yml` раскомментируйте строки `LLM_ENABLED` и `LLM_API_KEY`.

Суммаризируются только новые элементы, не больше `LLM_MAX_ITEMS` за запуск (по умолчанию 30). Ошибка LLM не роняет сборку.

## Функции дашборда

- **RU/EN** (шапка справа) — переключает язык карточек. По умолчанию RU. Если перевод
  для элемента ещё не готов, показывается оригинал и бейдж `EN` — это нормально, перевод
  копится постепенно (см. ниже).
- **🏆 топ-10** — 10 самых важных элементов по `importance`, независимо от текущей
  вкладки. Шестерёнка `⚙` рядом открывает список категорий, которые учитываются в подсчёте
  (выбор сохраняется в браузере). Клик по любой вкладке категории выходит из этого режима.
- **убрать похожие** — включённая по умолчанию клиентская фильтрация: схлопывает в списке
  карточки с одинаковым CVE в заголовке или с очень похожими заголовками (даже если это
  разные источники или категории — например, новость про уязвимость и сама CVE-запись).
  Это мягче и агрессивнее, чем дедуп на сервере (`collector/dedupe.py`), который просто
  устраняет точные дубли по URL/CVE внутри категории.

## Перевод на русский

`collector/translate.py` переводит title/summary через MyMemory (бесплатно, без ключа),
при отказе пробует Google Translate как запасной вариант. Переводятся только новые
элементы, не больше `translate.max_items_per_run` (по умолчанию 80) за один запуск —
перевод накапливается за несколько прогонов workflow. У бесплатного MyMemory небольшая
дневная квота на IP-адрес: если она исчерпана, элементы останутся на английском до
следующего дня, сборка при этом не падает.

Чтобы поднять квоту (бесплатно, без регистрации): задайте свой email в переменной
окружения `TRANSLATE_EMAIL` (или `email:` в `config/feeds.yaml` → `translate`) —
MyMemory увеличивает лимит для запросов с этим параметром.

Отключить перевод: `enabled: false` в секции `translate:` конфига, либо `TRANSLATE_ENABLED=0`.

## Скоринг

`importance` — число от 0 до 100. Из чего он складывается:
- базовый балл категории;
- совпадения с ключевыми словами (с потолком);
- CVE-сигналы: KEV +40, EPSS > 0.5 +25, PoC +20, популярный продукт +10, CVSS;
- свежесть.

`is_hot` = (KEV и PoC) или `importance > 80`.

Сигнал PoC срабатывает, только если источник проставил элементу `cve.poc`. Встроенные источники этого пока не делают.

## Известные ограничения источников

- arXiv RSS пустой по выходным, поэтому используется arXiv Atom API.
- HackerOne Hacktivity — JS-приложение. Выключен, вместо него скрейпится блог HackerOne.
- pentester.land не обновляется с 2024-09, securelist.com не ответил при проверке — оба выключены.
- У HavocFramework/Havoc нет релизов, в логе будет `EMPTY`.
# sec-feed
