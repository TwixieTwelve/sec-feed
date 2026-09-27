"use strict";

const CATEGORIES = {
  all: "всё",
  vulnerabilities: "vulns",
  exploits_poc: "exploits/poc",
  news: "news",
  offensive_research: "offensive research",
  tools_c2: "tools/c2",
  ai_pentest: "ai pentest",
  llm_security: "llm security",
  writeups: "writeups",
  red_team_ref: "red team ref",
  threat_intel: "threat intel",
};
const RENDER_LIMIT = 200; // карточек за раз; «показать ещё» догружает
const TOP10_SIZE = 10;

// Токенизация заголовков для клиентской «мягкой» дедупликации похожих новостей
// (тот же принцип, что и в collector/dedupe.py, но применяется уже к отфильтрованному
// списку на экране — порог мягче, т.к. цель именно «убрать похожее», а не строгий дедуп).
const STOPWORDS = new Set(["a", "an", "the", "and", "or", "of", "in", "on", "for", "to", "with", "by",
  "is", "are", "as", "at", "from", "new", "how", "its", "it", "via", "into"]);
const CVE_RE = /CVE-\d{4}-\d{4,7}/i;
const LOOSE_SIMILARITY = 0.55;
const LOOSE_MIN_TOKENS = 3;

function titleTokens(title) {
  const words = (title.toLowerCase().match(/[a-z0-9]+(?:-[a-z0-9]+)*/g)) || [];
  return new Set(words.filter((w) => !STOPWORDS.has(w) && w.length > 1));
}

function looseDedupe(list) {
  // Стадия 1: одинаковый CVE в заголовке — дублируется часто между категориями
  // (сама CVE в vulnerabilities и новость о ней в news).
  const seenCve = new Set();
  const stage1 = [];
  for (const it of list) {
    const m = it.title.match(CVE_RE);
    const cve = m && m[0].toUpperCase();
    if (cve) {
      if (seenCve.has(cve)) continue;
      seenCve.add(cve);
    }
    stage1.push(it);
  }
  // Стадия 2: похожие заголовки (инвертированный индекс по токенам), без учёта категории/источника.
  const kept = [];
  const index = new Map();
  for (const it of stage1) {
    const toks = titleTokens(it.title);
    let isDup = false;
    if (toks.size >= LOOSE_MIN_TOKENS) {
      const candidates = new Set();
      for (const t of toks) for (const i of (index.get(t) || [])) candidates.add(i);
      for (const ci of candidates) {
        const otoks = titleTokens(kept[ci].title);
        if (otoks.size < LOOSE_MIN_TOKENS) continue;
        let inter = 0;
        for (const x of toks) if (otoks.has(x)) inter++;
        const union = toks.size + otoks.size - inter;
        if (union && inter / union >= LOOSE_SIMILARITY) { isDup = true; break; }
      }
    }
    if (isDup) continue;
    for (const t of toks) { if (!index.has(t)) index.set(t, []); index.get(t).push(kept.length); }
    kept.push(it);
  }
  return kept;
}

// ---------- localStorage (может быть недоступен — работаем и без него) ----------
const store = {
  get(key, fallback) {
    try { const v = localStorage.getItem("secfeed:" + key); return v === null ? fallback : JSON.parse(v); }
    catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem("secfeed:" + key, JSON.stringify(value)); } catch { /* приватный режим и т.п. */ }
  },
};

const state = {
  items: [],
  category: store.get("category", "all"),
  hotOnly: false,
  sort: store.get("sort", "importance"),
  query: "",
  unreadOnly: false,
  limit: RENDER_LIMIT,
  read: new Set(store.get("read", [])),
  prevVisit: store.get("lastVisit", null),
  lang: store.get("lang", "ru"),
  looseDedup: store.get("looseDedup", true),
  top10: false,
  top10Categories: null, // Set — заполняется в ensureTop10Categories() после загрузки данных
};

const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

function safeUrl(url) {
  try { const u = new URL(url); return ["http:", "https:"].includes(u.protocol) ? u.href : null; }
  catch { return null; }
}

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  const diffH = (Date.now() - d) / 36e5;
  if (diffH >= 0 && diffH < 1) return `${Math.max(1, Math.round(diffH * 60))} мин назад`;
  if (diffH >= 0 && diffH < 24) return `${Math.round(diffH)} ч назад`;
  if (diffH >= 0 && diffH < 24 * 7) return `${Math.round(diffH / 24)} дн назад`;
  return d.toLocaleDateString("ru-RU", { day: "2-digit", month: "short", year: "numeric" });
}

function isNew(it) {
  return state.prevVisit && it.first_seen && it.first_seen > state.prevVisit;
}

function persistRead() {
  // Храним только id, которые ещё есть в фиде, — список не растёт бесконечно.
  const ids = new Set(state.items.map((i) => i.id));
  store.set("read", [...state.read].filter((id) => ids.has(id)));
}

// ---------- фильтрация ----------
function matchesQuery(it, q) {
  if (!q) return true;
  const hay = (it.title + " " + (it.title_ru || "") + " " + (it.tags || []).join(" ") + " " + (it.cve?.id || "")).toLowerCase();
  return q.split(/\s+/).every((w) => hay.includes(w));
}

function filtered() {
  const q = state.query.trim().toLowerCase();
  let list = state.items.filter((it) => {
    if (state.category !== "all" && it.category !== state.category) return false;
    if (state.hotOnly && !it.is_hot) return false;
    if (state.unreadOnly && state.read.has(it.id)) return false;
    return matchesQuery(it, q);
  });
  const byDate = (a, b) => (b.published || "").localeCompare(a.published || "");
  list.sort(state.sort === "date"
    ? byDate
    : (a, b) => (b.is_hot - a.is_hot) || (b.importance - a.importance) || byDate(a, b));
  if (state.looseDedup) list = looseDedupe(list);
  return list;
}

function top10List() {
  const q = state.query.trim().toLowerCase();
  const cats = state.top10Categories;
  let list = state.items.filter((it) => cats.has(it.category) && matchesQuery(it, q));
  list.sort((a, b) => b.importance - a.importance
    || (b.published || "").localeCompare(a.published || ""));
  if (state.looseDedup) list = looseDedupe(list);
  return list.slice(0, TOP10_SIZE);
}

// ---------- рендер ----------
function card(it) {
  const url = safeUrl(it.url);
  const read = state.read.has(it.id);
  const imp = it.importance ?? 0;
  const impClass = imp >= 70 ? "high" : imp >= 45 ? "mid" : "";
  const showRu = state.lang === "ru";
  const pending = showRu && !it.title_ru; // перевод ещё не подъехал (бесплатная квота ограничена)
  const titleText = showRu && it.title_ru ? it.title_ru : it.title;
  const summaryText = showRu && it.summary_ru ? it.summary_ru : it.summary;

  const head = el("div", { class: "head" },
    it.is_hot ? el("span", { class: "badge hot", text: "HOT" }) : null,
    isNew(it) ? el("span", { class: "badge new", text: "NEW" }) : null,
    el("span", { class: "badge src", text: it.source, title: (it.sources || []).join(", ") }),
    (it.sources || []).length > 1 ? el("span", { class: "badge", text: `+${it.sources.length - 1}` }) : null,
    el("span", { class: "badge cat", text: CATEGORIES[it.category] || it.category }),
    pending ? el("span", { class: "badge pending", text: "EN", title: "перевод ещё не готов — копится за несколько запусков" }) : null,
  );
  if (it.cve) {
    if (it.cve.kev) head.append(el("span", { class: "badge kev", text: "KEV" }));
    if (it.cve.epss != null) {
      head.append(el("span", {
        class: "badge epss", text: `EPSS ${(it.cve.epss * 100).toFixed(1)}%`,
        title: it.cve.epss_percentile != null ? `перцентиль ${(it.cve.epss_percentile * 100).toFixed(0)}` : null,
      }));
    }
    if (it.cve.poc) head.append(el("span", { class: "badge poc", text: "PoC" }));
    if (it.cve.cvss != null) head.append(el("span", { class: "badge", text: `CVSS ${it.cve.cvss}` }));
  }

  const link = el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: titleText });
  const markRead = () => {
    state.read.add(it.id); persistRead();
    node.classList.add("read"); node.classList.remove("unread");
    updateCounters();
  };
  link.addEventListener("click", markRead);
  link.addEventListener("auxclick", markRead);

  const tags = (it.tags || [])
    .filter((t) => !["KEV", "EPSS", "PoC"].includes(t))
    .slice(0, 5)
    .map((t) => el("span", { class: "tag", text: t }));

  const foot = el("div", { class: "foot" },
    el("time", { datetime: it.published, title: it.published || "", text: fmtDate(it.published) }),
    ...tags,
    el("span", { class: `imp ${impClass}`, title: `importance ${imp}/100` },
      el("span", { class: "bar" }, el("i", { style: `width:${imp}%` })),
      document.createTextNode(String(imp))),
  );

  const node = el("article", { class: `card${it.is_hot ? " hot" : ""} ${read ? "read" : "unread"}` },
    head, el("h3", {}, link), summaryText ? el("p", { class: "sum", text: summaryText }) : null, foot);
  return node;
}

function renderTabs() {
  const counts = { all: state.items.length };
  for (const it of state.items) counts[it.category] = (counts[it.category] || 0) + 1;
  const tabs = $("#tabs");
  tabs.replaceChildren(...Object.entries(CATEGORIES)
    .filter(([key]) => key === "all" || counts[key])
    .map(([key, label]) => {
      const b = el("button", { role: "tab", class: key === state.category ? "on" : "", "aria-selected": String(key === state.category) },
        document.createTextNode(label), el("span", { class: "n", text: String(counts[key] || 0) }));
      b.addEventListener("click", () => {
        if (state.top10) setTop10(false);
        state.category = key; store.set("category", key); state.limit = RENDER_LIMIT; renderTabs(); render();
      });
      return b;
    }));
}

function render() {
  const list = state.top10 ? top10List() : filtered();
  const grid = $("#grid");
  grid.replaceChildren(...list.slice(0, state.limit).map(card));
  if (!state.top10 && list.length > state.limit) {
    const more = el("button", { class: "ghost", text: `показать ещё (${list.length - state.limit})` });
    more.addEventListener("click", () => { state.limit += RENDER_LIMIT; render(); });
    grid.append(more);
  }
  $("#empty").hidden = list.length > 0;
  if (state.top10) {
    $("#summary").textContent = `> топ-${list.length} по важности · категорий учтено: ${state.top10Categories.size}`;
  } else {
    const hot = list.filter((i) => i.is_hot).length;
    $("#summary").textContent = `> ${list.length} элементов · hot: ${hot}`;
  }
}

// ---------- топ-10 ----------
function setTop10(on) {
  state.top10 = on;
  state.limit = RENDER_LIMIT;
  $("#top10Btn").classList.toggle("on", on);
  document.body.classList.toggle("top10-mode", on);
  if (!on) $("#top10Panel").hidden = true;
  render();
}

function ensureTop10Categories() {
  const allCats = Object.keys(CATEGORIES).filter((k) => k !== "all");
  const saved = store.get("top10Categories", null);
  const valid = Array.isArray(saved) ? saved.filter((c) => allCats.includes(c)) : null;
  state.top10Categories = new Set(valid && valid.length ? valid : allCats);
}

function renderTop10Checks() {
  const allCats = Object.keys(CATEGORIES).filter((k) => k !== "all");
  $("#top10Checks").replaceChildren(...allCats.map((key) => {
    const input = el("input", { type: "checkbox" });
    input.checked = state.top10Categories.has(key);
    input.addEventListener("change", () => {
      if (input.checked) state.top10Categories.add(key); else state.top10Categories.delete(key);
      store.set("top10Categories", [...state.top10Categories]);
      if (state.top10) render();
    });
    return el("label", { class: "pchk" }, input, document.createTextNode(" " + (CATEGORIES[key] || key)));
  }));
}

function updateCounters() {
  $("#unreadCount").textContent = state.items.filter((i) => !state.read.has(i.id)).length;
  $("#newCount").textContent = state.items.filter(isNew).length;
}

function renderStatus(statuses = []) {
  if (!statuses.length) return;
  const ok = statuses.filter((s) => s.ok).length;
  const bad = statuses.filter((s) => !s.ok).map((s) => `${s.name}: ${s.error || s.note || "недоступен"}`);
  const node = $("#srcStatus");
  node.textContent = `источники: ${ok}/${statuses.length} ok`;
  node.title = bad.length ? "Недоступны:\n" + bad.join("\n") : "все источники отвечают";
}

// ---------- события ----------
function bindControls() {
  let t;
  $("#search").addEventListener("input", (e) => {
    clearTimeout(t);
    t = setTimeout(() => { state.query = e.target.value; state.limit = RENDER_LIMIT; render(); }, 120);
  });
  $("#hotToggle").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.hotOnly = b.dataset.hot === "hot";
    for (const x of $("#hotToggle").children) x.classList.toggle("on", x === b);
    render();
  });
  $("#sortToggle").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.sort = b.dataset.sort; store.set("sort", state.sort);
    for (const x of $("#sortToggle").children) x.classList.toggle("on", x === b);
    render();
  });
  for (const x of $("#sortToggle").children) x.classList.toggle("on", x.dataset.sort === state.sort);
  $("#unreadOnly").addEventListener("change", (e) => { state.unreadOnly = e.target.checked; render(); });
  $("#markAll").addEventListener("click", () => {
    for (const it of filtered()) state.read.add(it.id);
    persistRead(); render(); updateCounters();
  });

  $("#langToggle").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    state.lang = b.dataset.lang; store.set("lang", state.lang);
    for (const x of $("#langToggle").children) x.classList.toggle("on", x === b);
    render();
  });
  for (const x of $("#langToggle").children) x.classList.toggle("on", x.dataset.lang === state.lang);

  $("#dedupBtn").addEventListener("click", () => {
    state.looseDedup = !state.looseDedup;
    store.set("looseDedup", state.looseDedup);
    $("#dedupBtn").classList.toggle("on", state.looseDedup);
    render();
  });
  $("#dedupBtn").classList.toggle("on", state.looseDedup);

  $("#top10Btn").addEventListener("click", () => setTop10(!state.top10));
  $("#top10Cfg").addEventListener("click", () => { $("#top10Panel").hidden = !$("#top10Panel").hidden; });
  $("#top10PanelClose").addEventListener("click", () => { $("#top10Panel").hidden = true; });
}

async function init() {
  bindControls();
  try {
    const res = await fetch("data.json", { cache: "no-cache" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    state.items = Array.isArray(data.items) ? data.items : [];
    if (!CATEGORIES[state.category]) state.category = "all";
    ensureTop10Categories();
    renderTop10Checks();
    const updated = data.generated_at ? new Date(data.generated_at) : null;
    $("#updated").textContent = updated && !isNaN(updated)
      ? `${updated.toLocaleString("ru-RU")} (${fmtDate(data.generated_at)})` : "—";
    $("#updated").title = data.generated_at || "";
    renderStatus(data.sources_status);
    renderTabs();
    render();
    updateCounters();
    // Запоминаем визит: при следующем открытии «новыми» будут элементы с first_seen позже этого момента.
    store.set("lastVisit", new Date().toISOString());
  } catch (err) {
    $("#empty").hidden = false;
    $("#empty").textContent = `Не удалось загрузить data.json: ${err.message}`;
  }
}

init();
