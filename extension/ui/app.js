// Controller for the popup (body.popup) and the full results page (body.page).

import { copyWithFeedback, icon } from './dom.js';
import { ResultView, renderHome, renderMessage } from './render.js';
import { PROVIDERS } from '../lib/providers/index.js';
import { classifyIp, extractIps, normalizeIp, parseQuery } from '../lib/ip.js';
import { runLookup, summarize } from '../lib/lookup.js';
import { clearHistory, createCache, getHistory, getSettings, recordHistory } from '../lib/storage.js';
import { resolveHost } from '../lib/dns.js';
import { fetchJson } from '../lib/http.js';
import { buildJsonReport, buildTextReport } from '../lib/report.js';

const mode = document.body.classList.contains('popup') ? 'popup' : 'page';
const $ = (id) => document.getElementById(id);
const els = {
  form: $('search'),
  input: $('q'),
  error: $('form-error'),
  content: $('content'),
  openTab: $('open-tab'),
  openOptions: $('open-options'),
};
const noop = () => {};

let settings = await getSettings();
let active = null; // { token, controller, info, scope, states, view, resolvedFrom, others }

for (const el of document.querySelectorAll('[data-icon]')) el.prepend(icon(el.dataset.icon, { size: Number(el.dataset.iconSize) || 16 }));

chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === 'local' && changes.settings) settings = await getSettings();
});

/* ------------------------------------------------------------ helpers */

function showError(message) {
  els.error.textContent = message;
  els.error.hidden = false;
}

function hideError() {
  els.error.hidden = true;
}

function abortActive() {
  active?.controller.abort();
  active = null;
}

function openOptions() {
  chrome.runtime.openOptionsPage();
}

function resultsUrl(query) {
  return chrome.runtime.getURL(query ? `results.html?q=${encodeURIComponent(query)}` : 'results.html');
}

function setPageUrl(query, push) {
  if (mode !== 'page') return;
  const url = query ? `?q=${encodeURIComponent(query)}` : location.pathname;
  if (push) history.pushState({ q: query }, '', url);
  else history.replaceState({ q: query }, '', url);
  document.title = query ? `${query} · ipScout` : 'ipScout';
}

/* ------------------------------------------------------------- lookups */

async function go(query, { push = false, force = false } = {}) {
  hideError();
  const parsed = parseQuery(query);
  if (!parsed) {
    if (String(query || '').trim()) showError('That doesn’t look like an IP address, hostname or URL.');
    return;
  }
  if (parsed.type === 'host') return lookupHost(parsed.host, { push });
  return startLookup(parsed.info, { push, force, others: parsed.others });
}

async function lookupHost(host, { push }) {
  abortActive();
  const controller = new AbortController();
  const token = {};
  active = { token, controller };
  els.input.value = host;
  setPageUrl(host, push);
  renderMessage(els.content, { title: `Resolving ${host}…`, busy: true });
  try {
    const { ipv4, ipv6 } = await resolveHost(host, (url, opts) => fetchJson(url, { ...opts, signal: controller.signal }));
    if (active?.token !== token) return;
    const ips = [...ipv4, ...ipv6];
    if (!ips.length) {
      renderMessage(els.content, { title: `${host} has no A or AAAA records`, detail: 'There is no IP address to look up.' });
      return;
    }
    startLookup(normalizeIp(ips[0]), { resolvedFrom: { host, ips }, keepUrl: true });
  } catch (err) {
    if (active?.token !== token) return;
    renderMessage(els.content, { title: `Couldn’t resolve ${host}`, detail: err?.message || 'DNS lookup failed.' });
  }
}

function startLookup(info, { push = false, force = false, others = [], resolvedFrom = null, keepUrl = false } = {}) {
  abortActive();
  const controller = new AbortController();
  const token = {};
  const scope = classifyIp(info);
  els.input.value = resolvedFrom ? resolvedFrom.host : info.ip;
  if (!keepUrl) setPageUrl(info.ip, push);
  else if (mode === 'page') document.title = `${info.ip} · ipScout`;

  const view = new ResultView(els.content, {
    mode,
    info,
    scope,
    providers: PROVIDERS,
    others,
    resolvedFrom,
    handlers: {
      onCopyIp: (btn) => copyWithFeedback(info.ip, btn),
      onRefresh: () => startLookup(info, { force: true, others, resolvedFrom, keepUrl: true }),
      onCopyReport: (btn) => copyWithFeedback(buildTextReport({ info, states: current.states, defang: settings.defangOnCopy }), btn),
      onCopyJson: mode === 'page' ? (btn) => copyWithFeedback(buildJsonReport({ info, scope, states: current.states }), btn) : null,
      onOpenOptions: openOptions,
      onRetry: (id) => retry(id),
      onPick: (ip, from) => {
        const picked = normalizeIp(ip);
        if (picked) startLookup(picked, { push: true, resolvedFrom: from || null });
      },
    },
  });
  const current = { token, controller, info, scope, states: {}, view, resolvedFrom, others };
  active = current;
  view.render();
  if (!scope.isPublic) return;

  recordHistory({ ip: info.ip, ts: Date.now() }).catch(noop);
  const cache = createCache({ ttlMs: settings.cacheTtlMinutes * 60000 });
  cache.maybePrune().catch(noop);

  runLookup(info, {
    settings,
    cache,
    force,
    signal: controller.signal,
    onUpdate: (id, state) => {
      if (active?.token !== token) return;
      current.states[id] = state;
      view.update(id, current.states);
    },
  }).then(() => {
    if (active?.token !== token) return;
    recordHistory({ ip: info.ip, ts: Date.now(), verdict: summarize(current.states).verdict }).catch(noop);
  });
}

function retry(providerId) {
  if (!active?.view) return;
  const { token, info, controller, view, states } = active;
  const provider = PROVIDERS.find((p) => p.id === providerId);
  if (!provider) return;
  runLookup(info, {
    settings,
    cache: createCache({ ttlMs: settings.cacheTtlMinutes * 60000 }),
    providers: [provider],
    force: true,
    signal: controller.signal,
    onUpdate: (id, state) => {
      if (active?.token !== token) return;
      states[id] = state;
      view.update(id, states);
    },
  });
}

async function lookupMyIp(button) {
  if (button) button.disabled = true;
  const attempts = [
    ['https://ipinfo.io/json', (d) => d?.ip],
    ['https://api.ipapi.is/', (d) => d?.ip],
  ];
  for (const [url, pick] of attempts) {
    try {
      const { data } = await fetchJson(url, { headers: { Accept: 'application/json' }, timeoutMs: 8000 });
      const ip = pick(data);
      if (ip && normalizeIp(ip)) {
        go(ip, { push: true });
        return;
      }
    } catch {
      // try the next service
    }
  }
  if (button) button.disabled = false;
  showError('Couldn’t determine your public IP address.');
}

/* ---------------------------------------------------------- home view */

async function showHome(pageContext = null) {
  abortActive();
  setPageUrl('', false);
  const history = await getHistory().catch(() => []);
  const pageIps = pageContext?.text ? extractIps(pageContext.text, { limit: 60, publicOnly: true }) : [];
  renderHome(els.content, {
    mode,
    history,
    pageIps,
    onPick: (ip) => go(ip, { push: true }),
    onMyIp: lookupMyIp,
    onClearHistory: async () => {
      await clearHistory();
      showHome(pageContext);
    },
  });
}

/**
 * Selection (and, if page scanning is on, visible text) of the active tab.
 * Popup only; relies on the activeTab grant. Nothing read here leaves the browser.
 */
async function getPageContext({ includeText }) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return null;
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: (maxChars) => ({
        selection: String(globalThis.getSelection?.() ?? '').slice(0, 4000),
        text: maxChars ? (document.body?.innerText ?? '').slice(0, maxChars) : '',
      }),
      args: [includeText ? 400000 : 0],
    });
    return injection?.result ?? null;
  } catch {
    return null; // chrome:// pages, the Web Store, PDFs, etc.
  }
}

/* ---------------------------------------------------------------- init */

els.form.addEventListener('submit', (e) => {
  e.preventDefault();
  go(els.input.value, { push: true });
});
els.openOptions?.addEventListener('click', openOptions);
els.openTab?.addEventListener('click', () => {
  chrome.tabs.create({ url: resultsUrl(active?.info?.ip || active?.resolvedFrom?.host || '') });
});

if (mode === 'page') {
  window.addEventListener('popstate', () => {
    const q = new URLSearchParams(location.search).get('q') || '';
    if (q) go(q);
    else showHome();
  });
}

const initialQuery = new URLSearchParams(location.search).get('q') || '';
if (initialQuery) {
  go(initialQuery);
} else if (mode === 'popup') {
  const wantsPage = settings.scanPage || settings.autoLookupSelection;
  const ctx = wantsPage
    ? await Promise.race([getPageContext({ includeText: settings.scanPage }), new Promise((r) => setTimeout(() => r(null), 600))])
    : null;
  const selected = settings.autoLookupSelection && ctx?.selection ? parseQuery(ctx.selection) : null;
  if (selected?.type === 'ip') {
    startLookup(selected.info, { others: selected.others });
  } else {
    await showHome(settings.scanPage ? ctx : null);
    els.input.focus();
  }
} else {
  await showHome();
  els.input.focus();
}
