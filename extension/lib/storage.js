// Persistence: settings, a per-source result cache and lookup history.
// Every function takes an optional storage area (defaults to chrome.storage.local)
// so the logic can be tested with an in-memory fake.

export const DEFAULT_SETTINGS = {
  keys: {}, // providerId -> API key
  enabled: {}, // providerId -> false to disable (enabled by default)
  cacheTtlMinutes: 360,
  abuseipdbMaxAgeDays: 90,
  abuseipdbFetchReports: true,
  autoLookupSelection: true,
  scanPage: true,
  defangOnCopy: false,
};

const CACHE_PREFIX = 'cache:';
const PRUNED_AT_KEY = 'cachePrunedAt';
const HISTORY_KEY = 'history';
export const HISTORY_MAX = 25;

function defaultArea() {
  const area = globalThis.chrome?.storage?.local;
  if (!area) throw new Error('chrome.storage.local is not available');
  return area;
}

export function normalizeSettings(saved) {
  const s = saved && typeof saved === 'object' ? saved : {};
  return {
    ...DEFAULT_SETTINGS,
    ...s,
    keys: { ...(s.keys || {}) },
    enabled: { ...(s.enabled || {}) },
  };
}

export async function getSettings(area = defaultArea()) {
  const { settings } = await area.get('settings');
  return normalizeSettings(settings);
}

export async function saveSettings(settings, area = defaultArea()) {
  const clean = normalizeSettings(settings);
  await area.set({ settings: clean });
  return clean;
}

export function isProviderEnabled(settings, id) {
  return settings.enabled?.[id] !== false;
}

/* ---------------------------- cache ---------------------------- */

export function cacheKey(providerId, ip) {
  return `${CACHE_PREFIX}${providerId}:${ip}`;
}

/**
 * Results are stored one key per source and IP, so parallel lookups never
 * race on a shared object. Raw API payloads are dropped to keep it small.
 */
export function createCache({ area = defaultArea(), ttlMs, now = () => Date.now() } = {}) {
  return {
    async get(providerId, ip) {
      if (!ttlMs) return null;
      const key = cacheKey(providerId, ip);
      const { [key]: entry } = await area.get(key);
      if (!entry || typeof entry.ts !== 'number' || now() - entry.ts > ttlMs) return null;
      return entry;
    },

    async set(providerId, ip, result) {
      if (!ttlMs) return;
      const { raw, ...rest } = result;
      await area.set({ [cacheKey(providerId, ip)]: { ts: now(), result: rest } });
    },

    /** Drop expired entries and cap the total (about 15 KB per IP, well under the 10 MB quota). */
    async prune(maxEntries = 1500) {
      const all = await area.get(null);
      const t = now();
      const entries = Object.entries(all).filter(([k]) => k.startsWith(CACHE_PREFIX));
      const isStale = ([, v]) => !v || typeof v.ts !== 'number' || t - v.ts > ttlMs;
      const stale = entries.filter(isStale).map(([k]) => k);
      const fresh = entries.filter((e) => !isStale(e)).sort((a, b) => b[1].ts - a[1].ts);
      const remove = [...stale, ...fresh.slice(maxEntries).map(([k]) => k)];
      if (remove.length) await area.remove(remove);
      return remove.length;
    },

    /** prune(), but at most once per interval, since it reads the whole store. */
    async maybePrune({ intervalMs = 10 * 60000, maxEntries } = {}) {
      const { [PRUNED_AT_KEY]: last = 0 } = await area.get(PRUNED_AT_KEY);
      if (now() - last < intervalMs) return 0;
      await area.set({ [PRUNED_AT_KEY]: now() });
      return this.prune(maxEntries);
    },

    async clear() {
      const all = await area.get(null);
      const keys = Object.keys(all).filter((k) => k.startsWith(CACHE_PREFIX));
      if (keys.length) await area.remove(keys);
      return keys.length;
    },
  };
}

/* --------------------------- history --------------------------- */

export async function getHistory(area = defaultArea()) {
  const { [HISTORY_KEY]: history } = await area.get(HISTORY_KEY);
  return Array.isArray(history) ? history : [];
}

/** Insert or update an entry ({ ip, ts, verdict }) at the top of the list. */
export async function recordHistory(entry, area = defaultArea()) {
  const list = await getHistory(area);
  const previous = list.find((e) => e.ip === entry.ip);
  const merged = { ...previous, ...entry };
  const next = [merged, ...list.filter((e) => e.ip !== entry.ip)].slice(0, HISTORY_MAX);
  await area.set({ [HISTORY_KEY]: next });
  return next;
}

export async function clearHistory(area = defaultArea()) {
  await area.remove(HISTORY_KEY);
}
