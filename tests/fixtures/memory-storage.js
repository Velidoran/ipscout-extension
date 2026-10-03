// In-memory stand-in for chrome.storage.local (promise API).
export function createMemoryArea(initial = {}) {
  const data = new Map(Object.entries(initial));
  const clone = (v) => (v === undefined ? v : structuredClone(v));
  return {
    data,
    async get(keys) {
      if (keys === null || keys === undefined) return Object.fromEntries([...data].map(([k, v]) => [k, clone(v)]));
      const list = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(keys);
      const out = {};
      for (const k of list) if (data.has(k)) out[k] = clone(data.get(k));
      return out;
    },
    async set(items) {
      for (const [k, v] of Object.entries(items)) data.set(k, clone(v));
    },
    async remove(keys) {
      for (const k of [].concat(keys)) data.delete(k);
    },
  };
}
