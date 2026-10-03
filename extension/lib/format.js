// Formatting helpers shared by providers and UI.

let regionNames = null;
try {
  regionNames = new Intl.DisplayNames(['en'], { type: 'region' });
} catch {
  regionNames = null;
}

/** "US" -> "United States". Returns the input when it is not a known code. */
export function countryName(code) {
  if (!code || typeof code !== 'string') return '';
  const upper = code.trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return code;
  try {
    return regionNames?.of(upper) || upper;
  } catch {
    return upper;
  }
}

/** "US" -> regional-indicator flag emoji. */
export function countryFlag(code) {
  if (!code || !/^[A-Za-z]{2}$/.test(code)) return '';
  return String.fromCodePoint(
    ...code
      .toUpperCase()
      .split('')
      .map((c) => 0x1f1e6 + c.charCodeAt(0) - 65),
  );
}

export function plural(n, singular, pluralForm = `${singular}s`) {
  return `${formatNumber(n)} ${n === 1 ? singular : pluralForm}`;
}

export function formatNumber(n) {
  return Number.isFinite(n) ? n.toLocaleString('en-US') : String(n ?? '');
}

/** Accepts ISO strings, "YYYY-MM-DD HH:MM:SS UTC", or unix seconds. */
export function toDate(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') return new Date(value < 1e12 ? value * 1000 : value);
  const s = String(value)
    .trim()
    .replace(/ UTC$/, 'Z')
    .replace(/^(\d{4}-\d{2}-\d{2}) (\d)/, '$1T$2');
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** "2026-10-03" style date (UTC). */
export function formatDate(value) {
  const d = toDate(value);
  return d ? d.toISOString().slice(0, 10) : '';
}

/** "2026-10-03 14:05 UTC" */
export function formatDateTime(value) {
  const d = toDate(value);
  return d ? `${d.toISOString().slice(0, 16).replace('T', ' ')} UTC` : '';
}

/** "5 min ago", "3 days ago". */
export function timeAgo(value, now = Date.now()) {
  const d = toDate(value);
  if (!d) return '';
  const seconds = Math.round((now - d.getTime()) / 1000);
  if (seconds < 45) return 'just now';
  const units = [
    ['year', 365 * 86400],
    ['month', 30 * 86400],
    ['day', 86400],
    ['hour', 3600],
    ['min', 60],
  ];
  for (const [unit, size] of units) {
    const n = Math.floor(Math.abs(seconds) / size);
    if (n >= 1) {
      const label = unit === 'min' ? 'min' : n === 1 ? unit : `${unit}s`;
      return seconds >= 0 ? `${n} ${label} ago` : `in ${n} ${label}`;
    }
  }
  return 'just now';
}

/** Join the truthy parts of a list. */
export function joinParts(parts, sep = ', ') {
  return parts.filter((p) => p !== null && p !== undefined && String(p).trim() !== '').join(sep);
}

export function truncate(text, max = 160) {
  const s = String(text ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

/** Only allow http(s) links coming from API data. */
export function safeUrl(url) {
  if (typeof url !== 'string') return null;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : null;
  } catch {
    return null;
  }
}
