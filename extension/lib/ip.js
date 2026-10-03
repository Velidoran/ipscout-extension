// IP address parsing, canonicalisation, classification and extraction.
// Pure functions only (no chrome.* APIs) so they can be unit tested in Node.

const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
const IPV4_EXACT = new RegExp(`^${OCTET}(?:\\.${OCTET}){3}$`);

// Matches IPv4 addresses embedded in free text. The look-arounds stop us from
// matching pieces of longer dotted sequences such as version numbers or OIDs.
const IPV4_IN_TEXT = new RegExp(`(?<![\\d.])${OCTET}(?:\\.${OCTET}){3}(?!\\.?\\d)`, 'g');

// Loose IPv6 candidate matcher; every candidate is validated by parseIPv6().
const IPV6_IN_TEXT =
  /(?<![0-9a-z:.])(?:[0-9a-f]{0,4}:){2,7}(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{0,4})(?:%[0-9a-z_.~-]+)?(?![0-9a-z:]|\.[0-9a-z])/gi;

/** Undo common IOC "defanging" such as 1.2.3[.]4 or 2001:db8[:]:1. */
export function refang(text) {
  return String(text)
    .replace(/\s?(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\{dot\})\s?/gi, '.')
    .replace(/\[:\]/g, ':');
}

/** Defang an IP so it is not clickable when pasted into tickets or chat. */
export function defang(ip) {
  return ip.includes(':') ? ip.replace(/:/g, '[:]') : ip.replace(/\./g, '[.]');
}

export function parseIPv4(str) {
  if (typeof str !== 'string' || !IPV4_EXACT.test(str)) return null;
  return str.split('.').map(Number);
}

/** Parse an IPv6 address into eight 16-bit groups, or null if invalid. */
export function parseIPv6(str) {
  if (typeof str !== 'string' || str.length < 2 || str.length > 45 || !str.includes(':')) {
    return null;
  }
  let s = str.toLowerCase();
  let tail = [];

  // Embedded dotted-quad in the low 32 bits, e.g. ::ffff:192.0.2.1
  const lastColon = s.lastIndexOf(':');
  if (s.indexOf('.', lastColon) !== -1) {
    const v4 = parseIPv4(s.slice(lastColon + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, lastColon + 1);
    if (!s.endsWith('::')) s = s.slice(0, -1);
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;
  const split = (part) => (part === '' ? [] : part.split(':'));
  const head = split(halves[0]);
  const rest = halves.length === 2 ? split(halves[1]) : [];
  if (![...head, ...rest].every((g) => /^[0-9a-f]{1,4}$/.test(g))) return null;

  const toNums = (groups) => groups.map((g) => parseInt(g, 16));
  const count = head.length + rest.length + tail.length;
  if (halves.length === 2) {
    if (count > 7) return null; // "::" must stand for at least one group
    return [...toNums(head), ...new Array(8 - count).fill(0), ...toNums(rest), ...tail];
  }
  return count === 8 ? [...toNums(head), ...tail] : null;
}

/** RFC 5952 canonical text form of eight 16-bit groups. */
export function formatIPv6(groups) {
  let bestStart = -1;
  let bestLen = 1; // only runs of two or more zero groups are compressed
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

/**
 * Normalise user input into a canonical IP.
 * Accepts brackets, ports, IPv6 zone ids and defanged notation.
 * IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are converted to IPv4.
 * Returns { ip, version, parts } or null.
 */
export function normalizeIp(input) {
  if (typeof input !== 'string') return null;
  let s = refang(input.trim());

  let m = s.match(/^\[([^\]]+)\](?::\d{1,5})?$/); // [v6] or [v6]:port
  if (m) s = m[1];
  m = s.match(/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/); // v4:port
  if (m) s = m[1];

  const v4 = parseIPv4(s);
  if (v4) return { ip: v4.join('.'), version: 4, parts: v4 };

  const v6 = parseIPv6(s.replace(/%[0-9a-z_.~-]+$/i, ''));
  if (!v6) return null;
  if (v6.slice(0, 5).every((g) => g === 0) && v6[5] === 0xffff) {
    const octets = [v6[6] >> 8, v6[6] & 0xff, v6[7] >> 8, v6[7] & 0xff];
    return { ip: octets.join('.'), version: 4, parts: octets };
  }
  return { ip: formatIPv6(v6), version: 6, parts: v6 };
}

export function isValidIp(input) {
  return normalizeIp(input) !== null;
}

/* ------------------------------------------------------------------ */
/* Special-purpose address ranges (IANA registries)                     */
/* ------------------------------------------------------------------ */

const V4_SPECIAL = [
  ['0.0.0.0/8', 'This network', 'RFC 1122'],
  ['10.0.0.0/8', 'Private network', 'RFC 1918'],
  ['100.64.0.0/10', 'Shared address space (carrier-grade NAT)', 'RFC 6598'],
  ['127.0.0.0/8', 'Loopback', 'RFC 1122'],
  ['169.254.0.0/16', 'Link-local', 'RFC 3927'],
  ['172.16.0.0/12', 'Private network', 'RFC 1918'],
  ['192.0.0.0/24', 'IETF protocol assignments', 'RFC 6890'],
  ['192.0.2.0/24', 'Documentation (TEST-NET-1)', 'RFC 5737'],
  ['192.168.0.0/16', 'Private network', 'RFC 1918'],
  ['198.18.0.0/15', 'Benchmarking', 'RFC 2544'],
  ['198.51.100.0/24', 'Documentation (TEST-NET-2)', 'RFC 5737'],
  ['203.0.113.0/24', 'Documentation (TEST-NET-3)', 'RFC 5737'],
  ['224.0.0.0/4', 'Multicast', 'RFC 5771'],
  ['240.0.0.0/4', 'Reserved for future use', 'RFC 1112'],
  ['255.255.255.255/32', 'Limited broadcast', 'RFC 919'],
];

const V6_SPECIAL = [
  ['::/128', 'Unspecified address', 'RFC 4291'],
  ['::1/128', 'Loopback', 'RFC 4291'],
  ['64:ff9b::/96', 'NAT64 translation prefix', 'RFC 6052'],
  ['64:ff9b:1::/48', 'Local-use NAT64 prefix', 'RFC 8215'],
  ['100::/64', 'Discard-only prefix', 'RFC 6666'],
  ['2001:2::/48', 'Benchmarking', 'RFC 5180'],
  ['2001:10::/28', 'ORCHID (deprecated)', 'RFC 4843'],
  ['2001:20::/28', 'ORCHIDv2', 'RFC 7343'],
  ['2001:db8::/32', 'Documentation', 'RFC 3849'],
  ['3fff::/20', 'Documentation', 'RFC 9637'],
  ['5f00::/16', 'Segment Routing (SRv6) SIDs', 'RFC 9602'],
  ['fc00::/7', 'Unique local address (private)', 'RFC 4193'],
  ['fe80::/10', 'Link-local', 'RFC 4291'],
  ['ff00::/8', 'Multicast', 'RFC 4291'],
];

function v4ToInt(parts) {
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function v6ToBigInt(parts) {
  return parts.reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
}

function compile(table, version) {
  return table
    .map(([cidr, label, rfc]) => {
      const [addr, len] = cidr.split('/');
      const prefix = Number(len);
      if (version === 4) {
        const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
        const net = (v4ToInt(parseIPv4(addr)) & mask) >>> 0;
        return { cidr, label, rfc, prefix, test: (n) => (n & mask) >>> 0 === net };
      }
      const shift = BigInt(128 - prefix);
      const net = v6ToBigInt(parseIPv6(addr)) >> shift;
      return { cidr, label, rfc, prefix, test: (n) => n >> shift === net };
    })
    .sort((a, b) => b.prefix - a.prefix); // most specific first
}

const V4_RANGES = compile(V4_SPECIAL, 4);
const V6_RANGES = compile(V6_SPECIAL, 6);
const PRIVATE_LABELS = new Set(['Private network', 'Unique local address (private)', 'Shared address space (carrier-grade NAT)']);

/**
 * Classify a normalised IP (from normalizeIp).
 * Returns { isPublic, label, rfc, cidr }. Non-public addresses are not sent
 * to any external service, since no public source knows anything about them.
 */
export function classifyIp(info) {
  if (info.version === 4) {
    const n = v4ToInt(info.parts);
    const hit = V4_RANGES.find((r) => r.test(n));
    if (hit) return { isPublic: false, isPrivate: PRIVATE_LABELS.has(hit.label), label: hit.label, rfc: hit.rfc, cidr: hit.cidr };
    return { isPublic: true, isPrivate: false, label: 'Public address' };
  }
  const n = v6ToBigInt(info.parts);
  const hit = V6_RANGES.find((r) => r.test(n));
  if (hit) return { isPublic: false, isPrivate: PRIVATE_LABELS.has(hit.label), label: hit.label, rfc: hit.rfc, cidr: hit.cidr };
  if (n >> 125n !== 1n) {
    return { isPublic: false, isPrivate: false, label: 'Reserved (outside global unicast space)', rfc: 'RFC 4291', cidr: null };
  }
  return { isPublic: true, isPrivate: false, label: 'Public address' };
}

/** DNS name used for reverse (PTR) lookups. */
export function reversePointerName(info) {
  if (info.version === 4) return `${[...info.parts].reverse().join('.')}.in-addr.arpa`;
  const nibbles = info.parts.map((g) => g.toString(16).padStart(4, '0')).join('');
  return `${nibbles.split('').reverse().join('.')}.ip6.arpa`;
}

/**
 * Find every IP address in a block of text, in order of first appearance.
 * Handles defanged notation. Options:
 *   limit      – maximum number of unique addresses to return
 *   publicOnly – drop private/reserved addresses
 */
export function extractIps(text, { limit = 100, publicOnly = false } = {}) {
  if (!text) return [];
  const source = refang(String(text));
  const matches = [];
  for (const m of source.matchAll(IPV4_IN_TEXT)) matches.push({ index: m.index, raw: m[0] });
  for (const m of source.matchAll(IPV6_IN_TEXT)) matches.push({ index: m.index, raw: m[0] });
  matches.sort((a, b) => a.index - b.index);

  const seen = new Set();
  const out = [];
  for (const { raw } of matches) {
    const info = normalizeIp(raw);
    if (!info || seen.has(info.ip)) continue;
    if (publicOnly && !classifyIp(info).isPublic) continue;
    seen.add(info.ip);
    out.push(info.ip);
    if (out.length >= limit) break;
  }
  return out;
}

/**
 * Interpret whatever the user typed, pasted or selected:
 *   { type: 'ip', info, others }  – an IP (bare, with port, inside a URL, or found in text)
 *   { type: 'host', host }        – a hostname / URL to resolve first
 *   null                          – nothing usable
 */
export function parseQuery(input) {
  const raw = String(input ?? '').trim();
  if (!raw) return null;

  const direct = normalizeIp(raw);
  if (direct) return { type: 'ip', info: direct, others: [] };

  const urlish = refang(raw).replace(/^hxxp/i, 'http');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(urlish)) {
    try {
      const info = normalizeIp(new URL(urlish).hostname);
      if (info) return { type: 'ip', info, others: [] };
    } catch {
      // not a URL after all; fall through
    }
  }

  const host = parseHostname(raw);
  if (host) return { type: 'host', host };

  const ips = extractIps(raw, { limit: 25 });
  if (ips.length) return { type: 'ip', info: normalizeIp(ips[0]), others: ips.slice(1) };
  return null;
}

/** Parse a hostname or URL the user typed into a bare lowercase hostname, or null. */
export function parseHostname(input) {
  if (typeof input !== 'string') return null;
  let s = refang(input.trim()).replace(/^hxxp/i, 'http');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return null;
    }
  } else {
    s = s.split(/[/?#]/)[0].replace(/:\d{1,5}$/, '');
  }
  s = s.replace(/\.$/, '').toLowerCase();
  const label = '(?!-)[a-z0-9-]{1,63}(?<!-)';
  const re = new RegExp(`^(?=.{1,253}$)${label}(?:\\.${label})*\\.(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`);
  return re.test(s) ? s : null;
}
