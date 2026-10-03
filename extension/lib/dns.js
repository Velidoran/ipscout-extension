// DNS-over-HTTPS helpers (JSON API). Google first, Cloudflare as a fallback.

import { LookupError } from './http.js';
import { normalizeIp } from './ip.js';

const RESOLVERS = [
  {
    name: 'Google Public DNS',
    url: (name, type) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
    headers: { Accept: 'application/dns-json' },
  },
  {
    name: 'Cloudflare DNS',
    url: (name, type) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
    headers: { Accept: 'application/dns-json' },
  },
];

const TYPE_CODES = { A: 1, CNAME: 5, PTR: 12, AAAA: 28 };

/**
 * Resolve one record type. Resolves to { status, answers, resolver } where
 * status is the DNS RCODE (0 = NOERROR, 3 = NXDOMAIN).
 * `fetchJson` is the bound fetch helper from the lookup context.
 */
export async function resolveDns(name, type, fetchJson) {
  let lastError = null;
  for (const resolver of RESOLVERS) {
    try {
      const { data } = await fetchJson(resolver.url(name, type), { headers: resolver.headers, timeoutMs: 8000 });
      if (!data || typeof data.Status !== 'number') throw new LookupError('parse', 'Unexpected DNS response');
      if (data.Status === 2) throw new LookupError('server', 'DNS server failure (SERVFAIL)');
      const answers = (Array.isArray(data.Answer) ? data.Answer : [])
        .filter((a) => a.type === TYPE_CODES[type] && typeof a.data === 'string')
        .map((a) => a.data.replace(/\.$/, ''));
      return { status: data.Status, answers, resolver: resolver.name };
    } catch (err) {
      if (err?.kind === 'aborted') throw err;
      lastError = err;
    }
  }
  throw lastError ?? new LookupError('network', 'DNS lookup failed');
}

/** Resolve a hostname to its IPv4 and IPv6 addresses (canonical form). */
export async function resolveHost(host, fetchJson) {
  const [a, aaaa] = await Promise.allSettled([resolveDns(host, 'A', fetchJson), resolveDns(host, 'AAAA', fetchJson)]);
  if (a.status === 'rejected' && aaaa.status === 'rejected') throw a.reason;
  const collect = (r) => (r.status === 'fulfilled' ? r.value.answers.map((x) => normalizeIp(x)?.ip).filter(Boolean) : []);
  return { ipv4: [...new Set(collect(a))], ipv6: [...new Set(collect(aaaa))] };
}
