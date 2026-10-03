import { resolveDns } from '../dns.js';
import { normalizeIp, reversePointerName } from '../ip.js';

export function buildRdnsResult(ptrs, checks, nxdomain) {
  if (!ptrs.length) {
    return {
      verdict: 'info',
      summary: nxdomain ? 'No PTR record (NXDOMAIN)' : 'No PTR record',
      fields: [{ label: 'PTR', value: 'None' }],
      tags: [],
      lists: [],
      flags: [],
      facts: {},
    };
  }
  const confirmed = checks.find((c) => c.ok);
  const fields = [
    { label: ptrs.length > 1 ? 'PTR records' : 'PTR record', value: ptrs.join(', '), mono: true },
    {
      label: 'Forward-confirmed',
      value: confirmed
        ? `Yes — ${confirmed.host} resolves back to this IP`
        : checks.some((c) => c.ok === false)
          ? 'No — the hostname does not resolve back to this IP'
          : 'Could not verify',
    },
  ];
  return {
    verdict: 'info',
    summary: `${ptrs[0]}${ptrs.length > 1 ? ` (+${ptrs.length - 1})` : ''}${confirmed ? ' · forward-confirmed' : ''}`,
    fields,
    tags: confirmed ? ['FCrDNS'] : [],
    lists: [],
    flags: [],
    facts: { hostname: ptrs[0], fcrdns: Boolean(confirmed) },
  };
}

export default {
  id: 'rdns',
  name: 'Reverse DNS',
  category: 'network',
  description: 'PTR hostname, checked by resolving it forward again (FCrDNS).',
  homepage: 'https://developers.google.com/speed/public-dns/docs/doh/json',
  webUrl: null,
  key: null,
  freeTier: 'no key needed (DNS-over-HTTPS via Google, Cloudflare as fallback)',
  ipv6: true,

  async lookup(ip, ctx) {
    const ptr = await resolveDns(reversePointerName(ctx.info), 'PTR', ctx.fetchJson);
    const ptrs = [...new Set(ptr.answers)];
    const type = ctx.info.version === 6 ? 'AAAA' : 'A';
    const checks = await Promise.all(
      ptrs.slice(0, 3).map(async (host) => {
        try {
          const fwd = await resolveDns(host, type, ctx.fetchJson);
          return { host, ok: fwd.answers.some((a) => normalizeIp(a)?.ip === ip) };
        } catch (err) {
          if (err?.kind === 'aborted') throw err;
          return { host, ok: null };
        }
      }),
    );
    const result = buildRdnsResult(ptrs, checks, ptr.status === 3);
    result.raw = { ptr: ptrs, forwardChecks: checks, resolver: ptr.resolver };
    return result;
  },
};
