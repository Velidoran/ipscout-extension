import { LookupError } from '../http.js';
import { countryName, joinParts } from '../format.js';

const FLAG_FIELDS = [
  ['is_vpn', 'vpn', 'VPN'],
  ['is_proxy', 'proxy', 'Proxy'],
  ['is_tor', 'tor', 'Tor'],
  ['is_datacenter', 'hosting', 'Hosting / data center'],
  ['is_abuser', 'abuser', 'Abuser'],
  ['is_mobile', 'mobile', 'Mobile network'],
  ['is_crawler', 'crawler', 'Crawler'],
  ['is_satellite', 'satellite', 'Satellite'],
];

export function parseIpapi(d) {
  if (!d || typeof d !== 'object') throw new LookupError('parse', 'Unexpected response from ipapi.is');
  if (typeof d.error === 'string') {
    const kind = /limit|quota/i.test(d.error) ? 'rate-limit' : /key/i.test(d.error) ? 'auth' : 'http';
    throw new LookupError(kind, kind === 'rate-limit' ? 'Free-tier rate limit reached — try again later' : 'ipapi.is error', {
      detail: d.error,
    });
  }
  if (!d.ip) throw new LookupError('parse', 'Unexpected response from ipapi.is');

  const active = FLAG_FIELDS.filter(([field]) => d[field] === true);
  const company = d.company || {};
  const asnInfo = d.asn || {};
  const loc = d.location || {};
  const asn = asnInfo.asn ? `AS${asnInfo.asn}` : null;
  const place = joinParts([loc.city, loc.state, loc.country || countryName(loc.country_code)]);

  const fields = [
    { label: 'Flags', value: active.length ? active.map(([, , label]) => label).join(', ') : 'None (not VPN, proxy, Tor or hosting)' },
    company.name && { label: 'Company', value: joinParts([company.name, company.type && `(${company.type})`], ' ') },
    (asn || asnInfo.org) && { label: 'AS', value: joinParts([asn, asnInfo.org], ' · ') },
    asnInfo.route && { label: 'Route', value: asnInfo.route, mono: true },
    d.vpn?.service && { label: 'VPN service', value: d.vpn.service },
    d.datacenter?.datacenter && { label: 'Data center', value: d.datacenter.datacenter },
    company.abuser_score && { label: 'Abuser score', value: String(company.abuser_score) },
    d.abuse?.email && { label: 'Abuse contact', value: d.abuse.email, mono: true },
    place && { label: 'Location', value: place },
  ].filter(Boolean);

  const flags = active.map(([, flag]) => flag);
  return {
    verdict: d.is_abuser ? 'suspicious' : 'info',
    summary: active.length
      ? `${active.map(([, , label]) => label).join(', ')}${company.name ? ` · ${company.name}` : ''}`
      : `No VPN / proxy / Tor / hosting flags${company.name ? ` · ${company.name}` : ''}`,
    fields,
    tags: active.map(([, , label]) => label),
    lists: [],
    flags,
    facts: {
      countryCode: loc.country_code || null,
      city: loc.city || null,
      region: loc.state || null,
      asn,
      org: asnInfo.org || company.name || null,
      abuseEmail: d.abuse?.email || null,
    },
  };
}

export default {
  id: 'ipapi',
  name: 'ipapi.is',
  category: 'network',
  description: 'Detects VPNs, proxies, Tor, hosting providers and known abusers.',
  homepage: 'https://ipapi.is',
  webUrl: (ip) => `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`,
  key: {
    required: false,
    url: 'https://ipapi.is/',
    hint: 'Optional: works without a key for light use',
  },
  freeTier: '1,000 lookups/day',
  ipv6: true,

  async lookup(ip, ctx) {
    let url = `https://api.ipapi.is/?q=${encodeURIComponent(ip)}`;
    if (ctx.apiKey) url += `&key=${encodeURIComponent(ctx.apiKey)}`;
    const { data } = await ctx.fetchJson(url, { headers: { Accept: 'application/json' } });
    const result = parseIpapi(data);
    result.raw = data;
    return result;
  },
};
