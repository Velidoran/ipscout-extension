import { LookupError } from '../http.js';
import { formatDate, joinParts, plural } from '../format.js';

function names(list) {
  return (Array.isArray(list) ? list : []).map((x) => (typeof x === 'string' ? x : x?.display_name || x?.name || '')).filter(Boolean);
}

export function parseOtx(d) {
  if (!d || typeof d !== 'object' || !d.pulse_info) throw new LookupError('parse', 'Unexpected response from AlienVault OTX');

  const count = Number(d.pulse_info.count) || 0;
  const pulses = Array.isArray(d.pulse_info.pulses) ? d.pulse_info.pulses : [];
  const validation = (Array.isArray(d.validation) ? d.validation : []).map((v) => v?.message || v?.name || v?.source).filter(Boolean);
  const related = d.pulse_info.related || {};
  const malware = [...new Set([...names(related.alienvault?.malware_families), ...names(related.other?.malware_families)])];
  const adversaries = [...new Set([...names(related.alienvault?.adversary), ...names(related.other?.adversary)])];
  for (const p of pulses) {
    for (const m of names(p.malware_families)) if (!malware.includes(m)) malware.push(m);
    if (p.adversary && !adversaries.includes(p.adversary)) adversaries.push(p.adversary);
  }

  let verdict = 'none';
  if (validation.length) verdict = 'clean';
  else if (count > 0) verdict = 'suspicious';

  let summary = count ? `Referenced in ${plural(count, 'threat pulse')}` : 'Not referenced in any threat pulses';
  if (validation.length) summary += ` · allowlisted (${validation[0]})`;

  const fields = [
    { label: 'Pulses', value: count ? plural(count, 'pulse') : 'None' },
    validation.length && { label: 'Allowlist', value: validation.join('; ') },
    malware.length && { label: 'Malware families', value: malware.slice(0, 10).join(', ') },
    adversaries.length && { label: 'Adversaries', value: adversaries.slice(0, 10).join(', ') },
    Number(d.reputation) && { label: 'Reputation', value: String(d.reputation) },
    d.asn && { label: 'AS', value: d.asn },
    (d.city || d.country_name) && { label: 'Location', value: joinParts([d.city, d.region, d.country_name]) },
  ].filter(Boolean);

  const recent = [...pulses].sort((a, b) => String(b.modified || '').localeCompare(String(a.modified || ''))).slice(0, 6);
  const lists = recent.length
    ? [
        {
          title: 'Recent pulses',
          items: recent.map((p) => ({
            text: p.name || 'Untitled pulse',
            href: p.id ? `https://otx.alienvault.com/pulse/${encodeURIComponent(p.id)}` : null,
            sub: joinParts(
              [formatDate(p.modified || p.created), p.author?.username && `by ${p.author.username}`, (p.tags || []).slice(0, 4).join(', ')],
              ' · ',
            ),
          })),
          more: Math.max(0, count - recent.length),
        },
      ]
    : [];

  const asnMatch = typeof d.asn === 'string' ? d.asn.match(/^(AS\d+)\s*(.*)$/i) : null;
  return {
    verdict,
    summary,
    fields,
    tags: [...malware.slice(0, 5), ...adversaries.slice(0, 3)],
    lists,
    flags: [],
    facts: {
      countryCode: d.country_code || null,
      city: d.city || null,
      region: d.region || null,
      asn: asnMatch ? asnMatch[1].toUpperCase() : null,
      org: asnMatch?.[2] || null,
    },
  };
}

export default {
  id: 'otx',
  name: 'AlienVault OTX',
  category: 'reputation',
  description: 'Community threat-intel "pulses" that mention this IP.',
  homepage: 'https://otx.alienvault.com',
  webUrl: (ip) => `https://otx.alienvault.com/indicator/ip/${ip}`,
  key: {
    required: false,
    url: 'https://otx.alienvault.com/api',
    hint: 'Optional: free account → API key shown on the API page',
  },
  freeTier: 'works without a key; a free key raises rate limits',
  ipv6: true,

  async lookup(ip, ctx) {
    const type = ctx.info.version === 6 ? 'IPv6' : 'IPv4';
    const headers = { Accept: 'application/json' };
    if (ctx.apiKey) headers['X-OTX-API-KEY'] = ctx.apiKey;
    const { data } = await ctx.fetchJson(`https://otx.alienvault.com/api/v1/indicators/${type}/${encodeURIComponent(ip)}/general`, {
      headers,
      timeoutMs: 20000,
    });
    const result = parseOtx(data);
    result.raw = data;
    return result;
  },
};
