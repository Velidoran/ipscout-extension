import { LookupError } from '../http.js';
import { countryName, formatDate, formatNumber, plural, timeAgo } from '../format.js';

export function parseVirusTotal(json) {
  const a = json?.data?.attributes;
  if (!a || typeof a !== 'object') throw new LookupError('parse', 'Unexpected response from VirusTotal');

  const s = a.last_analysis_stats || {};
  const malicious = Number(s.malicious) || 0;
  const suspicious = Number(s.suspicious) || 0;
  const engines = ['malicious', 'suspicious', 'harmless', 'undetected', 'timeout'].reduce((n, k) => n + (Number(s[k]) || 0), 0);

  let verdict = 'none';
  if (malicious >= 3) verdict = 'malicious';
  else if (malicious + suspicious > 0) verdict = 'suspicious';
  else if (engines > 0) verdict = 'clean';

  let summary = engines ? `${malicious}/${engines} security vendors flag this IP as malicious` : 'No analysis available yet';
  if (suspicious) summary += ` · ${suspicious} suspicious`;

  const votes = a.total_votes || {};
  const asn = a.asn ? `AS${a.asn}` : null;
  const fields = [
    engines && { label: 'Detections', value: `${malicious} malicious · ${suspicious} suspicious · ${engines} engines` },
    Number.isFinite(a.reputation) && { label: 'Community score', value: formatNumber(a.reputation) },
    (votes.harmless || votes.malicious) && {
      label: 'Community votes',
      value: `${formatNumber(votes.harmless || 0)} harmless · ${formatNumber(votes.malicious || 0)} malicious`,
    },
    (asn || a.as_owner) && { label: 'AS', value: [asn, a.as_owner].filter(Boolean).join(' · ') },
    a.network && { label: 'Network', value: a.network, mono: true },
    a.country && { label: 'Country', value: countryName(a.country) },
    a.regional_internet_registry && { label: 'Registry', value: a.regional_internet_registry },
    a.last_analysis_date && {
      label: 'Last analysis',
      value: `${formatDate(a.last_analysis_date)} (${timeAgo(a.last_analysis_date)})`,
    },
  ].filter(Boolean);

  const flagged = Object.values(a.last_analysis_results || {})
    .filter((r) => r && (r.category === 'malicious' || r.category === 'suspicious'))
    .sort((x, y) => (x.category === y.category ? 0 : x.category === 'malicious' ? -1 : 1));
  const lists = flagged.length
    ? [
        {
          title: `Flagged by ${plural(flagged.length, 'vendor')}`,
          items: flagged.map((r) => ({ text: r.engine_name || 'Unknown engine', sub: [r.result, r.category].filter(Boolean).join(' · ') })),
        },
      ]
    : [];

  return {
    verdict,
    summary,
    score: { value: malicious, max: engines },
    fields,
    tags: Array.isArray(a.tags) ? a.tags.slice(0, 10) : [],
    lists,
    flags: [],
    facts: { countryCode: a.country || null, asn, org: a.as_owner || null, network: a.network || null },
  };
}

export default {
  id: 'virustotal',
  name: 'VirusTotal',
  category: 'reputation',
  description: 'Verdicts from ~90 security vendors plus community votes.',
  homepage: 'https://www.virustotal.com',
  webUrl: (ip) => `https://www.virustotal.com/gui/ip-address/${ip}`,
  key: {
    required: true,
    url: 'https://www.virustotal.com/gui/my-apikey',
    hint: 'Free community account → profile menu → API key',
  },
  freeTier: '500 lookups/day, 4/min (non-commercial)',
  ipv6: true,

  async lookup(ip, ctx) {
    const { data } = await ctx.fetchJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
      headers: { 'x-apikey': ctx.apiKey, Accept: 'application/json' },
    });
    const result = parseVirusTotal(data);
    result.raw = data;
    return result;
  },
};
