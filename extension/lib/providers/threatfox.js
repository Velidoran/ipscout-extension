import { LookupError } from '../http.js';
import { formatDate, plural } from '../format.js';

/** ThreatFox stores IOCs as "ip" or "ip:port"; its search is a prefix match. */
function iocMatchesIp(ioc, ip) {
  if (typeof ioc !== 'string') return false;
  const value = ioc.trim().toLowerCase();
  if (value === ip) return true;
  if (ip.includes(':')) return value === `[${ip}]` || value.startsWith(`[${ip}]:`);
  return value.startsWith(`${ip}:`);
}

export function parseThreatFox(json, ip) {
  if (!json || typeof json !== 'object') throw new LookupError('parse', 'Unexpected response from ThreatFox');
  const status = json.query_status;
  if (status === 'no_result') {
    return { verdict: 'none', summary: 'No matching IOCs', fields: [], tags: [], lists: [], flags: [], facts: {} };
  }
  if (status !== 'ok') {
    const kind = /auth|key/i.test(String(status)) ? 'auth' : 'http';
    throw new LookupError(kind, kind === 'auth' ? 'API key missing or rejected' : `ThreatFox: ${status || 'unknown error'}`, {
      detail: typeof json.data === 'string' ? json.data : '',
    });
  }

  const iocs = (Array.isArray(json.data) ? json.data : []).filter((x) => iocMatchesIp(x.ioc, ip));
  if (!iocs.length) {
    return { verdict: 'none', summary: 'No matching IOCs', fields: [], tags: [], lists: [], flags: [], facts: {} };
  }

  const malware = [...new Set(iocs.map((x) => x.malware_printable).filter((m) => m && m !== 'Unknown malware'))];
  const threatTypes = [...new Set(iocs.map((x) => x.threat_type_desc || x.threat_type).filter(Boolean))];
  const maxConfidence = Math.max(...iocs.map((x) => Number(x.confidence_level) || 0));
  const firstSeen = iocs
    .map((x) => x.first_seen)
    .filter(Boolean)
    .sort()[0];
  const lastSeen = iocs
    .map((x) => x.last_seen || x.first_seen)
    .filter(Boolean)
    .sort()
    .pop();

  const fields = [
    { label: 'Matches', value: plural(iocs.length, 'IOC') },
    malware.length && { label: 'Malware', value: malware.join(', ') },
    threatTypes.length && { label: 'Threat type', value: threatTypes.join(', ') },
    { label: 'Confidence', value: `${maxConfidence}%` },
    firstSeen && { label: 'First seen', value: formatDate(firstSeen) },
    lastSeen && { label: 'Last seen', value: formatDate(lastSeen) },
  ].filter(Boolean);

  const lists = [
    {
      title: 'Indicators of compromise',
      items: iocs.slice(0, 15).map((x) => ({
        text: `${x.ioc} — ${x.malware_printable || x.malware || 'Unknown malware'}`,
        href: x.id ? `https://threatfox.abuse.ch/ioc/${encodeURIComponent(x.id)}/` : null,
        sub: [
          x.threat_type_desc || x.threat_type,
          x.confidence_level != null && `confidence ${x.confidence_level}%`,
          x.first_seen && `first seen ${formatDate(x.first_seen)}`,
        ]
          .filter(Boolean)
          .join(' · '),
      })),
      more: Math.max(0, iocs.length - 15),
    },
  ];

  const extraTags = iocs.flatMap((x) => (Array.isArray(x.tags) ? x.tags : [])).filter(Boolean);
  return {
    verdict: 'malicious',
    summary: `${plural(iocs.length, 'IOC')}${malware.length ? ` · ${malware.slice(0, 3).join(', ')}` : ''}${threatTypes.length ? ` (${threatTypes[0]})` : ''}`,
    fields,
    tags: [...new Set([...malware, ...extraTags])].slice(0, 8),
    lists,
    flags: [],
    facts: {},
  };
}

export default {
  id: 'threatfox',
  name: 'ThreatFox',
  category: 'reputation',
  description: 'abuse.ch database of malware C2 servers and other IOCs.',
  homepage: 'https://threatfox.abuse.ch',
  webUrl: (ip) => `https://threatfox.abuse.ch/browse.php?search=ioc%3A${encodeURIComponent(ip)}`,
  key: {
    required: true,
    url: 'https://auth.abuse.ch/',
    hint: 'Free abuse.ch Auth-Key (also works for URLhaus and MalwareBazaar)',
  },
  freeTier: 'fair use with a free abuse.ch Auth-Key',
  ipv6: true,

  async lookup(ip, ctx) {
    const { data } = await ctx.fetchJson('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Auth-Key': ctx.apiKey, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: ip }),
    });
    const result = parseThreatFox(data, ip);
    result.raw = data;
    return result;
  },
};
