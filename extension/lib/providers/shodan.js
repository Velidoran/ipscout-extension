import { LookupError } from '../http.js';
import { plural } from '../format.js';

const MALICIOUS_TAGS = new Set(['c2', 'malware']);
const SUSPICIOUS_TAGS = new Set(['compromised', 'doublepulsar']);
const FLAG_TAGS = { vpn: 'vpn', proxy: 'proxy', tor: 'tor', cloud: 'hosting', scanner: 'scanner' };

export function parseInternetDb(status, d) {
  if (status === 404) {
    return {
      verdict: 'none',
      summary: 'No open ports or services on record',
      fields: [],
      tags: [],
      lists: [],
      flags: [],
      facts: {},
    };
  }
  if (!d || typeof d !== 'object' || !Array.isArray(d.ports)) {
    throw new LookupError('parse', 'Unexpected response from Shodan InternetDB');
  }

  const ports = [...d.ports].sort((a, b) => a - b);
  const vulns = Array.isArray(d.vulns) ? [...d.vulns].sort().reverse() : [];
  const tags = Array.isArray(d.tags) ? d.tags : [];
  const hostnames = Array.isArray(d.hostnames) ? d.hostnames : [];
  const cpes = Array.isArray(d.cpes) ? d.cpes : [];

  let verdict = 'info';
  if (tags.some((t) => MALICIOUS_TAGS.has(t))) verdict = 'malicious';
  else if (tags.some((t) => SUSPICIOUS_TAGS.has(t))) verdict = 'suspicious';

  const parts = [
    ports.length ? `${plural(ports.length, 'open port')}: ${ports.slice(0, 8).join(', ')}${ports.length > 8 ? '…' : ''}` : 'No open ports',
  ];
  if (vulns.length) parts.push(plural(vulns.length, 'known CVE'));

  const fields = [
    { label: 'Open ports', value: ports.length ? ports.join(', ') : 'None', mono: true },
    vulns.length && { label: 'Vulnerabilities', value: plural(vulns.length, 'CVE') },
    hostnames.length && { label: 'Hostnames', value: hostnames.slice(0, 10).join(', '), mono: true },
    tags.length && { label: 'Tags', value: tags.join(', ') },
    cpes.length && { label: 'Software (CPE)', value: cpes.slice(0, 8).join(', '), mono: true },
  ].filter(Boolean);

  const lists = vulns.length
    ? [
        {
          title: 'Vulnerabilities (unverified, from banners)',
          items: vulns.slice(0, 25).map((cve) => ({ text: cve, href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}` })),
          more: Math.max(0, vulns.length - 25),
        },
      ]
    : [];

  const flags = [...new Set(tags.map((t) => FLAG_TAGS[t]).filter(Boolean))];

  return {
    verdict,
    summary: parts.join(' · '),
    fields,
    tags,
    lists,
    flags,
    facts: { hostname: hostnames[0] || null },
  };
}

export default {
  id: 'shodan',
  name: 'Shodan InternetDB',
  category: 'exposure',
  description: 'Open ports, known vulnerabilities, hostnames and tags from Shodan scans.',
  homepage: 'https://internetdb.shodan.io',
  webUrl: (ip) => `https://www.shodan.io/host/${ip}`,
  webLabel: 'Open full Shodan report',
  key: null,
  freeTier: 'no key needed (non-commercial use)',
  ipv6: false,

  async lookup(ip, ctx) {
    const { status, data } = await ctx.fetchJson(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/json' },
      allowStatus: [404],
    });
    const result = parseInternetDb(status, data);
    result.raw = data;
    return result;
  },
};
