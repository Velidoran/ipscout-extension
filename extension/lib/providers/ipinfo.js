import { LookupError } from '../http.js';
import { countryName, joinParts } from '../format.js';

export function parseIpinfo(d) {
  if (!d || typeof d !== 'object' || !d.ip) throw new LookupError('parse', 'Unexpected response from IPinfo');
  if (d.bogon) {
    return { verdict: 'info', summary: 'Bogon (reserved) address', fields: [], tags: ['Bogon'], lists: [], flags: [], facts: {} };
  }

  const orgMatch = typeof d.org === 'string' ? d.org.match(/^(AS\d+)\s+(.*)$/i) : null;
  const asn = orgMatch ? orgMatch[1].toUpperCase() : null;
  const org = orgMatch ? orgMatch[2] : d.org || null;
  const place = joinParts([d.city, d.region, countryName(d.country)]);
  const [lat, lon] = typeof d.loc === 'string' ? d.loc.split(',').map(Number) : [];
  const hasCoords = Number.isFinite(lat) && Number.isFinite(lon);

  const fields = [
    d.hostname && { label: 'Hostname', value: d.hostname, mono: true },
    place && { label: 'Location', value: place },
    hasCoords && {
      label: 'Coordinates',
      value: `${lat}, ${lon} (approximate)`,
      href: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=9/${lat}/${lon}`,
    },
    (asn || org) && { label: 'Organization', value: joinParts([asn, org], ' · ') },
    d.postal && { label: 'Postal code', value: d.postal },
    d.timezone && { label: 'Time zone', value: d.timezone },
    d.anycast && { label: 'Anycast', value: 'Yes — served from many locations' },
  ].filter(Boolean);

  return {
    verdict: 'info',
    summary: joinParts([place, joinParts([asn, org], ' ')], ' · ') || 'No location data',
    fields,
    tags: d.anycast ? ['Anycast'] : [],
    lists: [],
    flags: d.anycast ? ['anycast'] : [],
    facts: {
      countryCode: d.country || null,
      city: d.city || null,
      region: d.region || null,
      asn,
      org,
      hostname: d.hostname || null,
    },
  };
}

export default {
  id: 'ipinfo',
  name: 'IPinfo',
  category: 'network',
  description: 'Geolocation, owning organization / ASN and hostname.',
  homepage: 'https://ipinfo.io',
  webUrl: (ip) => `https://ipinfo.io/${ip}`,
  key: {
    required: false,
    url: 'https://ipinfo.io/signup',
    hint: 'Optional: free token raises the limit to 50,000 lookups/month',
  },
  freeTier: '1,000/day without a token · 50,000/month with a free token',
  ipv6: true,

  async lookup(ip, ctx) {
    const headers = { Accept: 'application/json' };
    if (ctx.apiKey) headers.Authorization = `Bearer ${ctx.apiKey}`;
    const { data } = await ctx.fetchJson(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, { headers });
    const result = parseIpinfo(data);
    result.raw = data;
    return result;
  },
};
