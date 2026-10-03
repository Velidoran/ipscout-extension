import { LookupError } from '../http.js';
import { countryName, formatDate, joinParts, truncate } from '../format.js';

const RIR_BY_HOST = {
  'rdap.arin.net': 'ARIN',
  'rdap.db.ripe.net': 'RIPE NCC',
  'rdap.apnic.net': 'APNIC',
  'rdap.lacnic.net': 'LACNIC',
  'rdap.afrinic.net': 'AFRINIC',
};
const RIR_BY_WHOIS = {
  'whois.arin.net': 'ARIN',
  'whois.ripe.net': 'RIPE NCC',
  'whois.apnic.net': 'APNIC',
  'whois.lacnic.net': 'LACNIC',
  'whois.afrinic.net': 'AFRINIC',
};

/** Read a property from an RDAP entity's jCard (RFC 7095). */
function vcardValues(entity, prop) {
  const props = entity?.vcardArray?.[1];
  if (!Array.isArray(props)) return [];
  return props
    .filter((p) => Array.isArray(p) && p[0] === prop)
    .map((p) => {
      const value = Array.isArray(p[3]) ? p[3].filter(Boolean).join(' ') : p[3];
      return prop === 'adr' && p[1]?.label ? p[1].label : value;
    })
    .filter((v) => typeof v === 'string' && v.trim());
}

/** Depth-first search for entities that carry a given role. */
function findByRole(entities, role, out = [], depth = 0) {
  if (!Array.isArray(entities) || depth > 4) return out;
  for (const e of entities) {
    if (Array.isArray(e?.roles) && e.roles.includes(role)) out.push(e);
    findByRole(e?.entities, role, out, depth + 1);
  }
  return out;
}

function entityName(e) {
  return vcardValues(e, 'fn')[0] || vcardValues(e, 'org')[0] || e?.handle || '';
}

export function parseRdap(status, d, finalUrl) {
  if (status === 404) {
    return { verdict: 'none', summary: 'No registration record found', fields: [], tags: [], lists: [], flags: [], facts: {} };
  }
  if (!d || typeof d !== 'object' || !(d.startAddress || d.handle || d.name)) {
    throw new LookupError('parse', 'Unexpected RDAP response');
  }

  let rir = null;
  try {
    rir = RIR_BY_HOST[new URL(finalUrl).hostname] || null;
  } catch {
    rir = null;
  }
  rir = rir || RIR_BY_WHOIS[String(d.port43 || '').toLowerCase()] || null;

  const cidrs = (Array.isArray(d.cidr0_cidrs) ? d.cidr0_cidrs : [])
    .map((c) => (c.v4prefix || c.v6prefix ? `${c.v4prefix || c.v6prefix}/${c.length}` : null))
    .filter(Boolean);
  const range = d.startAddress && d.endAddress ? `${d.startAddress} – ${d.endAddress}` : '';

  const registrant = findByRole(d.entities, 'registrant')[0];
  const abuse = findByRole(d.entities, 'abuse')[0];
  const abuseEmails = abuse ? vcardValues(abuse, 'email') : [];
  const abusePhone = abuse ? vcardValues(abuse, 'tel')[0]?.replace(/^tel:/, '') : '';
  const org = entityName(registrant) || null;

  const events = Array.isArray(d.events) ? d.events : [];
  const registered = events.find((e) => e.eventAction === 'registration')?.eventDate;
  const changed = events.find((e) => e.eventAction === 'last changed')?.eventDate;

  const originKey = Object.keys(d).find((k) => /originautnums$/i.test(k));
  const originAs = originKey && Array.isArray(d[originKey]) ? d[originKey].map((n) => `AS${n}`).join(', ') : '';

  const remark = (Array.isArray(d.remarks) ? d.remarks : [])
    .flatMap((r) => (Array.isArray(r.description) ? r.description : []))
    .filter(Boolean)
    .join(' ');

  const fields = [
    d.name && { label: 'Network name', value: d.name, mono: true },
    (cidrs.length || range) && {
      label: 'Range',
      value: cidrs.length ? `${cidrs.join(', ')}${range ? ` (${range})` : ''}` : range,
      mono: true,
    },
    org && { label: 'Registrant', value: org },
    abuseEmails.length && { label: 'Abuse contact', value: abuseEmails.join(', '), mono: true, href: `mailto:${abuseEmails[0]}` },
    abusePhone && { label: 'Abuse phone', value: abusePhone },
    originAs && { label: 'Origin AS', value: originAs },
    d.type && { label: 'Allocation', value: String(d.type) },
    d.country && { label: 'Country', value: countryName(d.country) },
    rir && { label: 'Registry', value: rir },
    registered && { label: 'Registered', value: formatDate(registered) },
    changed && { label: 'Last changed', value: formatDate(changed) },
    d.handle && { label: 'Handle', value: d.handle, mono: true },
    remark && { label: 'Remarks', value: truncate(remark, 220) },
  ].filter(Boolean);

  return {
    verdict: 'info',
    summary: joinParts([d.name, cidrs[0] || range, org], ' · ') || 'Registration record found',
    fields,
    tags: rir ? [rir] : [],
    lists: [],
    flags: [],
    facts: {
      network: cidrs[0] || null,
      registrant: org,
      abuseEmail: abuseEmails[0] || null,
      countryCode: d.country || null,
    },
  };
}

export default {
  id: 'rdap',
  name: 'WHOIS (RDAP)',
  category: 'network',
  description: 'Registry record: network owner, address range, abuse contact and dates.',
  homepage: 'https://about.rdap.org',
  webUrl: (ip) => `https://search.arin.net/rdap/?query=${encodeURIComponent(ip)}`,
  webLabel: 'Open RDAP search',
  key: null,
  freeTier: 'no key needed (data from the regional internet registries)',
  ipv6: true,

  async lookup(ip, ctx) {
    // rdap.org redirects to the authoritative registry (ARIN, RIPE NCC, APNIC, LACNIC, AFRINIC).
    const { status, data, url } = await ctx.fetchJson(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
      allowStatus: [404],
      timeoutMs: 20000,
    });
    const result = parseRdap(status, data, url);
    result.raw = data;
    return result;
  },
};
