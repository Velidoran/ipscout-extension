import { LookupError } from '../http.js';
import { formatDate, formatDateTime, joinParts, plural } from '../format.js';
import { normalizeIp } from '../ip.js';

const FIELDS = 'nickname,fingerprint,or_addresses,exit_addresses,running,flags,first_seen,last_seen,as,as_name,contact';

/** "1.2.3.4:9001" / "[2001:db8::1]:9001" -> canonical IP. */
function addressOf(entry) {
  if (typeof entry !== 'string') return null;
  const m = entry.match(/^\[(.+)\]:\d+$/) || entry.match(/^([^:]+):\d+$/);
  return normalizeIp(m ? m[1] : entry)?.ip ?? null;
}

export function parseOnionoo(d, ip) {
  if (!d || typeof d !== 'object' || !Array.isArray(d.relays)) throw new LookupError('parse', 'Unexpected response from Onionoo');

  // Onionoo's search is a prefix match (1.2.3.4 also finds 1.2.3.45), so filter exactly.
  const matches = d.relays
    .map((r) => ({
      relay: r,
      or: (r.or_addresses || []).some((a) => addressOf(a) === ip),
      exit: (r.exit_addresses || []).some((a) => addressOf(a) === ip),
    }))
    .filter((m) => m.or || m.exit);

  const asOf = d.relays_published ? `relay list as of ${formatDateTime(d.relays_published)}` : '';
  if (!matches.length) {
    return {
      verdict: 'none',
      summary: 'Not a Tor relay or exit node',
      fields: asOf ? [{ label: 'Checked against', value: `Tor ${asOf}` }] : [],
      tags: [],
      lists: [],
      flags: [],
      facts: {},
    };
  }

  const isExit = matches.some((m) => m.exit || (m.or && (m.relay.flags || []).includes('Exit')));
  const relays = matches.map((m) => m.relay);
  const nicknames = [...new Set(relays.map((r) => r.nickname).filter(Boolean))];
  const running = relays.some((r) => r.running);
  const lastSeen = relays
    .map((r) => r.last_seen)
    .filter(Boolean)
    .sort()
    .pop();
  const firstSeen = relays
    .map((r) => r.first_seen)
    .filter(Boolean)
    .sort()[0];
  const first = relays[0];

  const fields = [
    { label: 'Role', value: isExit ? 'Exit node — traffic from Tor users leaves the network here' : 'Relay (not an exit)' },
    { label: 'Relays on this IP', value: String(relays.length) },
    nicknames.length && { label: 'Nickname', value: nicknames.join(', ') },
    { label: 'Running', value: running ? 'Yes' : 'No (seen recently)' },
    first.flags?.length && { label: 'Flags', value: first.flags.join(', ') },
    firstSeen && { label: 'First seen', value: formatDate(firstSeen) },
    lastSeen && { label: 'Last seen', value: formatDate(lastSeen) },
    (first.as || first.as_name) && { label: 'AS', value: joinParts([first.as, first.as_name], ' · ') },
    first.contact && { label: 'Operator contact', value: first.contact },
  ].filter(Boolean);

  const lists = [
    {
      title: `Tor ${plural(relays.length, 'relay')}`,
      items: relays.slice(0, 10).map((r) => ({
        text: r.nickname || r.fingerprint || 'Unnamed relay',
        href: r.fingerprint ? `https://metrics.torproject.org/rs.html#details/${encodeURIComponent(r.fingerprint)}` : null,
        sub: joinParts([r.running ? 'running' : 'not running', (r.flags || []).includes('Exit') ? 'exit' : null, r.fingerprint], ' · '),
      })),
      more: Math.max(0, relays.length - 10),
    },
  ];

  return {
    verdict: 'info',
    summary: `${isExit ? 'Tor exit node' : 'Tor relay (non-exit)'}${nicknames.length ? ` · ${nicknames.slice(0, 2).join(', ')}` : ''}${running ? '' : ' · not currently running'}`,
    fields,
    tags: [isExit ? 'Tor exit' : 'Tor relay'],
    lists,
    flags: [isExit ? 'tor' : 'tor-relay'],
    facts: {},
  };
}

export default {
  id: 'tor',
  name: 'Tor Project',
  category: 'network',
  description: 'Checks the official Tor relay list (Onionoo) for relays and exit nodes.',
  homepage: 'https://metrics.torproject.org',
  webUrl: (ip) => `https://metrics.torproject.org/rs.html#search/${ip}`,
  webLabel: 'Open in Tor Metrics',
  key: null,
  freeTier: 'no key needed',
  ipv6: true,

  async lookup(ip, ctx) {
    const search = ctx.info.version === 6 ? `[${ip}]` : ip;
    const { data } = await ctx.fetchJson(`https://onionoo.torproject.org/details?search=${encodeURIComponent(search)}&fields=${FIELDS}`, {
      headers: { Accept: 'application/json' },
      timeoutMs: 20000,
    });
    const result = parseOnionoo(data, ip);
    result.raw = data;
    return result;
  },
};
