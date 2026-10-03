import { LookupError } from '../http.js';
import { formatDate, safeUrl, timeAgo } from '../format.js';

export function parseGreyNoise(status, d) {
  if (status === 404) {
    return {
      verdict: 'none',
      summary: 'Not seen scanning the internet and not a known business service',
      fields: [
        { label: 'Internet scanner', value: 'Not observed' },
        { label: 'Business service (RIOT)', value: 'No' },
      ],
      tags: [],
      lists: [],
      flags: [],
      facts: {},
    };
  }
  if (!d || typeof d !== 'object' || !('noise' in d || 'riot' in d)) {
    throw new LookupError('parse', 'Unexpected response from GreyNoise');
  }

  const classification = String(d.classification || '').toLowerCase();
  const name = d.name && d.name !== 'unknown' ? d.name : '';
  let verdict = 'none';
  let summary = 'No GreyNoise data';

  if (classification === 'malicious') {
    verdict = 'malicious';
    summary = `Malicious internet scanner${name ? ` · ${name}` : ''}`;
  } else if (d.riot) {
    verdict = 'clean';
    summary = `Known benign business service${name ? ` · ${name}` : ''}`;
  } else if (classification === 'benign') {
    verdict = 'clean';
    summary = `Benign scanner${name ? ` · ${name}` : ''}`;
  } else if (classification === 'suspicious') {
    verdict = 'suspicious';
    summary = `Suspicious internet scanner${name ? ` · ${name}` : ''}`;
  } else if (d.noise) {
    verdict = 'suspicious';
    summary = 'Scanning the internet · intent unknown';
  }

  const fields = [
    classification && { label: 'Classification', value: classification[0].toUpperCase() + classification.slice(1) },
    { label: 'Internet scanner', value: d.noise ? 'Yes — seen in the last 90 days' : 'No' },
    { label: 'Business service (RIOT)', value: d.riot ? 'Yes' : 'No' },
    name && { label: 'Actor / owner', value: name },
    d.last_seen && { label: 'Last seen', value: `${formatDate(d.last_seen)} (${timeAgo(d.last_seen)})` },
  ].filter(Boolean);

  const flags = [];
  if (d.noise) flags.push('scanner');
  if (d.riot) flags.push('benign-service');

  return {
    verdict,
    summary,
    fields,
    tags: [d.noise && 'Scanner', d.riot && 'RIOT'].filter(Boolean),
    lists: [],
    flags,
    facts: {},
    link: safeUrl(d.link),
  };
}

export default {
  id: 'greynoise',
  name: 'GreyNoise',
  category: 'reputation',
  description: 'Separates mass internet scanners and benign services from targeted activity.',
  homepage: 'https://www.greynoise.io',
  webUrl: (ip) => `https://viz.greynoise.io/ip/${ip}`,
  webLabel: 'Open GreyNoise Visualizer',
  key: {
    required: false,
    url: 'https://viz.greynoise.io/account/api-key',
    hint: 'Optional: free community account raises the lookup limit',
  },
  freeTier: 'small daily allowance without a key; more with a free community key',
  ipv6: false,

  async lookup(ip, ctx) {
    const headers = { Accept: 'application/json' };
    if (ctx.apiKey) headers.key = ctx.apiKey;
    const { status, data } = await ctx.fetchJson(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
      headers,
      allowStatus: [404],
    });
    const result = parseGreyNoise(status, data);
    result.raw = data;
    return result;
  },
};
