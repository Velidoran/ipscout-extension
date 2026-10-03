// Plain-text and JSON exports of a lookup, for tickets, chat and notes.

import { PROVIDERS } from './providers/index.js';
import { FLAG_LABELS, summarize, verdictHeadline } from './lookup.js';
import { countryName, formatDateTime, joinParts } from './format.js';
import { defang as defangIp } from './ip.js';

const STATUS_TEXT = {
  'needs-key': 'not checked (needs a free API key)',
  unsupported: 'not checked (IPv4 only)',
  loading: 'still loading',
};

function webLink(provider, state, ip) {
  return state?.result?.link || (provider.webUrl ? provider.webUrl(ip) : null);
}

export function buildTextReport({ info, states, providers = PROVIDERS, defang = false, now = Date.now() }) {
  const ip = info.ip;
  const summary = summarize(states, providers);
  const headline = verdictHeadline(summary);
  const f = summary.facts;
  const lines = [];

  lines.push(`ipScout report: ${ip} (IPv${info.version})`);
  lines.push(`Generated ${formatDateTime(now)}`);
  lines.push('');
  lines.push(`Verdict: ${headline.title} — ${headline.detail}`);
  const place = joinParts([f.city, f.region, countryName(f.countryCode)]);
  if (place) lines.push(`Location: ${place}`);
  const network = joinParts([joinParts([f.asn, f.org], ' '), f.network], ' · ');
  if (network) lines.push(`Network: ${network}`);
  if (f.hostname) lines.push(`Hostname: ${f.hostname}${f.fcrdns ? ' (forward-confirmed)' : ''}`);
  if (f.abuseEmail) lines.push(`Abuse contact: ${f.abuseEmail}`);
  const traits = Object.keys(summary.flags).map((k) => FLAG_LABELS[k] || k);
  if (traits.length) lines.push(`Traits: ${traits.join(', ')}`);

  lines.push('');
  lines.push('Sources');
  for (const p of providers) {
    const state = states[p.id];
    if (!state) continue;
    let text;
    if (state.status === 'done') text = `[${state.result.verdict}] ${state.result.summary}`;
    else if (state.status === 'error') text = `[error] ${state.error.message}`;
    else text = STATUS_TEXT[state.status] || state.status;
    lines.push(`- ${p.name}: ${text}`);
    const link = state.status === 'done' ? webLink(p, state, ip) : null;
    if (link) lines.push(`  ${link}`);
  }

  let out = lines.join('\n');
  if (defang)
    out = out
      .split(ip)
      .join(defangIp(ip))
      .replace(/https?:\/\//g, (m) => m.replace('http', 'hxxp'));
  return out;
}

export function buildJsonReport({ info, scope, states, providers = PROVIDERS, now = Date.now() }) {
  const summary = summarize(states, providers);
  const sources = {};
  for (const p of providers) {
    const state = states[p.id];
    if (!state) continue;
    const entry = { name: p.name, status: state.status };
    if (state.status === 'done') {
      const { raw, ...result } = state.result;
      Object.assign(entry, result, { link: webLink(p, state, info.ip) });
      if (state.cachedAt) entry.cachedAt = new Date(state.cachedAt).toISOString();
    } else if (state.status === 'error') {
      entry.error = state.error;
    }
    sources[p.id] = entry;
  }
  return JSON.stringify(
    {
      ip: info.ip,
      version: info.version,
      scope: scope?.label,
      generatedAt: new Date(now).toISOString(),
      verdict: summary.verdict,
      headline: verdictHeadline(summary),
      facts: summary.facts,
      traits: Object.keys(summary.flags),
      sources,
    },
    null,
    2,
  );
}
