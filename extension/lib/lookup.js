// Runs every enabled source for an IP in parallel and merges the results.

import { PROVIDERS } from './providers/index.js';
import { describeError, fetchJson } from './http.js';

export const VERDICT_RANK = { malicious: 4, suspicious: 3, clean: 2, info: 1, none: 0 };

export const FLAG_LABELS = {
  tor: 'Tor exit',
  'tor-relay': 'Tor relay',
  vpn: 'VPN',
  proxy: 'Proxy',
  abuser: 'Known abuser',
  scanner: 'Internet scanner',
  hosting: 'Hosting / data center',
  anycast: 'Anycast',
  mobile: 'Mobile network',
  crawler: 'Crawler',
  satellite: 'Satellite',
  'benign-service': 'Known benign service',
};

export const FLAG_TONES = {
  tor: 'warn',
  'tor-relay': 'warn',
  vpn: 'warn',
  proxy: 'warn',
  abuser: 'bad',
  scanner: 'warn',
  'benign-service': 'good',
};

/**
 * Start lookups for `info` (from normalizeIp). Calls onUpdate(providerId, state)
 * whenever a source changes state. State is one of:
 *   { status: 'loading' }
 *   { status: 'done', result, cachedAt?, fetchedAt? }
 *   { status: 'error', error }
 *   { status: 'needs-key' } | { status: 'unsupported' }
 * Disabled sources are skipped entirely. Resolves to the final states map.
 */
export async function runLookup(info, options) {
  const { settings, cache = null, providers = PROVIDERS, force = false, onUpdate = () => {}, signal, fetchImpl } = options;
  const states = {};
  const update = (id, state) => {
    if (signal?.aborted) return;
    states[id] = state;
    onUpdate(id, state, states);
  };

  const tasks = [];
  for (const provider of providers) {
    if (settings.enabled?.[provider.id] === false) continue;
    if (info.version === 6 && !provider.ipv6) {
      update(provider.id, { status: 'unsupported' });
      continue;
    }
    const apiKey = String(settings.keys?.[provider.id] || '').trim();
    if (provider.key?.required && !apiKey) {
      update(provider.id, { status: 'needs-key' });
      continue;
    }

    update(provider.id, { status: 'loading' });
    tasks.push(
      (async () => {
        try {
          if (!force && cache) {
            const hit = await cache.get(provider.id, info.ip);
            if (hit) {
              update(provider.id, { status: 'done', result: hit.result, cachedAt: hit.ts });
              return;
            }
          }
          const ctx = {
            info,
            apiKey,
            settings,
            fetchJson: (url, opts = {}) => fetchJson(url, { ...opts, signal, fetchImpl }),
          };
          const result = await provider.lookup(info.ip, ctx);
          if (signal?.aborted) return;
          update(provider.id, { status: 'done', result, fetchedAt: Date.now() });
          if (cache) await cache.set(provider.id, info.ip, result).catch(() => {});
        } catch (err) {
          update(provider.id, { status: 'error', error: describeError(err) });
        }
      })(),
    );
  }
  await Promise.all(tasks);
  return states;
}

function firstFact(states, key, order) {
  for (const id of order) {
    const state = states[id];
    const value = state?.status === 'done' ? state.result?.facts?.[key] : null;
    if (value) return { value, source: id };
  }
  return null;
}

/** Roll individual source results up into an overall picture. */
export function summarize(states, providers = PROVIDERS) {
  const done = providers.filter((p) => states[p.id]?.status === 'done');
  const namesWith = (verdict) => done.filter((p) => states[p.id].result.verdict === verdict).map((p) => p.name);
  const malicious = namesWith('malicious');
  const suspicious = namesWith('suspicious');
  const clean = namesWith('clean');
  const loading = providers.filter((p) => states[p.id]?.status === 'loading').length;
  const reputationSources = done.filter((p) => p.category === 'reputation').length;

  let verdict = 'none';
  if (malicious.length) verdict = 'malicious';
  else if (suspicious.length) verdict = 'suspicious';
  else if (clean.length) verdict = 'clean';

  // Prefer the ASN and organisation from the same source so they agree.
  const asnFact = firstFact(states, 'asn', ['ipinfo', 'ipapi', 'virustotal', 'otx']);
  const orgFromAsnSource = asnFact ? states[asnFact.source].result.facts.org : null;
  const org = orgFromAsnSource
    ? { value: orgFromAsnSource, source: asnFact.source }
    : firstFact(states, 'org', ['rdap', 'abuseipdb', 'ipinfo', 'ipapi', 'virustotal']);

  const country = firstFact(states, 'countryCode', ['ipinfo', 'ipapi', 'otx', 'virustotal', 'abuseipdb', 'rdap']);
  const locationSource = country?.source;
  const fromLocationSource = (key) => (locationSource ? states[locationSource]?.result?.facts?.[key] || null : null);

  const flags = {};
  for (const p of done) {
    for (const flag of states[p.id].result.flags || []) {
      (flags[flag] ||= []).push(p.name);
    }
  }
  // A Tor exit is also a relay; only show the stronger trait.
  if (flags.tor) delete flags['tor-relay'];

  return {
    verdict,
    malicious,
    suspicious,
    clean,
    loading,
    reputationSources,
    facts: {
      countryCode: country?.value || null,
      city: fromLocationSource('city'),
      region: fromLocationSource('region'),
      asn: asnFact?.value || null,
      org: org?.value || null,
      network: firstFact(states, 'network', ['rdap', 'virustotal'])?.value || null,
      hostname: firstFact(states, 'hostname', ['rdns', 'ipinfo', 'shodan', 'abuseipdb'])?.value || null,
      fcrdns: states.rdns?.status === 'done' ? Boolean(states.rdns.result.facts?.fcrdns) : null,
      abuseEmail: firstFact(states, 'abuseEmail', ['rdap', 'ipapi'])?.value || null,
    },
    flags,
  };
}

/** Headline text for the overall verdict. */
export function verdictHeadline(summary) {
  const list = (names) => (names.length > 3 ? `${names.slice(0, 3).join(', ')} +${names.length - 3}` : names.join(', '));
  const s = (n) => (n === 1 ? '' : 's');
  const pending = summary.loading ? ` · ${summary.loading} still checking` : '';
  if (summary.verdict === 'malicious') return { title: 'Malicious', detail: `Flagged by ${list(summary.malicious)}${pending}` };
  if (summary.verdict === 'suspicious') return { title: 'Suspicious', detail: `Reported by ${list(summary.suspicious)}${pending}` };
  const n = summary.reputationSources;
  if (n > 0) return { title: 'No threats reported', detail: `${n} reputation source${s(n)} checked${pending}` };
  if (summary.loading) return { title: 'Checking…', detail: `Waiting on ${summary.loading} source${s(summary.loading)}` };
  return { title: 'No reputation data', detail: 'Add free API keys in Options to enable more sources' };
}
