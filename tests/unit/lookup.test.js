import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runLookup, summarize, verdictHeadline } from '../../extension/lib/lookup.js';
import { normalizeIp } from '../../extension/lib/ip.js';
import { createCache, normalizeSettings } from '../../extension/lib/storage.js';
import { PROVIDERS } from '../../extension/lib/providers/index.js';
import { BENIGN_IP, FLAGGED_IP, createMockFetch } from '../fixtures/responses.js';
import { createMemoryArea } from '../fixtures/memory-storage.js';

const ALL_KEYS = { abuseipdb: 'a', virustotal: 'v', threatfox: 't' };
const settingsWith = (overrides = {}) => normalizeSettings(overrides);

async function lookup(ip, { settings = settingsWith(), fetchImpl = createMockFetch(), ...rest } = {}) {
  const events = [];
  const states = await runLookup(normalizeIp(ip), { settings, fetchImpl, onUpdate: (id, s) => events.push([id, s.status]), ...rest });
  return { states, events, fetchImpl };
}

test('without keys, key-only sources are skipped and never contacted', async () => {
  const { states, fetchImpl } = await lookup(BENIGN_IP);
  for (const id of ['abuseipdb', 'virustotal', 'threatfox']) assert.equal(states[id].status, 'needs-key', id);
  for (const id of ['greynoise', 'otx', 'shodan', 'ipinfo', 'ipapi', 'rdap', 'rdns', 'tor']) assert.equal(states[id].status, 'done', id);
  const hosts = new Set(fetchImpl.calls.map((c) => new URL(c.url).hostname));
  for (const host of ['api.abuseipdb.com', 'www.virustotal.com', 'threatfox-api.abuse.ch']) assert.ok(!hosts.has(host), host);
});

test('every source goes loading -> done, and the roll-up flags the IP', async () => {
  const { states, events } = await lookup(FLAGGED_IP, { settings: settingsWith({ keys: ALL_KEYS }) });
  assert.equal(Object.keys(states).length, PROVIDERS.length);
  for (const p of PROVIDERS) {
    const seq = events.filter(([id]) => id === p.id).map(([, s]) => s);
    assert.deepEqual(seq, ['loading', 'done'], p.id);
  }
  const s = summarize(states);
  assert.equal(s.verdict, 'malicious');
  assert.deepEqual(s.malicious, ['AbuseIPDB', 'VirusTotal', 'GreyNoise', 'ThreatFox']);
  assert.deepEqual(s.suspicious, ['AlienVault OTX', 'ipapi.is']);
  assert.deepEqual(Object.keys(s.flags).sort(), ['abuser', 'hosting', 'scanner', 'tor', 'vpn']);
  assert.deepEqual(s.flags.tor.sort(), ['AbuseIPDB', 'Tor Project', 'ipapi.is']);
  assert.deepEqual(verdictHeadline(s), { title: 'Malicious', detail: 'Flagged by AbuseIPDB, VirusTotal, GreyNoise +1' });
});

test('summary facts prefer the most specific source', async () => {
  const { states } = await lookup(BENIGN_IP, { settings: settingsWith({ keys: ALL_KEYS }) });
  const s = summarize(states);
  assert.equal(s.verdict, 'clean');
  assert.deepEqual(s.facts, {
    countryCode: 'US',
    city: 'Mountain View',
    region: 'California',
    asn: 'AS15169',
    org: 'Google LLC',
    network: '8.8.8.0/24',
    hostname: 'dns.google',
    fcrdns: true,
    abuseEmail: 'network-abuse@google.com',
  });
  assert.deepEqual(verdictHeadline(s), { title: 'No threats reported', detail: '5 reputation sources checked' });
});

test('disabled sources are skipped entirely', async () => {
  const { states, fetchImpl } = await lookup(BENIGN_IP, { settings: settingsWith({ enabled: { otx: false, tor: false } }) });
  assert.equal(states.otx, undefined);
  assert.equal(states.tor, undefined);
  assert.ok(!fetchImpl.calls.some((c) => c.url.includes('alienvault') || c.url.includes('onionoo')));
});

test('IPv4-only sources are marked unsupported for IPv6', async () => {
  const { states } = await lookup('2001:4860:4860::8888');
  assert.equal(states.greynoise.status, 'unsupported');
  assert.equal(states.shodan.status, 'unsupported');
});

test('one failing source does not affect the others', async () => {
  const fetchImpl = createMockFetch({ override: (url) => (url.includes('ipinfo.io') ? { status: 503, body: {} } : null) });
  const { states } = await lookup(BENIGN_IP, { fetchImpl });
  assert.equal(states.ipinfo.status, 'error');
  assert.equal(states.ipinfo.error.kind, 'server');
  assert.equal(states.ipapi.status, 'done');
  // Location then comes from the next source in line.
  assert.equal(summarize(states).facts.city, 'Mountain View');
});

test('cached results are reused until they expire, and force bypasses them', async () => {
  const area = createMemoryArea();
  let clock = 1_000_000;
  const cache = createCache({ area, ttlMs: 60_000, now: () => clock });

  const first = await lookup(BENIGN_IP, { cache });
  assert.ok(first.fetchImpl.calls.length > 0);
  assert.ok([...area.data.keys()].some((k) => k === 'cache:greynoise:8.8.8.8'));
  assert.equal(area.data.get('cache:greynoise:8.8.8.8').result.raw, undefined, 'raw payloads are not cached');

  clock += 30_000;
  const second = await lookup(BENIGN_IP, { cache });
  assert.equal(second.fetchImpl.calls.length, 0);
  assert.equal(second.states.greynoise.cachedAt, 1_000_000);

  const forced = await lookup(BENIGN_IP, { cache, force: true });
  assert.ok(forced.fetchImpl.calls.length > 0);

  clock += 120_000;
  const expired = await lookup(BENIGN_IP, { cache });
  assert.ok(expired.fetchImpl.calls.length > 0);
});

test('aborting stops further updates', async () => {
  const controller = new AbortController();
  const slowFetch = (url, init) =>
    new Promise((resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
    });
  const events = [];
  const running = runLookup(normalizeIp(BENIGN_IP), {
    settings: settingsWith(),
    fetchImpl: slowFetch,
    signal: controller.signal,
    onUpdate: (id, s) => events.push([id, s.status]),
  });
  const before = events.length;
  controller.abort();
  await running;
  assert.ok(before > 0);
  assert.equal(events.length, before, 'no updates after abort');
});

test('a Tor exit hides the weaker "Tor relay" trait', () => {
  const done = (flags, verdict = 'info') => ({ status: 'done', result: { verdict, summary: '', fields: [], flags, facts: {} } });
  const s = summarize({ tor: done(['tor']), ipapi: done(['tor-relay']) });
  assert.deepEqual(Object.keys(s.flags), ['tor']);
});

test('headline covers loading and empty states', () => {
  assert.deepEqual(verdictHeadline({ verdict: 'none', loading: 3, reputationSources: 0, malicious: [], suspicious: [], clean: [] }), {
    title: 'Checking…',
    detail: 'Waiting on 3 sources',
  });
  assert.equal(
    verdictHeadline({ verdict: 'none', loading: 0, reputationSources: 0, malicious: [], suspicious: [], clean: [] }).title,
    'No reputation data',
  );
  assert.deepEqual(
    verdictHeadline({ verdict: 'suspicious', loading: 2, reputationSources: 1, malicious: [], suspicious: ['OTX'], clean: [] }),
    {
      title: 'Suspicious',
      detail: 'Reported by OTX · 2 still checking',
    },
  );
});
