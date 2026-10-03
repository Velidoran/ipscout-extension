import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_SETTINGS,
  HISTORY_MAX,
  clearHistory,
  createCache,
  getHistory,
  getSettings,
  isProviderEnabled,
  normalizeSettings,
  recordHistory,
  saveSettings,
} from '../../extension/lib/storage.js';
import { buildJsonReport, buildTextReport } from '../../extension/lib/report.js';
import { runLookup } from '../../extension/lib/lookup.js';
import { fetchJson } from '../../extension/lib/http.js';
import { classifyIp, normalizeIp } from '../../extension/lib/ip.js';
import { FLAGGED_IP, createMockFetch } from '../fixtures/responses.js';
import { createMemoryArea } from '../fixtures/memory-storage.js';

/* ------------------------------------------------------------ settings */

test('settings default sensibly and round-trip through storage', async () => {
  const area = createMemoryArea();
  assert.deepEqual(await getSettings(area), DEFAULT_SETTINGS);
  await saveSettings({ keys: { virustotal: 'k' }, enabled: { tor: false }, cacheTtlMinutes: 60 }, area);
  const s = await getSettings(area);
  assert.equal(s.keys.virustotal, 'k');
  assert.equal(s.cacheTtlMinutes, 60);
  assert.equal(s.abuseipdbMaxAgeDays, 90);
  assert.equal(isProviderEnabled(s, 'tor'), false);
  assert.equal(isProviderEnabled(s, 'otx'), true);
  assert.deepEqual(normalizeSettings(null).keys, {});
});

/* ------------------------------------------------------------- history */

test('history keeps the newest entry per IP and is capped', async () => {
  const area = createMemoryArea();
  await recordHistory({ ip: '1.1.1.1', ts: 1 }, area);
  await recordHistory({ ip: '8.8.8.8', ts: 2 }, area);
  await recordHistory({ ip: '1.1.1.1', ts: 3, verdict: 'clean' }, area);
  let list = await getHistory(area);
  assert.deepEqual(
    list.map((e) => e.ip),
    ['1.1.1.1', '8.8.8.8'],
  );
  assert.equal(list[0].verdict, 'clean');
  await recordHistory({ ip: '1.1.1.1', ts: 4 }, area); // verdict survives a later update without one
  assert.equal((await getHistory(area))[0].verdict, 'clean');

  for (let i = 0; i < HISTORY_MAX + 10; i++) await recordHistory({ ip: `9.9.9.${i}`, ts: 10 + i }, area);
  list = await getHistory(area);
  assert.equal(list.length, HISTORY_MAX);
  assert.equal(list[0].ip, `9.9.9.${HISTORY_MAX + 9}`);
  await clearHistory(area);
  assert.deepEqual(await getHistory(area), []);
});

/* --------------------------------------------------------------- cache */

test('cache prune drops expired entries and caps the rest; maybePrune is rate limited', async () => {
  let clock = 10_000;
  const area = createMemoryArea({ settings: { keys: { a: 'b' } } });
  const cache = createCache({ area, ttlMs: 1000, now: () => clock });
  for (let i = 0; i < 5; i++) {
    await cache.set('p', `1.1.1.${i}`, { verdict: 'info', raw: { big: true } });
    clock += 10;
  }
  clock += 2000;
  await cache.set('p', '2.2.2.2', { verdict: 'info' });
  clock += 10;
  await cache.set('p', '3.3.3.3', { verdict: 'info' }); // newest, so it survives the cap
  assert.equal(await cache.prune(1), 6); // 5 expired + 1 over the cap
  const remaining = Object.keys(await area.get(null)).filter((k) => k.startsWith('cache:'));
  assert.deepEqual(remaining, ['cache:p:3.3.3.3']);
  assert.ok((await area.get('settings')).settings, 'non-cache keys are untouched');

  assert.equal(await cache.maybePrune({ intervalMs: 5000 }), 0); // nothing stale, but it ran
  clock += 3000;
  await cache.set('p', '4.4.4.4', { verdict: 'info' });
  clock += 1500;
  assert.equal(await cache.maybePrune({ intervalMs: 5000 }), 0, 'skipped: ran less than 5s ago');
  clock += 5000;
  assert.ok((await cache.maybePrune({ intervalMs: 5000 })) >= 1);

  assert.equal(await createCache({ area, ttlMs: 0 }).get('p', '3.3.3.3'), null, 'ttl 0 disables caching');
  assert.ok((await cache.clear()) >= 0);
});

/* ------------------------------------------------------------- reports */

async function flaggedStates() {
  const settings = normalizeSettings({ keys: { abuseipdb: 'a', threatfox: 't' } }); // VirusTotal left without a key
  const fetchImpl = createMockFetch({
    override: (url) => (url.includes('greynoise') ? { status: 429, body: { message: 'Daily limit reached' } } : null),
  });
  return runLookup(normalizeIp(FLAGGED_IP), { settings, fetchImpl });
}

test('text report summarises verdict, facts and every source', async () => {
  const info = normalizeIp(FLAGGED_IP);
  const states = await flaggedStates();
  const text = buildTextReport({ info, states, now: Date.UTC(2026, 9, 3, 12, 0) });
  assert.match(text, /^ipScout report: 1\.2\.3\.4 \(IPv4\)\nGenerated 2026-10-03 12:00 UTC/);
  assert.match(text, /Verdict: Malicious — Flagged by AbuseIPDB, ThreatFox/);
  assert.match(text, /Location: Brisbane, Queensland, Australia/);
  assert.match(text, /Network: AS64500 Example Hosting Pty Ltd · 1\.2\.3\.0\/24/);
  assert.match(text, /Traits: .*Tor exit/);
  assert.match(text, /- VirusTotal: not checked \(needs a free API key\)/);
  assert.match(text, /- GreyNoise: \[error\] Free-tier rate limit reached/);
  assert.match(text, /- ThreatFox: \[malicious\] 1 IOC · Cobalt Strike/);
  assert.match(text, /\n {2}https:\/\/www\.abuseipdb\.com\/check\/1\.2\.3\.4\n/);
});

test('defanged text report contains no live IPs or links', async () => {
  const info = normalizeIp(FLAGGED_IP);
  const text = buildTextReport({ info, states: await flaggedStates(), defang: true });
  assert.ok(!text.includes('1.2.3.4'));
  assert.ok(!/https?:\/\//.test(text));
  assert.match(text, /1\[\.\]2\[\.\]3\[\.\]4/);
  assert.match(text, /hxxps:\/\/www\.abuseipdb\.com/);
});

test('JSON report is valid and excludes raw payloads', async () => {
  const info = normalizeIp(FLAGGED_IP);
  const states = await flaggedStates();
  const report = JSON.parse(buildJsonReport({ info, scope: classifyIp(info), states }));
  assert.equal(report.ip, FLAGGED_IP);
  assert.equal(report.verdict, 'malicious');
  assert.equal(report.sources.virustotal.status, 'needs-key');
  assert.equal(report.sources.greynoise.error.kind, 'rate-limit');
  assert.equal(report.sources.threatfox.verdict, 'malicious');
  assert.equal(report.sources.threatfox.raw, undefined);
  assert.match(report.sources.abuseipdb.link, /abuseipdb\.com\/check/);
});

/* ---------------------------------------------------------------- http */

const respond =
  (body, status = 200, raw = false) =>
  async () =>
    new Response(raw ? body : JSON.stringify(body), { status });

test('fetchJson parses JSON, omits credentials and maps HTTP errors', async () => {
  let seenInit;
  const ok = await fetchJson('https://example.test/a', {
    fetchImpl: async (url, init) => {
      seenInit = init;
      return new Response('{"x":1}', { status: 200 });
    },
  });
  assert.deepEqual(ok.data, { x: 1 });
  assert.equal(seenInit.credentials, 'omit');
  assert.equal(seenInit.referrerPolicy, 'no-referrer');

  const allowed = await fetchJson('https://example.test/a', { fetchImpl: respond({ detail: 'none' }, 404), allowStatus: [404] });
  assert.equal(allowed.status, 404);

  const cases = [
    [401, 'auth'],
    [403, 'auth'],
    [404, 'not-found'],
    [429, 'rate-limit'],
    [502, 'server'],
    [418, 'http'],
  ];
  for (const [status, kind] of cases) {
    await assert.rejects(fetchJson('https://example.test/a', { fetchImpl: respond({ message: `m${status}` }, status) }), (err) => {
      assert.equal(err.kind, kind, `status ${status}`);
      assert.equal(err.detail, `m${status}`);
      return true;
    });
  }
  await assert.rejects(fetchJson('https://example.test/a', { fetchImpl: respond('<html>oops</html>', 200, true) }), { kind: 'parse' });
});

test('fetchJson distinguishes network failures, timeouts and cancellation', async () => {
  await assert.rejects(
    fetchJson('https://example.test/a', {
      fetchImpl: async () => {
        throw new TypeError('Failed to fetch');
      },
    }),
    { kind: 'network' },
  );

  const hang = (url, init) =>
    new Promise((_, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));
  await assert.rejects(fetchJson('https://example.test/a', { fetchImpl: hang, timeoutMs: 20 }), { kind: 'timeout' });

  const controller = new AbortController();
  const pending = fetchJson('https://example.test/a', { fetchImpl: hang, signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, { kind: 'aborted' });
});
