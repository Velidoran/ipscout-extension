import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fetchJson } from '../../extension/lib/http.js';
import { normalizeIp } from '../../extension/lib/ip.js';
import { normalizeSettings } from '../../extension/lib/storage.js';
import { PROVIDERS, getProvider } from '../../extension/lib/providers/index.js';
import { BENIGN_IP, FLAGGED_IP, createMockFetch } from '../fixtures/responses.js';

function ctxFor(ip, { fetchImpl = createMockFetch(), apiKey = 'test-key', settings = {} } = {}) {
  return {
    info: normalizeIp(ip),
    apiKey,
    settings: normalizeSettings(settings),
    fetchJson: (url, opts = {}) => fetchJson(url, { ...opts, fetchImpl }),
  };
}

const lookup = (id, ip, opts) => getProvider(id).lookup(ip, ctxFor(ip, opts));
const jsonResponse = (body, status = 200) => ({ status, body });
const fieldValue = (result, label) => result.fields.find((f) => f.label === label)?.value;

test('every provider declares the metadata the UI relies on', () => {
  const ids = new Set();
  for (const p of PROVIDERS) {
    assert.ok(p.id && !ids.has(p.id), `unique id for ${p.name}`);
    ids.add(p.id);
    assert.ok(p.name && p.description && p.freeTier, `${p.id} text`);
    assert.ok(['reputation', 'exposure', 'network'].includes(p.category), `${p.id} category`);
    assert.match(p.homepage, /^https:\/\//);
    assert.equal(typeof p.lookup, 'function');
    assert.equal(typeof p.ipv6, 'boolean');
    if (p.webUrl) assert.match(p.webUrl('8.8.8.8'), /^https:\/\//);
    if (p.key) assert.match(p.key.url, /^https:\/\//);
  }
});

/* ----------------------------------------------------------- AbuseIPDB */

test('AbuseIPDB: high confidence score is malicious, with report categories', async () => {
  const fetchImpl = createMockFetch();
  const r = await lookup('abuseipdb', FLAGGED_IP, { fetchImpl, apiKey: 'abc' });
  assert.equal(r.verdict, 'malicious');
  assert.match(r.summary, /Abuse confidence 100%/);
  assert.match(r.summary, /1,532 reports from 312 users/);
  assert.deepEqual(r.flags.sort(), ['hosting', 'tor']);
  const categories = r.lists.find((l) => l.inline);
  assert.deepEqual(
    categories.items.slice(0, 2).map((i) => [i.text, i.count]),
    [
      ['Brute-Force', 2],
      ['SSH', 2],
    ],
  );
  assert.equal(r.lists.find((l) => l.title === 'Recent report comments').items.length, 3); // blank comment skipped
  // Key goes in the "Key" header, never in the URL.
  const [check, reports] = fetchImpl.calls;
  assert.equal(check.init.headers.Key, 'abc');
  assert.ok(!check.url.includes('abc'));
  assert.match(check.url, /\/check\?ipAddress=1\.2\.3\.4&maxAgeInDays=90$/);
  assert.match(reports.url, /\/reports\?/);
});

test('AbuseIPDB: allowlisted IP is clean and skips the reports call', async () => {
  const fetchImpl = createMockFetch();
  const r = await lookup('abuseipdb', BENIGN_IP, { fetchImpl });
  assert.equal(r.verdict, 'clean');
  assert.equal(fetchImpl.calls.length, 1);
  assert.ok(r.tags.includes('Allowlisted'));
});

test('AbuseIPDB: a failing reports call does not hide the main result', async () => {
  const fetchImpl = createMockFetch({
    override: (url) =>
      url.includes('/reports')
        ? jsonResponse({ errors: [{ detail: 'Daily rate limit of 100 requests exceeded', status: 429 }] }, 429)
        : null,
  });
  const r = await lookup('abuseipdb', FLAGGED_IP, { fetchImpl });
  assert.equal(r.verdict, 'malicious');
  assert.equal(r.lists.length, 0);
});

test('AbuseIPDB: respects the report window and the reports toggle', async () => {
  const fetchImpl = createMockFetch();
  await lookup('abuseipdb', FLAGGED_IP, { fetchImpl, settings: { abuseipdbMaxAgeDays: 30, abuseipdbFetchReports: false } });
  assert.equal(fetchImpl.calls.length, 1);
  assert.match(fetchImpl.calls[0].url, /maxAgeInDays=30/);
});

test('AbuseIPDB: rejected key surfaces as an auth error with the API message', async () => {
  const fetchImpl = createMockFetch({
    override: () =>
      jsonResponse(
        { errors: [{ detail: 'Authentication failed. Your API key is either missing, incorrect, or revoked.', status: 401 }] },
        401,
      ),
  });
  await assert.rejects(lookup('abuseipdb', FLAGGED_IP, { fetchImpl }), (err) => {
    assert.equal(err.kind, 'auth');
    assert.match(err.detail, /Authentication failed/);
    return true;
  });
});

/* ---------------------------------------------------------- VirusTotal */

test('VirusTotal: detections drive the verdict and list flagged engines', async () => {
  const fetchImpl = createMockFetch();
  const r = await lookup('virustotal', FLAGGED_IP, { fetchImpl, apiKey: 'vt-key' });
  assert.equal(r.verdict, 'malicious');
  assert.equal(r.summary, '9/94 security vendors flag this IP as malicious · 2 suspicious');
  assert.deepEqual(r.score, { value: 9, max: 94 });
  const flagged = r.lists[0].items.map((i) => i.text);
  assert.deepEqual(flagged, ['Engine A', 'Engine B', 'Engine C']); // malicious before suspicious
  assert.equal(fetchImpl.calls[0].init.headers['x-apikey'], 'vt-key');
  assert.equal(r.facts.asn, 'AS64500');

  const benign = await lookup('virustotal', BENIGN_IP);
  assert.equal(benign.verdict, 'clean');
});

test('VirusTotal: one or two detections are only suspicious; no analysis is no data', async () => {
  const withStats = (stats) => createMockFetch({ override: () => jsonResponse({ data: { attributes: { last_analysis_stats: stats } } }) });
  const one = await lookup('virustotal', FLAGGED_IP, { fetchImpl: withStats({ malicious: 1, harmless: 80, undetected: 10 }) });
  assert.equal(one.verdict, 'suspicious');
  const none = await lookup('virustotal', FLAGGED_IP, { fetchImpl: withStats({}) });
  assert.equal(none.verdict, 'none');
});

test('VirusTotal: quota errors map to rate-limit', async () => {
  const fetchImpl = createMockFetch({
    override: () => jsonResponse({ error: { code: 'QuotaExceededError', message: 'Quota exceeded' } }, 429),
  });
  await assert.rejects(lookup('virustotal', FLAGGED_IP, { fetchImpl }), { kind: 'rate-limit', detail: 'Quota exceeded' });
});

/* ----------------------------------------------------------- GreyNoise */

test('GreyNoise: RIOT is clean, malicious scanner is malicious, 404 is no data', async () => {
  const benign = await lookup('greynoise', BENIGN_IP, { apiKey: '' });
  assert.equal(benign.verdict, 'clean');
  assert.deepEqual(benign.flags, ['benign-service']);
  assert.equal(benign.link, 'https://viz.greynoise.io/riot/8.8.8.8');

  const bad = await lookup('greynoise', FLAGGED_IP);
  assert.equal(bad.verdict, 'malicious');
  assert.deepEqual(bad.flags, ['scanner']);

  const unseen = await lookup('greynoise', '9.9.9.9');
  assert.equal(unseen.verdict, 'none');
});

test('GreyNoise: unknown-intent scanner is suspicious; key header only when set', async () => {
  const fetchImpl = createMockFetch({
    override: () => jsonResponse({ ip: FLAGGED_IP, noise: true, riot: false, classification: 'unknown', name: 'unknown' }),
  });
  const r = await lookup('greynoise', FLAGGED_IP, { fetchImpl, apiKey: '' });
  assert.equal(r.verdict, 'suspicious');
  assert.equal(fetchImpl.calls[0].init.headers.key, undefined);

  const keyed = createMockFetch();
  await lookup('greynoise', BENIGN_IP, { fetchImpl: keyed, apiKey: 'gn' });
  assert.equal(keyed.calls[0].init.headers.key, 'gn');
});

/* ---------------------------------------------------------------- OTX */

test('OTX: allowlisted indicators are clean despite many pulses', async () => {
  const r = await lookup('otx', BENIGN_IP, { apiKey: '' });
  assert.equal(r.verdict, 'clean');
  assert.match(r.summary, /50 threat pulses · allowlisted \(Whitelisted IP\)/);
  assert.equal(r.facts.asn, 'AS15169');
});

test('OTX: pulses without allowlisting are suspicious and list malware families', async () => {
  const fetchImpl = createMockFetch();
  const r = await lookup('otx', FLAGGED_IP, { fetchImpl, apiKey: 'otx-key' });
  assert.equal(r.verdict, 'suspicious');
  assert.deepEqual(fieldValue(r, 'Malware families'), 'Cobalt Strike, Mirai');
  assert.equal(r.lists[0].items[0].text, 'Cobalt Strike C2 sweep (synthetic)'); // newest first
  assert.equal(r.lists[0].more, 2);
  assert.equal(fetchImpl.calls[0].init.headers['X-OTX-API-KEY'], 'otx-key');
});

test('OTX: IPv6 uses the IPv6 indicator path', async () => {
  const fetchImpl = createMockFetch({ override: () => jsonResponse({ pulse_info: { count: 0, pulses: [] }, validation: [] }) });
  const r = await lookup('otx', '2001:4860:4860::8888', { fetchImpl });
  assert.equal(r.verdict, 'none');
  assert.match(fetchImpl.calls[0].url, /\/indicators\/IPv6\/2001%3A4860%3A4860%3A%3A8888\/general$/);
});

/* ----------------------------------------------------------- ThreatFox */

test('ThreatFox: keeps only exact IP matches from the prefix search', async () => {
  const fetchImpl = createMockFetch();
  const r = await lookup('threatfox', FLAGGED_IP, { fetchImpl, apiKey: 'tf-key' });
  assert.equal(r.verdict, 'malicious');
  assert.equal(r.lists[0].items.length, 1);
  assert.match(r.lists[0].items[0].text, /^1\.2\.3\.4:443 — Cobalt Strike$/);
  assert.equal(r.summary, '1 IOC · Cobalt Strike (Botnet C&C)');
  const call = fetchImpl.calls[0];
  assert.equal(call.init.method, 'POST');
  assert.equal(call.init.headers['Auth-Key'], 'tf-key');
  assert.deepEqual(JSON.parse(call.init.body), { query: 'search_ioc', search_term: FLAGGED_IP });
});

test('ThreatFox: no_result is no data; other statuses are errors', async () => {
  assert.equal((await lookup('threatfox', BENIGN_IP)).verdict, 'none');
  const onlyOthers = createMockFetch({
    override: () => jsonResponse({ query_status: 'ok', data: [{ ioc: '1.2.3.45:80', malware_printable: 'X' }] }),
  });
  assert.equal((await lookup('threatfox', FLAGGED_IP, { fetchImpl: onlyOthers })).verdict, 'none');
  const badKey = createMockFetch({ override: () => jsonResponse({ query_status: 'unknown_auth_key' }) });
  await assert.rejects(lookup('threatfox', FLAGGED_IP, { fetchImpl: badKey }), { kind: 'auth' });
  const odd = createMockFetch({ override: () => jsonResponse({ query_status: 'illegal_search_term' }) });
  await assert.rejects(lookup('threatfox', FLAGGED_IP, { fetchImpl: odd }), { kind: 'http', message: 'ThreatFox: illegal_search_term' });
});

/* -------------------------------------------------- Shodan InternetDB */

test('InternetDB: sorted ports, CVE list and 404 handling', async () => {
  const r = await lookup('shodan', FLAGGED_IP, { apiKey: '' });
  assert.equal(r.verdict, 'info');
  assert.equal(fieldValue(r, 'Open ports'), '22, 80, 443, 8080');
  assert.equal(r.summary, '4 open ports: 22, 80, 443, 8080 · 2 known CVEs');
  assert.deepEqual(
    r.lists[0].items.map((i) => i.text),
    ['CVE-2023-38408', 'CVE-2021-41617'],
  );
  assert.deepEqual(r.flags, ['hosting']); // "cloud" tag

  const none = await lookup('shodan', '9.9.9.9');
  assert.equal(none.verdict, 'none');
});

test('InternetDB: C2 tags are malicious', async () => {
  const fetchImpl = createMockFetch({
    override: () => jsonResponse({ ip: FLAGGED_IP, ports: [443], tags: ['c2'], vulns: [], cpes: [], hostnames: [] }),
  });
  assert.equal((await lookup('shodan', FLAGGED_IP, { fetchImpl })).verdict, 'malicious');
});

/* ------------------------------------------------------------- IPinfo */

test('IPinfo: location and organisation facts; token sent as a bearer header', async () => {
  const anonymous = createMockFetch();
  const r = await lookup('ipinfo', BENIGN_IP, { fetchImpl: anonymous, apiKey: '' });
  assert.equal(r.verdict, 'info');
  assert.deepEqual(
    { asn: r.facts.asn, org: r.facts.org, city: r.facts.city, countryCode: r.facts.countryCode, hostname: r.facts.hostname },
    { asn: 'AS15169', org: 'Google LLC', city: 'Mountain View', countryCode: 'US', hostname: 'dns.google' },
  );
  assert.deepEqual(r.flags, ['anycast']);
  assert.equal(anonymous.calls[0].init.headers.Authorization, undefined);

  const keyed = createMockFetch();
  await lookup('ipinfo', BENIGN_IP, { fetchImpl: keyed, apiKey: 'tok' });
  assert.equal(keyed.calls[0].init.headers.Authorization, 'Bearer tok');
});

test('IPinfo: bogon responses are handled', async () => {
  const fetchImpl = createMockFetch({ override: () => jsonResponse({ ip: '10.0.0.1', bogon: true }) });
  const r = await lookup('ipinfo', '10.0.0.1', { fetchImpl });
  assert.equal(r.summary, 'Bogon (reserved) address');
});

/* ----------------------------------------------------------- ipapi.is */

test('ipapi.is: anonymiser flags map to canonical traits', async () => {
  const r = await lookup('ipapi', FLAGGED_IP, { apiKey: '' });
  assert.equal(r.verdict, 'suspicious'); // is_abuser
  assert.deepEqual(r.flags, ['vpn', 'tor', 'hosting', 'abuser']);
  assert.equal(r.facts.abuseEmail, 'abuse@example.net');

  const benign = await lookup('ipapi', BENIGN_IP);
  assert.equal(benign.verdict, 'info');
  assert.deepEqual(benign.flags, ['hosting']);
});

test('ipapi.is: quota errors in a 200 body become rate-limit errors', async () => {
  const fetchImpl = createMockFetch({ override: () => jsonResponse({ error: 'Daily request limit reached. Please upgrade.' }) });
  await assert.rejects(lookup('ipapi', FLAGGED_IP, { fetchImpl }), { kind: 'rate-limit' });
});

/* --------------------------------------------------------------- RDAP */

test('RDAP: registrant, nested abuse contact, registry and range', async () => {
  const r = await lookup('rdap', BENIGN_IP);
  assert.equal(r.summary, 'GOGL · 8.8.8.0/24 · Google LLC');
  assert.equal(fieldValue(r, 'Abuse contact'), 'network-abuse@google.com');
  assert.equal(fieldValue(r, 'Abuse phone'), '+1-650-253-0000');
  assert.equal(fieldValue(r, 'Registry'), 'ARIN');
  assert.equal(fieldValue(r, 'Origin AS'), 'AS15169');
  assert.equal(fieldValue(r, 'Registered'), '2023-12-28');

  const apnic = await lookup('rdap', FLAGGED_IP);
  assert.equal(fieldValue(apnic, 'Registry'), 'APNIC');
  assert.equal(apnic.facts.abuseEmail, 'abuse@example.net');
  assert.equal(apnic.facts.registrant, 'Example Hosting Pty Ltd');

  const missing = await lookup('rdap', '9.9.9.9');
  assert.equal(missing.verdict, 'none');
});

/* ---------------------------------------------------------- Reverse DNS */

test('Reverse DNS: PTR with forward confirmation', async () => {
  const r = await lookup('rdns', BENIGN_IP);
  assert.equal(r.summary, 'dns.google · forward-confirmed');
  assert.equal(r.facts.fcrdns, true);

  const none = await lookup('rdns', FLAGGED_IP);
  assert.equal(none.summary, 'No PTR record (NXDOMAIN)');
});

test('Reverse DNS: hostname that does not resolve back is reported', async () => {
  const fetchImpl = createMockFetch({
    override: (url) => {
      const u = new URL(url);
      if (u.searchParams.get('type') === 'PTR') return jsonResponse({ Status: 0, Answer: [{ type: 12, data: 'spoofed.example.' }] });
      return jsonResponse({ Status: 0, Answer: [{ type: 1, data: '203.0.113.99' }] });
    },
  });
  const r = await lookup('rdns', FLAGGED_IP, { fetchImpl });
  assert.equal(r.facts.fcrdns, false);
  assert.match(fieldValue(r, 'Forward-confirmed'), /^No/);
});

test('Reverse DNS: falls back to Cloudflare when Google is unreachable', async () => {
  const fetchImpl = createMockFetch({
    override: (url) => (url.startsWith('https://dns.google/') ? jsonResponse({}, 503) : null),
  });
  const r = await lookup('rdns', BENIGN_IP, { fetchImpl });
  assert.equal(r.summary, 'dns.google · forward-confirmed');
  assert.ok(fetchImpl.calls.some((c) => c.url.startsWith('https://cloudflare-dns.com/')));
});

/* --------------------------------------------------------------- Tor */

test('Tor: exact exit match, ignoring relays on look-alike IPs', async () => {
  const r = await lookup('tor', FLAGGED_IP);
  assert.equal(r.summary, 'Tor exit node · ExampleExit1');
  assert.deepEqual(r.flags, ['tor']);
  assert.equal(fieldValue(r, 'Relays on this IP'), '1');

  const clean = await lookup('tor', BENIGN_IP);
  assert.equal(clean.verdict, 'none');
  assert.equal(clean.summary, 'Not a Tor relay or exit node');
});

test('Tor: IPv6 search is bracketed and relay-only IPs are not exits', async () => {
  const fetchImpl = createMockFetch({
    override: () =>
      jsonResponse({
        relays: [
          {
            nickname: 'V6Relay',
            fingerprint: 'AB',
            or_addresses: ['[2001:db8:1::5]:9001'],
            exit_addresses: [],
            flags: ['Fast'],
            running: true,
          },
        ],
      }),
  });
  const r = await lookup('tor', '2001:db8:1::5', { fetchImpl });
  assert.match(decodeURIComponent(fetchImpl.calls[0].url), /search=\[2001:db8:1::5\]/);
  assert.deepEqual(r.flags, ['tor-relay']);
  assert.match(r.summary, /^Tor relay \(non-exit\)/);
});
