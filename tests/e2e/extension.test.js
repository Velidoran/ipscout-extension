// End-to-end tests: the real extension in Chromium, with every API mocked.
// Run with: npm run test:e2e   (needs `npx playwright install chromium` locally)

import { after, before, beforeEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { launchExtension } from './harness.js';

let ext;
let pageErrors;

before(async () => {
  ext = await launchExtension();
});

after(async () => {
  await ext?.close();
});

beforeEach(async () => {
  pageErrors = [];
  await withExtensionPage((page) => page.evaluate(() => chrome.storage.local.clear()));
});

async function withExtensionPage(fn, file = 'options.html') {
  const page = await ext.context.newPage();
  try {
    await page.goto(ext.url(file));
    return await fn(page);
  } finally {
    await page.close();
  }
}

async function openPage(file, { width = 1280 } = {}) {
  const page = await ext.context.newPage();
  page.on('pageerror', (e) => pageErrors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && pageErrors.push(m.text()));
  await page.setViewportSize({ width, height: 900 });
  await page.goto(ext.url(file));
  return page;
}

async function settled(page) {
  await page.waitForFunction(() => document.querySelector('.results') && !document.querySelector('#content .spinner'));
}

const setSettings = (settings) => withExtensionPage((page) => page.evaluate((s) => chrome.storage.local.set({ settings: s }), settings));
const hostsSince = (start) => new Set(ext.requests.slice(start).map((r) => new URL(r.url).hostname));

test('installing opens the welcome page and registers the service worker', async () => {
  const deadline = Date.now() + 5000;
  while (!ext.context.pages().some((p) => p.url().endsWith('options.html?welcome=1')) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const welcome = ext.context.pages().find((p) => p.url().endsWith('options.html?welcome=1'));
  assert.ok(welcome, 'welcome page opened on install');
  await welcome.waitForSelector('#welcome:not([hidden])');
  assert.match(await welcome.locator('#welcome').textContent(), /8 sources are ready to go/);
  assert.equal(await ext.worker.evaluate(() => typeof chrome.omnibox.onInputEntered), 'object');
});

test('benign IP: keyless sources report and the overview says no threats', async () => {
  const start = ext.requests.length;
  const page = await openPage('results.html?q=8.8.8.8');
  await settled(page);

  assert.equal(await page.locator('.verdict-title').textContent(), 'No threats reported');
  assert.equal(await page.title(), '8.8.8.8 · ipScout');
  for (const id of ['greynoise', 'otx', 'shodan', 'ipinfo', 'ipapi', 'rdap', 'rdns', 'tor']) {
    assert.equal(await page.locator(`details.source[data-provider="${id}"]`).count(), 1, `${id} card`);
  }
  assert.match(await page.locator('.notice').first().textContent(), /AbuseIPDB, VirusTotal, ThreatFox need a free API key/);
  assert.match(await page.locator('.facts').textContent(), /Mountain View, California, United States/);
  assert.match(await page.locator('.traits').textContent(), /Known benign service/);

  const hosts = hostsSince(start);
  for (const host of ['api.abuseipdb.com', 'www.virustotal.com', 'threatfox-api.abuse.ch'])
    assert.ok(!hosts.has(host), `${host} contacted without a key`);
  assert.deepEqual(pageErrors, []);
  await page.close();
});

test('flagged IP: all sources run with keys, sent in the right headers', async () => {
  await setSettings({ keys: { abuseipdb: 'abuse-key', virustotal: 'vt-key', threatfox: 'tf-key' } });
  const start = ext.requests.length;
  const page = await openPage('results.html?q=1.2.3.4');
  await settled(page);

  assert.equal(await page.locator('.verdict-title').textContent(), 'Malicious');
  assert.match(await page.locator('.traits').textContent(), /Tor exit/);
  assert.equal(await page.locator('details.source').count(), 11);
  assert.match(await page.locator('[data-provider="threatfox"] .source-summary').textContent(), /1 IOC · Cobalt Strike \(Botnet C&C\)/);
  assert.equal(await page.locator('.notice').count(), 0);

  const sent = ext.requests.slice(start);
  const header = (host, name) => sent.find((r) => new URL(r.url).hostname === host)?.headers[name];
  assert.equal(header('api.abuseipdb.com', 'key'), 'abuse-key');
  assert.equal(header('www.virustotal.com', 'x-apikey'), 'vt-key');
  assert.equal(header('threatfox-api.abuse.ch', 'auth-key'), 'tf-key');
  assert.ok(
    sent.every((r) => !r.headers.cookie),
    'no cookies are sent',
  );
  assert.deepEqual(pageErrors, []);
  await page.close();
});

test('private addresses are never sent to any service', async () => {
  const start = ext.requests.length;
  const page = await openPage('popup.html?q=10.0.0.5', { width: 480 });
  await page.waitForSelector('.scope-note');
  assert.match(await page.locator('.scope-note').textContent(), /Private network — RFC 1918, 10\.0\.0\.0\/8/);
  await page.waitForTimeout(300);
  assert.equal(ext.requests.length, start);
  await page.close();
});

test('hostnames (even defanged URLs) are resolved over DNS-over-HTTPS first', async () => {
  const page = await openPage(`popup.html?q=${encodeURIComponent('hxxps://example[.]org/login')}`, { width: 480 });
  await settled(page);
  assert.equal(await page.locator('.result-ip').textContent(), '1.2.3.4');
  assert.match(await page.locator('.resolved-from').first().textContent(), /example\.org resolves to 1 address/);
  assert.equal(await page.inputValue('#q'), 'example.org');
  await page.close();
});

test('results are cached, and Refresh bypasses the cache', async () => {
  const first = await openPage('results.html?q=8.8.8.8');
  await settled(first);
  await first.close();

  const start = ext.requests.length;
  const second = await openPage('results.html?q=8.8.8.8');
  await settled(second);
  assert.equal(ext.requests.length, start, 'second lookup served from cache');
  assert.match(await second.locator('[data-provider="ipinfo"] .source-meta').textContent(), /cached/);

  await second.getByRole('button', { name: 'Refresh (skip cache)' }).click();
  await settled(second);
  assert.ok(ext.requests.length > start, 'refresh fetched again');
  await second.close();
});

test('switching a source off in Options stops it being queried', async () => {
  const options = await openPage('options.html');
  await options.getByRole('checkbox', { name: 'Use Tor Project' }).uncheck();
  await options.waitForFunction(async () => (await chrome.storage.local.get('settings')).settings?.enabled?.tor === false);
  await options.close();

  const start = ext.requests.length;
  const page = await openPage('results.html?q=8.8.8.8');
  await settled(page);
  assert.equal(await page.locator('[data-provider="tor"]').count(), 0);
  assert.ok(!hostsSince(start).has('onionoo.torproject.org'));
  await page.close();
});

test('pasting a log line looks up the first IP and offers the others', async () => {
  const page = await openPage('results.html');
  await page.fill('#q', 'DROP IN=eth0 SRC=8.8.8.8 DST=1.2.3.4 PROTO=TCP');
  await page.press('#q', 'Enter');
  await settled(page);
  assert.equal(await page.locator('.result-ip').textContent(), '8.8.8.8');
  assert.match(page.url(), /\?q=8\.8\.8\.8$/);

  await page.locator('.resolved-from .chip', { hasText: '1.2.3.4' }).click();
  await settled(page);
  assert.equal(await page.locator('.result-ip').textContent(), '1.2.3.4');
  assert.match(page.url(), /\?q=1\.2\.3\.4$/);

  await page.goBack();
  await settled(page);
  assert.equal(await page.locator('.result-ip').textContent(), '8.8.8.8');
  await page.close();
});

test('popup home lists recent lookups with their verdicts', async () => {
  const lookupPage = await openPage('results.html?q=8.8.8.8');
  await settled(lookupPage);
  await lookupPage.close();

  const popup = await openPage('popup.html', { width: 480 });
  await popup.waitForSelector('.home .chip');
  const chip = popup.locator('.home .chip', { hasText: '8.8.8.8' });
  assert.equal(await chip.count(), 1);
  await chip.click();
  await settled(popup);
  assert.equal(await popup.locator('.result-ip').textContent(), '8.8.8.8');
  await popup.close();
});
