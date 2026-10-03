import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runLookup } from '../../extension/lib/lookup.js';
import { normalizeIp } from '../../extension/lib/ip.js';
import { normalizeSettings } from '../../extension/lib/storage.js';
import { QUICK_LINKS } from '../../extension/lib/quicklinks.js';
import { BENIGN_IP, FLAGGED_IP, createMockFetch } from '../fixtures/responses.js';

const extDir = fileURLToPath(new URL('../../extension/', import.meta.url));
const manifest = JSON.parse(await readFile(`${extDir}manifest.json`, 'utf8'));

function hostAllowed(hostname) {
  return manifest.host_permissions.some((pattern) => {
    const m = pattern.match(/^https:\/\/([^/]+)\/\*$/);
    if (!m) return false;
    const host = m[1];
    return host.startsWith('*.') ? hostname.endsWith(host.slice(1)) : hostname === host;
  });
}

test('manifest is MV3 and every referenced file exists', async () => {
  assert.equal(manifest.manifest_version, 3);
  const files = [
    ...Object.values(manifest.icons),
    ...Object.values(manifest.action.default_icon),
    manifest.action.default_popup,
    manifest.options_ui.page,
    manifest.background.service_worker,
    'results.html',
  ];
  for (const file of files) await access(`${extDir}${file}`);
  assert.equal(manifest.background.type, 'module');
  assert.deepEqual([...manifest.permissions].sort(), ['activeTab', 'contextMenus', 'scripting', 'storage']);
});

test('host permissions cover every API host a lookup can contact', async () => {
  const settings = normalizeSettings({ keys: { abuseipdb: 'a', virustotal: 'v', threatfox: 't' } });
  const fetchImpl = createMockFetch();
  for (const ip of [BENIGN_IP, FLAGGED_IP, '2001:4860:4860::8888']) {
    await runLookup(normalizeIp(ip), { settings, fetchImpl });
  }
  // The DNS fallback resolver and RDAP registry redirects aren't hit by the mocks.
  const hosts = new Set([
    ...fetchImpl.calls.map((c) => new URL(c.url).hostname),
    'cloudflare-dns.com',
    'rdap.arin.net',
    'rdap.db.ripe.net',
    'rdap.apnic.net',
    'rdap.lacnic.net',
    'rdap.afrinic.net',
  ]);
  for (const host of hosts) assert.ok(hostAllowed(host), `${host} is missing from host_permissions`);
  assert.ok(hosts.size >= 14);
});

test('quick links are https and include the IP', () => {
  for (const link of QUICK_LINKS) {
    const url = link.url('8.8.8.8');
    assert.match(url, /^https:\/\//, link.id);
    assert.ok(url.includes('8.8.8.8'), link.id);
  }
});
