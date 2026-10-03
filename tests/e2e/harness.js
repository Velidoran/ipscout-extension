// Launches Chromium with the unpacked extension and serves every outbound
// HTTPS request from the mock fixtures, so tests never touch the real APIs.

import { chromium } from 'playwright';
import { cp, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mockResponse } from '../fixtures/responses.js';

export const EXTENSION_PATH = fileURLToPath(new URL('../../extension/', import.meta.url));

// A stand-in for an ordinary website, for tests that inject a content script.
export const TEST_PAGE_URL = 'https://example.test/';

/**
 * extraHostPermissions loads a copy of the extension with additional host
 * access, e.g. so a test can inject a content script into TEST_PAGE_URL.
 */
export async function launchExtension({ deviceScaleFactor = 1, extraHostPermissions = [] } = {}) {
  const userDataDir = await mkdtemp(path.join(tmpdir(), 'ipscout-e2e-'));
  let extensionPath = EXTENSION_PATH;
  let extensionCopy = null;
  if (extraHostPermissions.length) {
    extensionCopy = await mkdtemp(path.join(tmpdir(), 'ipscout-ext-'));
    await cp(EXTENSION_PATH, extensionCopy, { recursive: true });
    const manifestPath = path.join(extensionCopy, 'manifest.json');
    const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
    manifest.host_permissions.push(...extraHostPermissions);
    await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
    extensionPath = extensionCopy;
  }

  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium', // the full Chromium build supports extensions in headless mode
    headless: true,
    deviceScaleFactor,
    args: [`--disable-extensions-except=${extensionPath}`, `--load-extension=${extensionPath}`],
  });

  const requests = [];
  await context.route(
    (url) => url.protocol === 'https:',
    async (route) => {
      const request = route.request();
      if (request.url().startsWith(TEST_PAGE_URL)) {
        return route.fulfill({ contentType: 'text/html', body: '<!doctype html><title>Test page</title><p>Seen from 8.8.8.8</p>' });
      }
      requests.push({ url: request.url(), method: request.method(), headers: request.headers() });
      const res = mockResponse(request.url(), { body: request.postData() });
      if (!res) return route.fulfill({ status: 599, body: 'blocked by test harness' });
      return route.fulfill({ status: res.status, contentType: 'application/json', body: JSON.stringify(res.body) });
    },
  );

  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent('serviceworker');
  // The worker can be reported before Chrome has bound its extension APIs,
  // so poll (each evaluate runs in the worker's current context) until they appear.
  const deadline = Date.now() + 10000;
  while (!(await worker.evaluate(() => typeof globalThis.chrome?.storage === 'object'))) {
    if (Date.now() > deadline) throw new Error('extension APIs never became available in the service worker');
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  const extensionId = new URL(worker.url()).host;

  return {
    context,
    worker,
    extensionId,
    requests,
    url: (file) => `chrome-extension://${extensionId}/${file}`,
    async close() {
      await context.close();
      await rm(userDataDir, { recursive: true, force: true });
      if (extensionCopy) await rm(extensionCopy, { recursive: true, force: true });
    },
  };
}
