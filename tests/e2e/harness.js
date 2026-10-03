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
 * Poll an async check from Node until it returns something truthy.
 * (Playwright's waitForFunction treats a returned promise as already truthy,
 * so it can't wait on async extension APIs like chrome.storage.)
 */
export async function waitFor(check, { timeout = 10000, interval = 50, message = 'condition' } = {}) {
  const deadline = Date.now() + timeout;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${message}`);
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
}

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
  // The worker can be reported before Chrome has bound its extension APIs.
  // Each evaluate runs in the worker's current context, so poll until they appear.
  await waitFor(() => worker.evaluate(() => typeof globalThis.chrome?.storage === 'object'), {
    message: 'extension APIs in the service worker',
  });
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
