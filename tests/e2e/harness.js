// Launches Chromium with the unpacked extension and serves every outbound
// HTTPS request from the mock fixtures, so tests never touch the real APIs.

import { chromium } from 'playwright';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mockResponse } from '../fixtures/responses.js';

export const EXTENSION_PATH = fileURLToPath(new URL('../../extension/', import.meta.url));

export async function launchExtension({ deviceScaleFactor = 1 } = {}) {
  const userDataDir = await mkdtemp(path.join(tmpdir(), 'ipscout-e2e-'));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: 'chromium', // the full Chromium build supports extensions in headless mode
    headless: true,
    deviceScaleFactor,
    args: [`--disable-extensions-except=${EXTENSION_PATH}`, `--load-extension=${EXTENSION_PATH}`],
  });

  const requests = [];
  await context.route(
    (url) => url.protocol === 'https:',
    async (route) => {
      const request = route.request();
      requests.push({ url: request.url(), method: request.method(), headers: request.headers() });
      const res = mockResponse(request.url(), { method: request.method(), body: request.postData() });
      if (!res) return route.fulfill({ status: 599, body: 'blocked by test harness' });
      return route.fulfill({ status: res.status, contentType: 'application/json', body: JSON.stringify(res.body) });
    },
  );

  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent('serviceworker');
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
    },
  };
}
