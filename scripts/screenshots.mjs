// Regenerates the README screenshots from mocked API data.
// Usage: node scripts/screenshots.mjs

import { execFileSync } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { launchExtension } from '../tests/e2e/harness.js';

const outDir = fileURLToPath(new URL('../docs/', import.meta.url));
await mkdir(outDir, { recursive: true });

const ext = await launchExtension({ deviceScaleFactor: 2 });
try {
  const setup = await ext.context.newPage();
  await setup.goto(ext.url('options.html'));
  await setup.evaluate(() =>
    chrome.storage.local.set({ settings: { keys: { abuseipdb: 'demo', virustotal: 'demo', threatfox: 'demo' } } }),
  );
  await setup.close();

  const settled = (page) => page.waitForFunction(() => document.querySelector('.results') && !document.querySelector('#content .spinner'));

  const popup = await ext.context.newPage();
  await popup.setViewportSize({ width: 480, height: 600 });
  await popup.goto(ext.url('popup.html?q=1.2.3.4'));
  await settled(popup);
  await popup.screenshot({ path: `${outDir}popup.png`, fullPage: true });
  console.log('docs/popup.png');

  const page = await ext.context.newPage();
  await page.setViewportSize({ width: 1240, height: 980 });
  await page.goto(ext.url('results.html?q=8.8.8.8'));
  await settled(page);
  await page.screenshot({ path: `${outDir}report.png` });
  console.log('docs/report.png');

  const options = await ext.context.newPage();
  await options.setViewportSize({ width: 900, height: 760 });
  await options.goto(ext.url('options.html'));
  await options.waitForSelector('.provider-row');
  await options.screenshot({ path: `${outDir}options.png` });
  console.log('docs/options.png');
} finally {
  await ext.close();
}

// Shrink the PNGs to 8-bit palettes (~60% smaller) when ImageMagick is available.
for (const name of ['popup', 'report', 'options']) {
  const file = `${outDir}${name}.png`;
  try {
    execFileSync('convert', [file, '+dither', '-colors', '256', `PNG8:${file}`]);
  } catch {
    console.warn(`Skipped compressing ${name}.png (ImageMagick not found)`);
    break;
  }
}
