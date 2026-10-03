// Regenerates the README images from mocked API data (no real lookups):
//   docs/hero.png            – README banner: the full report with the popup on top
//   docs/options.png         – the settings page
//   docs/social-preview.png  – 1280×640 card for GitHub's "Social preview" setting
// Usage: npm run screenshots

import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { launchExtension } from '../tests/e2e/harness.js';

const docs = fileURLToPath(new URL('../docs/', import.meta.url));
const icon = fileURLToPath(new URL('../extension/icons/icon128.png', import.meta.url));
const work = await mkdtemp(path.join(tmpdir(), 'ipscout-shots-'));
await mkdir(docs, { recursive: true });

/* ------------------------------------------------- 1. raw screenshots */

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
  await popup.screenshot({ path: `${work}/popup.png`, fullPage: true });

  const report = await ext.context.newPage();
  await report.setViewportSize({ width: 1240, height: 980 });
  await report.goto(ext.url('results.html?q=8.8.8.8'));
  await settled(report);
  await report.screenshot({ path: `${work}/report.png` });

  const options = await ext.context.newPage();
  await options.setViewportSize({ width: 900, height: 760 });
  await options.goto(ext.url('options.html'));
  await options.waitForSelector('.provider-row');
  await options.screenshot({ path: `${docs}options.png` });
} finally {
  await ext.close();
}

/* ---------------------------------------------- 2. composed images */

const dataUri = async (file) => `data:image/png;base64,${(await readFile(file)).toString('base64')}`;
const images = {
  report: await dataUri(`${work}/report.png`),
  popup: await dataUri(`${work}/popup.png`),
  icon: await dataUri(icon),
};

const BACKDROP = `
  radial-gradient(circle at 12% 8%, rgba(150, 170, 255, 0.55), transparent 42%),
  radial-gradient(circle at 92% 95%, rgba(99, 230, 190, 0.35), transparent 40%),
  linear-gradient(135deg, #4c6ef5, #2b3cae)`;

const heroHtml = `<!doctype html><html><head><style>
  * { box-sizing: border-box; margin: 0; }
  body { width: 1280px; height: 760px; background: transparent; font-family: system-ui, sans-serif; }
  .stage { position: relative; width: 100%; height: 100%; border-radius: 24px; overflow: hidden; background: ${BACKDROP}; }
  .window { position: absolute; left: 56px; top: 56px; width: 900px; height: 660px; border-radius: 14px; overflow: hidden;
    background: #fff; box-shadow: 0 30px 70px rgba(8, 18, 60, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.25); }
  .bar { height: 38px; display: flex; align-items: center; gap: 8px; padding: 0 14px; background: #eef0f4; border-bottom: 1px solid #dde1e7; }
  .light { width: 12px; height: 12px; border-radius: 50%; }
  .url { margin-left: 14px; flex: 1; height: 24px; display: flex; align-items: center; padding: 0 12px; border-radius: 12px;
    background: #fff; border: 1px solid #dde1e7; color: #5c6570; font-size: 12px; }
  .window img { display: block; width: 100%; }
  .popup { position: absolute; right: 56px; top: 104px; width: 400px; height: 612px; border-radius: 12px; overflow: hidden;
    background: #fff; box-shadow: 0 30px 70px rgba(8, 18, 60, 0.5), 0 0 0 1px rgba(0, 0, 0, 0.08); }
  .popup img { display: block; width: 100%; }
</style></head><body><div class="stage">
  <div class="window">
    <div class="bar">
      <span class="light" style="background:#ff5f57"></span><span class="light" style="background:#febc2e"></span><span class="light" style="background:#28c840"></span>
      <div class="url">ipScout · 8.8.8.8</div>
    </div>
    <img src="${images.report}" alt="">
  </div>
  <div class="popup"><img src="${images.popup}" alt=""></div>
</div></body></html>`;

const socialHtml = `<!doctype html><html><head><style>
  * { box-sizing: border-box; margin: 0; }
  body { width: 1280px; height: 640px; font-family: system-ui, -apple-system, 'Segoe UI', sans-serif; color: #fff; }
  .stage { position: relative; width: 100%; height: 100%; overflow: hidden; background: ${BACKDROP}; }
  .text { position: absolute; left: 88px; top: 96px; width: 600px; }
  .logo { width: 108px; height: 108px; border-radius: 26px; box-shadow: 0 14px 34px rgba(8, 18, 60, 0.35); }
  h1 { margin-top: 30px; font-size: 84px; font-weight: 800; letter-spacing: -0.03em; line-height: 1; }
  p { margin-top: 20px; font-size: 32px; line-height: 1.3; color: rgba(255, 255, 255, 0.92); }
  .pills { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 30px; }
  .pill { padding: 8px 16px; border-radius: 999px; font-size: 20px; font-weight: 600;
    background: rgba(255, 255, 255, 0.16); border: 1px solid rgba(255, 255, 255, 0.3); }
  .popup { position: absolute; right: 88px; top: 70px; width: 420px; height: 640px; border-radius: 14px; overflow: hidden;
    background: #fff; box-shadow: 0 30px 70px rgba(8, 18, 60, 0.5); }
  .popup img { display: block; width: 100%; }
</style></head><body><div class="stage">
  <div class="text">
    <img class="logo" src="${images.icon}" alt="">
    <h1>ipScout</h1>
    <p>Research any IP address in one click, right from Chrome.</p>
    <div class="pills"><span class="pill">11 free sources</span><span class="pill">One verdict</span><span class="pill">No server</span></div>
  </div>
  <div class="popup"><img src="${images.popup}" alt=""></div>
</div></body></html>`;

const browser = await chromium.launch();
try {
  const hero = await browser.newPage({ viewport: { width: 1280, height: 760 }, deviceScaleFactor: 2 });
  await hero.setContent(heroHtml, { waitUntil: 'load' });
  await hero.screenshot({ path: `${docs}hero.png`, omitBackground: true });

  const social = await browser.newPage({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 });
  await social.setContent(socialHtml, { waitUntil: 'load' });
  await social.screenshot({ path: `${docs}social-preview.png` });
} finally {
  await browser.close();
  await rm(work, { recursive: true, force: true });
}

/* ------------------------------------------------------- 3. compress */

// 8-bit palettes make the PNGs ~60% smaller, and -strip drops timestamps so
// identical renders give identical files. Skipped if ImageMagick is missing.
for (const name of ['hero', 'options', 'social-preview']) {
  const file = `${docs}${name}.png`;
  try {
    execFileSync('convert', [file, '-strip', '+dither', '-colors', '256', `PNG8:${file}`]);
  } catch {
    console.warn('ImageMagick not found; leaving the PNGs uncompressed.');
    break;
  }
}
console.log('Wrote docs/hero.png, docs/options.png and docs/social-preview.png');
