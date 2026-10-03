// Renders extension/icons/*.svg into the PNG sizes Chrome needs.
// Usage: npm run icons   (needs the Playwright dev dependency and a Chromium build)

import { chromium } from 'playwright';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('../extension/icons/', import.meta.url));
const sources = {
  large: await readFile(`${dir}icon.svg`, 'utf8'),
  small: await readFile(`${dir}icon-small.svg`, 'utf8'),
};
const targets = [
  [16, 'small'],
  [32, 'large'],
  [48, 'large'],
  [128, 'large'],
];

const browser = await chromium.launch();
try {
  for (const [size, variant] of targets) {
    const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
    const svg = sources[variant].replace('<svg ', `<svg width="${size}" height="${size}" `);
    await page.setContent(`<html><body style="margin:0;background:transparent">${svg}</body></html>`);
    await page.locator('svg').screenshot({ path: `${dir}icon${size}.png`, omitBackground: true });
    await page.close();
    console.log(`icons/icon${size}.png`);
  }
} finally {
  await browser.close();
}
