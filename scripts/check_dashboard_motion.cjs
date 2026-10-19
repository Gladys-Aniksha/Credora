// Optional browser check: provide Playwright through NODE_PATH and a Python executable.
const { chromium } = require('playwright');
const fs = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const { execFileSync } = require('node:child_process');
const assert = require('node:assert/strict');

async function main() {
  const root = path.resolve(__dirname, '..');
  const python = process.argv[2] || 'python';
  const payload = JSON.parse(execFileSync(python, ['-c', `
import json
from dashboard.components.assessment_motion import motion_payload
from modules.phase1_foundation.m11_trust_score.aggregator import WEIGHTS
current = {"model_name": "Browser validation", "trust_score": 76, "module_results": [{"module": name, "status": "pass", "score": 50 + index * 3} for index, name in enumerate(WEIGHTS)]}
baseline = {"trust_score": 82, "module_results": [{"module": name, "status": "pass", "score": 85 - index * 2} for index, name in enumerate(WEIGHTS)]}
print(json.dumps(motion_payload(current, baseline)))
`], { cwd: root, encoding: 'utf8' }));
  const template = await fs.readFile(path.join(root, 'dashboard/components/assessment_motion.html'), 'utf8');
  const html = template.replace('__ASSESSMENT_DATA__', JSON.stringify(payload));
  const output = await fs.mkdtemp(path.join(os.tmpdir(), 'credora-motion-'));
  const browser = await chromium.launch({ headless: true, channel: process.env.CREDORA_BROWSER_CHANNEL || 'msedge' });
  try {
    for (const [width, height] of [[1366, 768], [1440, 900], [1672, 941], [1920, 1080], [390, 844]]) {
      const page = await browser.newPage({ viewport: { width, height } });
      const errors = [];
      page.on('pageerror', error => errors.push(error.message));
      await page.setContent(html);
      await page.waitForTimeout(250);
      const moving = Number(await page.locator('#score').textContent());
      assert(moving > 0 && moving < 76, 'Needle must animate automatically on entry');
      await page.waitForFunction(() => document.getElementById('score').textContent === '76.0');
      assert.equal(errors.length, 0, errors.join('\n'));
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      assert(await page.evaluate(() => {
        const pixels = document.getElementById('chart').getContext('2d').getImageData(0, 0, document.getElementById('chart').width, document.getElementById('chart').height).data;
        return pixels.some((value, index) => index % 4 === 3 && value > 0);
      }));
      assert.equal(await page.locator('button,input').count(), 0, 'Playback controls must be absent');
      await page.waitForTimeout(100);
      await page.screenshot({ path: path.join(output, `motion-${width}.png`), fullPage: true });
      await page.close();
    }
    const page = await browser.newPage({ reducedMotion: 'reduce' });
    await page.setContent(html);
    await page.waitForFunction(() => document.getElementById('score').textContent === '76.0');
    await page.close();
    console.log(`Browser checks passed. Screenshots: ${output}`);
  } finally {
    await browser.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
