// 実ブラウザ（Chromium）で 3D 描画を確認し、スクリーンショットを保存する。
// 前提: playwright が import できること、viz/ を HTTP で配信していること。
//   python3 -m http.server 8765 --bind 127.0.0.1 --directory viz &
//   node viz/tests/render-check.mjs http://127.0.0.1:8765/ out-dir
import fs from 'node:fs';
import { createRequire } from 'node:module';

// グローバルに入れた playwright も使えるよう、ESM で見つからなければ NODE_PATH 経由で読む
const { chromium } = await import('playwright').catch(() => createRequire(import.meta.url)('playwright'));

const base = process.argv[2] ?? 'http://127.0.0.1:8765/';
const out = process.argv[3] ?? 'screenshots';
fs.mkdirSync(out, { recursive: true });

const shots = [
  { name: '01-overview', q: 't=1&cam=overview' },
  { name: '02-root-delegation', q: 't=16' },
  { name: '03-csr-to-ra', q: 't=54&cam=ra' },
  { name: '04-signing', q: 't=75.6' },
  { name: '05-present-chain', q: 't=96&cam=client' },
  { name: '06-gate-san', q: 't=118' },
  { name: '07-crl-update', q: 't=166' },
  { name: '08-revoked-reject', q: 't=179' },
  { name: '09-untrusted', q: 'scenario=untrusted&t=179&cam=gates' },
  { name: '10-intermediate-revoked', q: 'scenario=intermediateRevoked&t=179' },
  { name: '11-crl-expired', q: 'scenario=crlExpired&t=179' },
  { name: '12-mobile', q: 't=118', viewport: { width: 390, height: 844 } },
];

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
  args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'],
});
let failures = 0;
for (const s of shots) {
  const page = await browser.newPage({ viewport: s.viewport ?? { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  await page.goto(`${base}?capture=1&${s.q}`);
  await page.waitForFunction(() => document.body.classList.contains('ready') && window.__atelier, null, { timeout: 30000 });
  await page.waitForTimeout(1500);
  const info = await page.evaluate(() => {
    const r = window.__atelier.renderer.info.render;
    return { calls: r.calls, triangles: r.triangles, title: document.getElementById('sceneTitle').textContent,
      result: document.getElementById('result').hidden ? null : document.getElementById('result').textContent };
  });
  await page.screenshot({ path: `${out}/${s.name}.png` });
  const ok = errors.length === 0 && info.calls > 0 && info.triangles > 0;
  if (!ok) failures++;
  console.log(`${ok ? 'ok ' : 'NG '} ${s.name}  calls=${info.calls} tris=${info.triangles}  「${info.title}」 ${info.result ?? ''} ${errors.join(' | ')}`);
  await page.close();
}
await browser.close();
process.exit(failures ? 1 : 0);
