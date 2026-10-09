// 実ブラウザ（Chromium）で 3D 描画と「表示内容の意味」を確認し、スクリーンショットを保存する。
// 前提: viz/ を HTTP で配信していること、playwright が使えること（viz/package.json の devDependencies）。
//   python3 -m http.server 8765 --bind 127.0.0.1 --directory viz &
//   node viz/tests/render-check.mjs http://127.0.0.1:8765/ out-dir
import fs from 'node:fs';
import { createRequire } from 'node:module';

// ローカルに無ければ NODE_PATH 経由（グローバルの playwright）で読む
const { chromium } = await import('playwright').catch(() => createRequire(import.meta.url)('playwright'));

const base = process.argv[2] ?? 'http://127.0.0.1:8765/';
const out = process.argv[3] ?? 'screenshots';
fs.mkdirSync(out, { recursive: true });

// title: 場面タイトルに含まれる文字列 / result: 結果表示（null は非表示）/ view: カード等の内容の検査
const shots = [
  { name: '01-overview', q: 't=1&cam=overview', title: 'ようこそ', result: null },
  { name: '02-root-delegation', q: 't=16', title: '委任', result: null },
  { name: '03-csr-to-ra', q: 't=54&cam=ra', title: 'RA', result: null },
  { name: '04-signing', q: 't=75.6', title: '署名', result: null },
  { name: '05-present-chain', q: 't=96&cam=client', title: '提示', result: null,
    view: (v) => v.target.includes('localhost') && v.leaf.rows.join().includes('serverAuth') },
  { name: '06-gate-san', q: 't=118', title: 'SAN', result: null },
  { name: '07-crl-update', q: 't=166', title: 'CRL', result: 'OK',
    view: (v) => v.crlNew.rows.join().includes('失効 1件') },
  { name: '08-revoked-reject', q: 't=179', title: '拒否', result: 'LEAF_REVOKED' },
  { name: '09-untrusted', q: 'scenario=untrusted&t=179&cam=gates', title: 'ふりかえり', result: 'UNTRUSTED_ANCHOR',
    view: (v) => v.trust.includes('なし'), hidden: ['rootCertCopy'] },
  { name: '10-intermediate-revoked', q: 'scenario=intermediateRevoked&t=179', title: 'ふりかえり',
    result: 'INTERMEDIATE_REVOKED', view: (v) => v.crlFetch.title.includes('ルートCA') && v.crlFetch.rows.join().includes('中間CA') },
  { name: '11-crl-expired', q: 'scenario=crlExpired&t=179', title: 'ふりかえり', result: 'CRL_EXPIRED',
    view: (v) => v.crlFetch.rows.join().includes('期限切れ') },
  { name: '12-wrong-eku', q: 'scenario=wrongEku&t=139', title: '用途', result: 'WRONG_EKU',
    view: (v) => v.leaf.rows.join().includes('clientAuth') && !v.leaf.rows.join().includes('serverAuth') },
  { name: '13-san-mismatch', q: 'scenario=sanMismatch&t=96&cam=client', title: '提示', result: null,
    view: (v) => v.target.includes('example.com') },
  { name: '14-leaf-revoked', q: 'scenario=leafRevoked&t=148', title: '失効確認', result: 'LEAF_REVOKED',
    view: (v) => v.crlFetch.rows.join().includes('サーバー証明書') },
  { name: '15-mobile', q: 't=118', title: 'SAN', result: null, viewport: { width: 390, height: 844 } },
];

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM_PATH || undefined,
  args: ['--use-angle=swiftshader', '--enable-unsafe-swiftshader', '--ignore-gpu-blocklist'],
});
let failures = 0;
const fail = (name, why) => { failures++; console.log(`NG  ${name}: ${why}`); };

for (const s of shots) {
  const page = await browser.newPage({ viewport: s.viewport ?? { width: 1440, height: 900 } });
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
  await page.goto(`${base}?capture=1&${s.q}`);
  await page.waitForFunction(() => document.body.classList.contains('ready') && window.__atelier, null, { timeout: 30000 });
  await page.waitForTimeout(1200);
  const info = await page.evaluate(() => {
    const r = window.__atelier.renderer.info.render;
    const resultEl = document.getElementById('result');
    return {
      calls: r.calls, triangles: r.triangles, title: document.getElementById('sceneTitle').textContent,
      result: resultEl.hidden ? null : resultEl.textContent, view: window.__atelier.describe(),
      visible: Object.fromEntries(Object.entries(window.__atelier.world.tokens).map(([k, o]) => [k, o.visible])),
      fallback: !document.getElementById('fallback').hidden,
    };
  });
  await page.screenshot({ path: `${out}/${s.name}.png` });
  const before = failures;
  if (errors.length) fail(s.name, `console: ${errors.join(' | ')}`);
  if (info.fallback || !(info.calls > 0 && info.triangles > 0)) fail(s.name, 'WebGL で描画されていない');
  if (!info.title.includes(s.title)) fail(s.name, `場面タイトル「${info.title}」に「${s.title}」がない`);
  if (s.result === null && info.result !== null) fail(s.name, `結果が表示されている: ${info.result}`);
  if (s.result && !(info.result ?? '').includes(s.result)) fail(s.name, `結果「${info.result}」に ${s.result} がない`);
  if (s.view && !s.view(info.view)) fail(s.name, `表示内容が条件と一致しない: ${JSON.stringify(info.view)}`);
  for (const k of s.hidden ?? []) if (info.visible[k]) fail(s.name, `${k} が表示されている`);
  if (failures === before) console.log(`ok  ${s.name}  calls=${info.calls} tris=${info.triangles} 「${info.title}」 ${info.result ?? ''}`);
  await page.close();
}

// F08: measured が true でない記録を「実測」と表示しない
{
  const page = await browser.newPage();
  await page.goto(`${base}?autoplay=0`);
  await page.waitForFunction(() => window.__atelier, null, { timeout: 30000 });
  const res = await page.evaluate(() => {
    const doc = { schema: 'pkilab-events/2', measured: false,
      events: [{ seq: 1, type: 'CERT_ISSUED', origin: 'measured', result: 'ok', details: {} }] };
    window.__atelier.loadEventsDoc(JSON.stringify(doc), 'synthetic.json');
    return { status: document.getElementById('eventsStatus').textContent,
      dots: [...document.querySelectorAll('#chapters .dot')].filter((d) => !d.hidden).length };
  });
  if (/実測として提供/.test(res.status) || res.dots !== 0) fail('measured-false', JSON.stringify(res));
  else console.log(`ok  measured-false  「${res.status}」`);
  const sample = await page.evaluate(async () => {
    window.__atelier.loadEventsDoc(await (await fetch('data/sample-events.json')).text(), 'sample');
    return { status: document.getElementById('eventsStatus').textContent,
      dots: [...document.querySelectorAll('#chapters .dot')].filter((d) => !d.hidden).length };
  });
  if (!/実測として提供/.test(sample.status) || sample.dots === 0) fail('sample-events', JSON.stringify(sample));
  else console.log(`ok  sample-events  dots=${sample.dots}`);
  await page.close();
}

await browser.close();
console.log(failures ? `FAILED: ${failures}` : 'ALL OK');
process.exit(failures ? 1 : 0);
