// Real HTTP + Chromium WebGL integration test, including GLBs and scenario semantics.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright';
const base=process.argv[2]??'http://127.0.0.1:8765/';
const out=process.argv[3]??'screenshots-atlas';fs.mkdirSync(out,{recursive:true});
const browser=await chromium.launch({args:['--use-angle=swiftshader','--enable-unsafe-swiftshader','--ignore-gpu-blocklist']});
const results=[],errors=[];
try {
 const page=await browser.newPage({viewport:{width:1440,height:1000}});
 page.on('pageerror',e=>errors.push(e.message));
 await page.goto(`${base}?quality=balanced&capture=1&t=1&cam=overview`);
 await page.waitForFunction(()=>window.__atelier?.world.assetCount===40&&window.__atelier.renderer.info.render.calls>0,null,{timeout:120000});
 assert.equal(await page.evaluate(()=>window.__atelier.world.usedAssetIds.length),40);
 await page.screenshot({path:`${out}/overview.png`});
 const keys=await page.evaluate(()=>Object.fromEntries(Object.entries(window.__atelier.world.keys).map(([k,o])=>[k,o.position.toArray()])));
 for(const [scenario,t,code] of [['normal',162,'OK'],['untrusted',109,'UNTRUSTED_ANCHOR'],['sanMismatch',119,'SAN_MISMATCH'],['expired',129,'CERT_EXPIRED'],['wrongEku',139,'WRONG_EKU'],['leafRevoked',149,'LEAF_REVOKED'],['intermediateRevoked',149,'INTERMEDIATE_REVOKED'],['crlExpired',149,'CRL_EXPIRED'],['lesson',179,'LEAF_REVOKED']]) {
  await page.selectOption('#scenario',scenario);
  await page.evaluate(t=>{const a=window.__atelier;a.ui.t=t;a.ui.playing=false;a.ui.autoCam=true;a.ui.lastScene=-1;},t);
  await page.waitForFunction(code=>document.getElementById('result').textContent.includes(code),code);
  const info=await page.evaluate(()=>({view:window.__atelier.describe(),keys:Object.fromEntries(Object.entries(window.__atelier.world.keys).map(([k,o])=>[k,o.position.toArray()])),rootVisible:window.__atelier.world.tokens.rootCertCopy.visible}));
  assert.deepEqual(info.keys,keys);
  if(scenario==='wrongEku'){assert.match(info.view.leaf.rows.join(),/clientAuth/);assert.doesNotMatch(info.view.leaf.rows.join(),/serverAuth/);}
  if(scenario==='intermediateRevoked')assert.match(info.view.crlFetch.title,/ルートCA/);
  if(scenario==='untrusted'){assert.match(info.view.trust,/なし/);assert.equal(info.rootVisible,false);}
  if(scenario==='crlExpired')assert.match(info.view.crlFetch.rows.join(),/期限切れ/);
  results.push({scenario,code,ok:true});
 }
 assert.equal(await page.evaluate(()=>window.__atelier.world.keys.root.userData.material!==window.__atelier.world.keys.server.userData.material),true);
 await page.setViewportSize({width:390,height:844});await page.screenshot({path:`${out}/mobile.png`});
 await page.close();
 const model=await browser.newPage({viewport:{width:1440,height:1000}});model.on('pageerror',e=>errors.push(e.message));
 await model.goto(`${base}models.html?id=A12&lod=0`);
 await model.waitForFunction(()=>window.__modelViewer?.inspect().loaded,null,{timeout:120000});
 assert.equal(await model.locator('#asset option').count(),40);
 for(const [id,clip] of [['A10','VaultDoor_Open'],['A12','Signing_Press'],['A17','TrustDrawer_Select'],['A18','Gate_Open'],['A26','CSR_Read'],['A37','Guide_Point']]) {
  await model.selectOption('#asset',id);await model.waitForFunction(id=>window.__modelViewer.inspect().loaded&&window.__modelViewer.inspect().id===id,id,{timeout:90000});
  assert.ok((await model.evaluate(()=>window.__modelViewer.inspect().clips)).includes(clip));
  await model.check('#animate');await model.waitForTimeout(300);
  assert.ok(await model.evaluate(()=>window.__modelViewer.renderer.info.render.calls>0));
  results.push({id,clip,ok:true});
 }
 await model.screenshot({path:`${out}/model-guide.png`});await model.close();
 assert.deepEqual(errors,[]);
 fs.writeFileSync(`${out}/results.json`,JSON.stringify({ok:true,scope:'HTTP / Chromium SwiftShader; not real GPU performance',results},null,2));
 console.log(`ATLAS OK: 40 GLBs, ${results.length} scene/clip checks`);
} finally {await browser.close();}
