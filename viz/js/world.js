// 3D 空間とモデル（すべてコードで生成する。外部の GLB や画像は使わない）。
// モデル ID は docs/3d-space-design.md のモデル一覧に対応する。
import * as THREE from 'three';
import { RoundedBoxGeometry } from 'three/addons/geometries/RoundedBoxGeometry.js';
import { STATIONS, GATES } from './lesson.js';

// ---------------------------------------------------------------------------
// 材質
// ---------------------------------------------------------------------------
const M = {};
function mats() {
  if (M.ready) return M;
  const std = (color, roughness = 0.55, metalness = 0.1, extra = {}) =>
    new THREE.MeshStandardMaterial({ color, roughness, metalness, ...extra });
  Object.assign(M, {
    ready: true,
    floor: std(0x1b2230, 0.85, 0.05),
    tile: std(0x232c3d, 0.7, 0.1),
    plinth: std(0x2b3447, 0.6, 0.2),
    wall: std(0xdfe4ec, 0.8, 0.0),
    wallDark: std(0x39445a, 0.7, 0.1),
    steel: std(0x9aa4b2, 0.32, 0.85),
    darkSteel: std(0x3a414d, 0.4, 0.8),
    black: std(0x111418, 0.5, 0.3),
    rubber: std(0x1d1f24, 0.9, 0.0),
    gold: std(0xe0a526, 0.22, 1.0, { emissive: 0x3a2400, emissiveIntensity: 0.4 }),
    pubKey: std(0x3fa9ff, 0.25, 0.6, { emissive: 0x0b3d80, emissiveIntensity: 0.6 }),
    glass: new THREE.MeshPhysicalMaterial({ color: 0xbfe3ff, roughness: 0.05, metalness: 0,
      transparent: true, opacity: 0.16, side: THREE.DoubleSide, depthWrite: false }),
    screen: std(0x0b1a2a, 0.3, 0.1, { emissive: 0x1d5c8f, emissiveIntensity: 0.9 }),
    paper: std(0xf4f1e8, 0.9, 0.0),
    root: std(0xb3263a, 0.45, 0.35),
    inter: std(0xe08a1e, 0.45, 0.35),
    ra: std(0x1f9e8f, 0.5, 0.25),
    server: std(0x2f6fdb, 0.45, 0.35),
    client: std(0x3aa35b, 0.5, 0.25),
    crl: std(0x7d4bd1, 0.45, 0.3),
    ocsp: std(0x5b6b84, 0.45, 0.4),
    lampOff: std(0x2a2f38, 0.4, 0.2, { emissive: 0x000000 }),
    robot: std(0xeef1f5, 0.35, 0.2),
    visor: std(0x0d1117, 0.15, 0.6, { emissive: 0x2a6df5, emissiveIntensity: 0.8 }),
    wood: std(0x8a6a4a, 0.75, 0.0),
    light: new THREE.MeshStandardMaterial({ color: 0xffffff, emissive: 0xfff3dc, emissiveIntensity: 2.2 }),
  });
  return M;
}

// ---------------------------------------------------------------------------
// 形状ヘルパー
// ---------------------------------------------------------------------------
function rbox(w, h, d, mat, r = 0.04) {
  const radius = Math.min(r, w / 2 - 1e-3, h / 2 - 1e-3, d / 2 - 1e-3);
  const m = new THREE.Mesh(new RoundedBoxGeometry(w, h, d, 3, Math.max(radius, 0.001)), mat);
  m.castShadow = true; m.receiveShadow = true;
  return m;
}
function box(w, h, d, mat) {
  const m = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), mat);
  m.castShadow = true; m.receiveShadow = true;
  return m;
}
function cyl(rt, rb, h, mat, seg = 32) {
  const m = new THREE.Mesh(new THREE.CylinderGeometry(rt, rb, h, seg), mat);
  m.castShadow = true; m.receiveShadow = true;
  return m;
}
function at(obj, x, y, z, ry = 0) { obj.position.set(x, y, z); obj.rotation.y = ry; return obj; }
function group(...children) { const g = new THREE.Group(); children.forEach((c) => g.add(c)); return g; }

// 日本語ラベル（Canvas テクスチャのスプライト）
export function makeLabel(text, { size = 0.32, color = '#ffffff', bg = 'rgba(15,20,30,0.78)', accent = null, weight = 700 } = {}) {
  const lines = String(text).split('\n');
  const px = 64;
  const c = document.createElement('canvas');
  const ctx = c.getContext('2d');
  ctx.font = `${weight} ${px}px "Hiragino Sans","Noto Sans JP","Yu Gothic",system-ui,sans-serif`;
  const w = Math.ceil(Math.max(...lines.map((l) => ctx.measureText(l).width))) + px;
  const h = lines.length * px * 1.25 + px * 0.5;
  c.width = w; c.height = h;
  ctx.font = `${weight} ${px}px "Hiragino Sans","Noto Sans JP","Yu Gothic",system-ui,sans-serif`;
  ctx.fillStyle = bg;
  roundRect(ctx, 0, 0, w, h, px * 0.35); ctx.fill();
  if (accent) { ctx.fillStyle = accent; roundRect(ctx, 0, 0, px * 0.22, h, px * 0.1); ctx.fill(); }
  ctx.fillStyle = color; ctx.textBaseline = 'middle';
  lines.forEach((l, i) => ctx.fillText(l, px * 0.5, px * 0.25 + px * 1.25 * (i + 0.5)));
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = 4;
  const sp = new THREE.Sprite(new THREE.SpriteMaterial({ map: tex, depthWrite: false, transparent: true }));
  const scale = size / px;
  sp.scale.set(w * scale, h * scale, 1);
  sp.renderOrder = 10;
  return sp;
}
function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath();
}

// 証明書カードの表面（Canvas に項目を描く）
function cardFace(title, rows, accent) {
  const c = document.createElement('canvas');
  c.width = 512; c.height = 320;
  const ctx = c.getContext('2d');
  ctx.fillStyle = '#f7f4ec'; ctx.fillRect(0, 0, 512, 320);
  ctx.fillStyle = accent; ctx.fillRect(0, 0, 512, 64);
  ctx.fillStyle = '#fff';
  ctx.font = '700 34px "Hiragino Sans","Noto Sans JP",system-ui,sans-serif';
  ctx.fillText(title, 20, 44);
  ctx.fillStyle = '#1d2433';
  ctx.font = '500 24px ui-monospace,"Noto Sans Mono",monospace';
  rows.forEach((r, i) => ctx.fillText(r, 20, 104 + i * 38));
  // 署名欄（押印のたとえ）
  ctx.strokeStyle = accent; ctx.lineWidth = 5;
  ctx.beginPath(); ctx.arc(450, 262, 38, 0, Math.PI * 2); ctx.stroke();
  ctx.fillStyle = accent; ctx.font = '700 22px system-ui'; ctx.fillText('署名', 428, 270);
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  return tex;
}

// ---------------------------------------------------------------------------
// 小物モデル（A24〜A36）
// ---------------------------------------------------------------------------

// A24 秘密鍵（金色の鍵）。象徴であり、実際の鍵データではない。
function makePrivateKey() {
  const m = mats();
  const g = new THREE.Group();
  const bow = new THREE.Mesh(new THREE.TorusGeometry(0.12, 0.035, 16, 40), m.gold);
  bow.position.x = -0.22;
  const shaft = cyl(0.025, 0.025, 0.42, m.gold, 16); shaft.rotation.z = Math.PI / 2; shaft.position.x = 0.07;
  const t1 = box(0.035, 0.09, 0.03, m.gold); t1.position.set(0.2, -0.05, 0);
  const t2 = box(0.035, 0.06, 0.03, m.gold); t2.position.set(0.26, -0.035, 0);
  g.add(bow, shaft, t1, t2);
  g.traverse((o) => { o.castShadow = true; });
  return g;
}

// A25 公開鍵（青い多面体）
function makePublicKey() {
  const m = mats();
  const g = new THREE.Group();
  const gem = new THREE.Mesh(new THREE.OctahedronGeometry(0.13, 0), m.pubKey);
  gem.castShadow = true;
  g.add(gem);
  return g;
}

// A26 CSR フォルダー（申込書）
function makeCSRFolder() {
  const m = mats();
  const g = new THREE.Group();
  const back = rbox(0.42, 0.3, 0.02, m.ra, 0.008);
  const sheet = box(0.38, 0.27, 0.005, m.paper); sheet.position.z = 0.013;
  const tex = cardFace('CSR 申込書', ['公開鍵: EC P-256', 'SAN: localhost', '     127.0.0.1', '自己署名: あり'], '#1f9e8f');
  const face = new THREE.Mesh(new THREE.PlaneGeometry(0.37, 0.23), new THREE.MeshStandardMaterial({ map: tex, roughness: 0.9 }));
  face.position.z = 0.0165;
  const cover = new THREE.Group();
  const coverMesh = rbox(0.42, 0.3, 0.012, m.ra, 0.006);
  coverMesh.position.x = 0.21; coverMesh.position.z = 0.025;
  cover.add(coverMesh); cover.position.x = -0.21; cover.name = 'cover';
  g.add(back, sheet, face, cover);
  g.userData.cover = cover;
  return g;
}

// A27〜A29 証明書カード
function makeCertCard(kind) {
  const m = mats();
  const spec = {
    leaf: { mat: m.server, accent: '#2f6fdb', title: 'サーバー証明書',
      rows: ['Subject: CN=localhost', 'SAN: DNS:localhost', '     IP:127.0.0.1', 'CA:FALSE / serverAuth'] },
    inter: { mat: m.inter, accent: '#e08a1e', title: '中間CA証明書',
      rows: ['Issuer: Root CA', 'CA:TRUE pathlen:0', 'NameConstraints:', ' localhost,127.0.0.1'] },
    root: { mat: m.root, accent: '#b3263a', title: 'ルートCA証明書',
      rows: ['自己署名', 'CA:TRUE pathlen:1', 'keyCertSign,cRLSign', '信頼の起点'] },
  }[kind];
  const g = new THREE.Group();
  const body = rbox(0.5, 0.32, 0.025, spec.mat, 0.02);
  const face = new THREE.Mesh(new THREE.PlaneGeometry(0.47, 0.295),
    new THREE.MeshStandardMaterial({ map: cardFace(spec.title, spec.rows, spec.accent), roughness: 0.8,
      emissive: 0xffffff, emissiveIntensity: 0.0 }));
  face.position.z = 0.0135;
  const back = face.clone(); back.rotation.y = Math.PI; back.position.z = -0.0135;
  g.add(body, face, back);
  g.userData.face = face;
  g.userData.body = body;
  return g;
}

// A30 CRL 一覧ボード
function makeCRLBoard(version = 1) {
  const m = mats();
  const g = new THREE.Group();
  const frame = rbox(0.5, 0.36, 0.03, m.crl, 0.015);
  const rows = version === 1
    ? ['CRL #1000 中間CA', '失効: 0 件', 'nextUpdate: 24h後', '署名: 中間CA']
    : ['CRL #1001 中間CA', '失効: 1 件', '＋ サーバー証明書', '  理由: keyCompromise'];
  const face = new THREE.Mesh(new THREE.PlaneGeometry(0.46, 0.32),
    new THREE.MeshStandardMaterial({ map: cardFace('CRL 失効リスト', rows, '#7d4bd1'), roughness: 0.85 }));
  face.position.z = 0.016;
  g.add(frame, face);
  return g;
}

// A31 OCSP 応答ディスク
function makeOCSPDisk(label, color) {
  const g = new THREE.Group();
  const d = cyl(0.16, 0.16, 0.03, new THREE.MeshStandardMaterial({ color, roughness: 0.35, metalness: 0.4 }), 40);
  d.rotation.x = Math.PI / 2;
  const l = makeLabel(label, { size: 0.075, bg: 'rgba(0,0,0,0.0)' });
  l.position.z = 0.05;
  g.add(d, l);
  return g;
}

// A32 チェーン接続環
function makeChainLink() {
  const m = mats();
  const t = new THREE.Mesh(new THREE.TorusGeometry(0.09, 0.022, 12, 32), m.steel);
  t.scale.set(1.5, 1, 1);
  t.castShadow = true;
  return t;
}

// A34 発行承認バッジ
function makeApprovalBadge() {
  const g = new THREE.Group();
  const coin = cyl(0.11, 0.11, 0.025, new THREE.MeshStandardMaterial({ color: 0x1f9e8f, metalness: 0.6, roughness: 0.3,
    emissive: 0x0b4d45, emissiveIntensity: 0.6 }), 40);
  coin.rotation.x = Math.PI / 2;
  const l = makeLabel('承認', { size: 0.09, bg: 'rgba(0,0,0,0)' });
  l.position.z = 0.03;
  g.add(coin, l);
  return g;
}

// A35 有効期限クロック
function makeClock() {
  const m = mats();
  const g = new THREE.Group();
  const rim = new THREE.Mesh(new THREE.TorusGeometry(0.22, 0.03, 16, 48), m.steel);
  const face = new THREE.Mesh(new THREE.CircleGeometry(0.21, 48), m.paper);
  face.position.z = -0.005;
  const hand = box(0.012, 0.16, 0.01, m.black); hand.position.y = 0.07; hand.position.z = 0.01;
  const handPivot = group(hand); handPivot.name = 'hand';
  const hand2 = box(0.016, 0.11, 0.01, m.black); hand2.position.y = 0.05; hand2.position.z = 0.012;
  const handPivot2 = group(hand2); handPivot2.rotation.z = -1.1;
  g.add(rim, face, handPivot, handPivot2);
  g.userData.hand = handPivot;
  return g;
}

// A36 拒否状態の遮断パネル
function makeRejectPanel() {
  const g = new THREE.Group();
  const mat = new THREE.MeshStandardMaterial({ color: 0xd92b3a, emissive: 0x8a0d18, emissiveIntensity: 1.2,
    transparent: true, opacity: 0.85, roughness: 0.3 });
  const p = new THREE.Mesh(new THREE.PlaneGeometry(1.1, 1.0), mat);
  const x1 = box(0.9, 0.09, 0.02, new THREE.MeshStandardMaterial({ color: 0xffffff, emissive: 0xffffff, emissiveIntensity: 0.8 }));
  x1.rotation.z = Math.PI / 4; x1.position.z = 0.01;
  const x2 = x1.clone(); x2.rotation.z = -Math.PI / 4;
  g.add(p, x1, x2);
  g.userData.mat = mat;
  return g;
}

// A33 TLS 鍵共有の概念展示（2つの光る球と結ぶ線）
function makeTLSSpark() {
  const g = new THREE.Group();
  const mat = new THREE.MeshStandardMaterial({ color: 0x9ff7c5, emissive: 0x3bf08a, emissiveIntensity: 2 });
  const a = new THREE.Mesh(new THREE.SphereGeometry(0.08, 24, 16), mat); a.position.x = -0.6;
  const b = a.clone(); b.position.x = 0.6;
  const line = cyl(0.015, 0.015, 1.2, mat, 8); line.rotation.z = Math.PI / 2;
  const l = makeLabel('TLS 1.3 接続成立\n（鍵は端末同士で共有）', { size: 0.13, accent: '#3bf08a' });
  l.position.y = 0.35;
  g.add(a, b, line, l);
  return g;
}

// ---------------------------------------------------------------------------
// 設備モデル（A09〜A23, A37〜A40）
// ---------------------------------------------------------------------------

// A09〜A11 ルートCA金庫・可動扉・鍵固定台
function makeVault() {
  const m = mats();
  const g = new THREE.Group();
  const body = rbox(1.6, 2.0, 1.2, m.darkSteel, 0.08); body.position.y = 1.0;
  const trim = rbox(1.66, 0.08, 1.26, m.root, 0.03); trim.position.y = 2.02;
  const base = rbox(1.8, 0.12, 1.4, m.black, 0.03); base.position.y = 0.06;
  // ボルト
  for (let i = 0; i < 6; i++) {
    for (const sx of [-0.72, 0.72]) {
      const bolt = cyl(0.025, 0.025, 0.02, m.steel, 12);
      bolt.rotation.x = Math.PI / 2; bolt.position.set(sx, 0.3 + i * 0.3, 0.61);
      g.add(bolt);
    }
  }
  // 可動扉（左端ヒンジ）
  const hinge = new THREE.Group(); hinge.position.set(-0.62, 1.0, 0.62);
  const door = rbox(1.24, 1.7, 0.12, m.steel, 0.05); door.position.x = 0.62;
  const wheel = new THREE.Mesh(new THREE.TorusGeometry(0.2, 0.03, 12, 40), m.darkSteel);
  wheel.position.set(0.62, 0, 0.09);
  for (let i = 0; i < 4; i++) {
    const spoke = box(0.4, 0.025, 0.025, m.darkSteel); spoke.rotation.z = (i * Math.PI) / 4; spoke.position.set(0.62, 0, 0.09);
    hinge.add(spoke);
  }
  const hub = cyl(0.06, 0.06, 0.06, m.root, 24); hub.rotation.x = Math.PI / 2; hub.position.set(0.62, 0, 0.1);
  const dial = cyl(0.09, 0.09, 0.04, m.black, 32); dial.rotation.x = Math.PI / 2; dial.position.set(0.3, 0.45, 0.08);
  hinge.add(door, wheel, hub, dial);
  // 内部の鍵固定台
  const fixture = rbox(0.6, 0.12, 0.5, m.black, 0.03); fixture.position.set(0, 0.9, 0.1);
  const glow = new THREE.PointLight(0xffc04a, 0.0, 2.5); glow.position.set(0, 1.4, 0.5);
  g.add(body, trim, base, hinge, fixture, glow);
  g.userData.door = hinge;
  g.userData.glow = glow;
  return g;
}

// A12 中間CA署名コンソール（押印ヘッド付き）
function makeSigningConsole() {
  const m = mats();
  const g = new THREE.Group();
  const desk = rbox(2.0, 0.9, 1.0, m.darkSteel, 0.06); desk.position.y = 0.45;
  const top = rbox(2.06, 0.06, 1.06, m.inter, 0.02); top.position.y = 0.92;
  const pillar = rbox(0.18, 1.1, 0.18, m.steel, 0.04); pillar.position.set(0, 1.5, -0.32);
  const arm = rbox(0.18, 0.14, 0.9, m.steel, 0.04); arm.position.set(0, 2.02, 0.05);
  const head = new THREE.Group(); head.position.set(0, 1.75, 0.48);
  const piston = cyl(0.05, 0.05, 0.4, m.steel, 20); piston.position.y = 0.0;
  const stamp = cyl(0.2, 0.22, 0.14, m.inter, 40); stamp.position.y = -0.24;
  const stampFace = cyl(0.2, 0.2, 0.02, m.black, 40); stampFace.position.y = -0.32;
  head.add(piston, stamp, stampFace);
  const pad = rbox(0.6, 0.03, 0.45, m.black, 0.01); pad.position.set(0, 0.965, 0.48);
  // 端末
  const monitor = makeMonitor(m.inter); monitor.position.set(-0.65, 0.95, -0.1); monitor.rotation.y = 0.25;
  const keySlot = rbox(0.5, 0.18, 0.35, m.black, 0.03); keySlot.position.set(0.7, 1.04, -0.2);
  const light = new THREE.PointLight(0xffb347, 0.0, 3); light.position.set(0, 1.4, 0.6);
  g.add(desk, top, pillar, arm, head, pad, monitor, keySlot, light);
  g.userData.head = head;
  g.userData.light = light;
  return g;
}

// A14・A15 モニターとキーボード
function makeMonitor(accentMat) {
  const m = mats();
  const g = new THREE.Group();
  const stand = cyl(0.04, 0.06, 0.25, m.darkSteel, 16); stand.position.y = 0.13;
  const foot = rbox(0.3, 0.02, 0.2, m.darkSteel, 0.01); foot.position.y = 0.01;
  const frame = rbox(0.62, 0.4, 0.04, m.black, 0.02); frame.position.y = 0.45;
  const screen = new THREE.Mesh(new THREE.PlaneGeometry(0.56, 0.34), m.screen); screen.position.set(0, 0.45, 0.021);
  const strip = box(0.62, 0.012, 0.042, accentMat ?? m.steel); strip.position.y = 0.25;
  const kb = rbox(0.5, 0.025, 0.17, m.black, 0.01); kb.position.set(0, 0.012, 0.25);
  for (let r = 0; r < 4; r++) {
    for (let c = 0; c < 12; c++) {
      const k = box(0.032, 0.012, 0.032, m.darkSteel); k.castShadow = false;
      k.position.set(-0.21 + c * 0.038, 0.03, 0.19 + r * 0.038);
      g.add(k);
    }
  }
  g.add(stand, foot, frame, screen, strip, kb);
  return g;
}

// A13 RA 申請カウンター
function makeRACounter() {
  const m = mats();
  const g = new THREE.Group();
  const counter = rbox(2.4, 1.05, 0.7, m.wallDark, 0.06); counter.position.y = 0.525;
  const top = rbox(2.5, 0.06, 0.85, m.ra, 0.02); top.position.y = 1.08;
  const front = box(2.2, 0.5, 0.02, m.ra); front.position.set(0, 0.55, 0.36);
  const monitor = makeMonitor(m.ra); monitor.position.set(-0.7, 1.11, -0.15);
  const tray = rbox(0.5, 0.05, 0.4, m.steel, 0.02); tray.position.set(0, 1.13, 0);
  const lamp = new THREE.Mesh(new THREE.SphereGeometry(0.07, 20, 14), m.lampOff.clone()); lamp.position.set(0.8, 1.25, -0.2);
  g.add(counter, top, front, monitor, tray, lamp);
  g.userData.lamp = lamp;
  return g;
}

// A16 HTTPS サーバーラック
function makeServerRack() {
  const m = mats();
  const g = new THREE.Group();
  const frame = rbox(1.0, 2.2, 1.0, m.black, 0.04); frame.position.y = 1.1;
  for (let i = 0; i < 8; i++) {
    const u = rbox(0.86, 0.18, 0.06, m.darkSteel, 0.015); u.position.set(0, 0.35 + i * 0.22, 0.49);
    const led = new THREE.Mesh(new THREE.SphereGeometry(0.018, 8, 8),
      new THREE.MeshStandardMaterial({ color: 0x00ff88, emissive: i % 3 ? 0x00c060 : 0x2f6fdb, emissiveIntensity: 2 }));
    led.position.set(0.36, 0.35 + i * 0.22, 0.53);
    for (let s = 0; s < 10; s++) {
      const slit = box(0.04, 0.1, 0.01, m.black); slit.castShadow = false;
      slit.position.set(-0.35 + s * 0.06, 0.35 + i * 0.22, 0.525);
      g.add(slit);
    }
    g.add(u, led);
  }
  const cap = rbox(1.04, 0.06, 1.04, m.server, 0.02); cap.position.y = 2.22;
  // 秘密鍵の固定台（鍵はサーバーから出ない）
  const keyStand = rbox(0.5, 0.9, 0.5, m.wallDark, 0.04); keyStand.position.set(-0.85, 0.45, 0.6);
  const keyTop = rbox(0.56, 0.05, 0.56, m.server, 0.02); keyTop.position.set(-0.85, 0.92, 0.6);
  const glass = new THREE.Mesh(new THREE.CylinderGeometry(0.22, 0.22, 0.45, 32, 1, true), m.glass); glass.position.set(-0.85, 1.17, 0.6);
  const term = makeMonitor(m.server); term.position.set(0.9, 0.0, 0.7); term.scale.setScalar(0.9);
  const termDesk = rbox(0.7, 0.8, 0.5, m.wallDark, 0.04); termDesk.position.set(0.9, 0.4, 0.75);
  term.position.y = 0.82;
  g.add(frame, cap, keyStand, keyTop, glass, termDesk, term);
  return g;
}

// A17 信頼ストア（引き出し付きキャビネット）
function makeTrustStore() {
  const m = mats();
  const g = new THREE.Group();
  const body = rbox(1.0, 0.9, 0.7, m.wallDark, 0.05); body.position.y = 0.45;
  const top = rbox(1.06, 0.05, 0.76, m.client, 0.02); top.position.y = 0.92;
  const drawer = new THREE.Group();
  const front = rbox(0.9, 0.3, 0.05, m.client, 0.02); front.position.set(0, 0.55, 0.36);
  const handle = rbox(0.3, 0.04, 0.05, m.steel, 0.015); handle.position.set(0, 0.55, 0.4);
  const tray = box(0.86, 0.04, 0.6, m.darkSteel); tray.position.set(0, 0.42, 0.06);
  drawer.add(front, handle, tray);
  const lower = rbox(0.9, 0.3, 0.05, m.wallDark, 0.02); lower.position.set(0, 0.2, 0.36);
  const label = makeLabel('信頼ストア\n（利用者が選んだルート）', { size: 0.12, accent: '#3aa35b' });
  label.position.set(0, 1.3, 0);
  g.add(body, top, drawer, lower, label);
  g.userData.drawer = drawer;
  return g;
}

// A18・A19 検証ゲート（左右の遮断部・ランプ・チェック端末）
function makeGate(index, info) {
  const m = mats();
  const g = new THREE.Group();
  const postMat = m.steel;
  const lp = rbox(0.18, 1.3, 0.5, m.darkSteel, 0.04); lp.position.set(0, 0.65, -0.55);
  const rp = lp.clone(); rp.position.z = 0.55;
  const arch = rbox(0.18, 0.12, 1.3, postMat, 0.04); arch.position.set(0, 1.36, 0);
  const lampMat = m.lampOff.clone();
  const lamp = new THREE.Mesh(new THREE.SphereGeometry(0.09, 24, 16), lampMat); lamp.position.set(0, 1.5, 0);
  const leftPivot = new THREE.Group(); leftPivot.position.set(0, 0.7, -0.45);
  const lb = rbox(0.06, 0.5, 0.44, m.glass, 0.02); lb.position.z = 0.22; lb.material = lb.material.clone();
  lb.material.opacity = 0.45; lb.material.color = new THREE.Color(0x9fb8d6);
  leftPivot.add(lb);
  const rightPivot = new THREE.Group(); rightPivot.position.set(0, 0.7, 0.45);
  const rb = lb.clone(); rb.position.z = -0.22;
  rightPivot.add(rb);
  const plate = makeLabel(`${'①②③④⑤⑥'[index]} ${info.label}`, { size: 0.13, accent: '#ffffff' });
  plate.position.set(0, 2.75, 0);
  const pointLight = new THREE.PointLight(0xffffff, 0, 2.2); pointLight.position.set(0.3, 1.4, 0);
  g.add(lp, rp, arch, lamp, leftPivot, rightPivot, plate, pointLight);
  g.userData = { lamp, lampMat, leftPivot, rightPivot, pointLight, barrierMat: lb.material };
  return g;
}

// A20 CRL 配布キャビネット
function makeCRLCabinet() {
  const m = mats();
  const g = new THREE.Group();
  const body = rbox(1.4, 1.6, 0.8, m.wallDark, 0.05); body.position.y = 0.8;
  const top = rbox(1.46, 0.06, 0.86, m.crl, 0.02); top.position.y = 1.62;
  for (let i = 0; i < 4; i++) {
    const d = rbox(1.25, 0.32, 0.05, i === 3 ? m.crl : m.darkSteel, 0.02); d.position.set(0, 0.25 + i * 0.38, 0.41);
    const h = rbox(0.25, 0.03, 0.04, m.steel, 0.01); h.position.set(0, 0.25 + i * 0.38, 0.45);
    g.add(d, h);
  }
  const board = makeCRLBoard(1); board.position.set(0, 2.0, 0); board.scale.setScalar(1.6);
  const boardNew = makeCRLBoard(2); boardNew.position.set(0, 2.0, 0.01); boardNew.scale.setScalar(1.6); boardNew.visible = false;
  const light = new THREE.PointLight(0xb08cff, 0, 3); light.position.set(0, 2.0, 1.0);
  g.add(body, top, board, boardNew, light);
  g.userData = { board, boardNew, light };
  return g;
}

// A21 OCSP 比較キオスク（本編の外に置く比較展示）
function makeOCSPKiosk() {
  const m = mats();
  const g = new THREE.Group();
  const base = rbox(0.8, 1.1, 0.6, m.ocsp, 0.06); base.position.y = 0.55;
  const head = rbox(0.9, 0.6, 0.12, m.black, 0.04); head.position.set(0, 1.45, 0.05); head.rotation.x = -0.2;
  const screen = new THREE.Mesh(new THREE.PlaneGeometry(0.8, 0.5), m.screen); screen.position.set(0, 1.46, 0.12); screen.rotation.x = -0.2;
  const discs = [['good', 0x3aa35b], ['revoked', 0xd92b3a], ['unknown', 0x8a8f99]].map(([l, c], i) => {
    const d = makeOCSPDisk(l, c); d.position.set(-0.45 + i * 0.45, 2.1, 0); return d;
  });
  const label = makeLabel('OCSP（比較展示）\ngood でも「証明書全体が有効」ではない', { size: 0.1, accent: '#5b6b84' });
  label.position.set(0, 2.55, 0);
  g.add(base, head, screen, label, ...discs);
  return g;
}

// A22 監査記録キャビネット
function makeAuditCabinet() {
  const m = mats();
  const g = new THREE.Group();
  const body = rbox(1.2, 1.9, 0.5, m.wallDark, 0.04); body.position.y = 0.95;
  for (let r = 0; r < 4; r++) {
    const shelf = box(1.1, 0.03, 0.45, m.steel); shelf.position.set(0, 0.3 + r * 0.45, 0.02);
    g.add(shelf);
    for (let b = 0; b < 9; b++) {
      const binder = box(0.08, 0.32, 0.36, b % 2 ? m.ra : m.inter); binder.castShadow = false;
      binder.position.set(-0.45 + b * 0.11, 0.47 + r * 0.45, 0.04);
      g.add(binder);
    }
  }
  const light = new THREE.PointLight(0x7af0e0, 0, 2.5); light.position.set(0, 1.2, 0.8);
  const label = makeLabel('監査記録（ハッシュ連鎖）', { size: 0.11, accent: '#1f9e8f' });
  label.position.set(0, 2.2, 0);
  g.add(body, light, label);
  g.userData.light = light;
  return g;
}

// A37 案内・運用ロボット（剛体パーツ）
function makeRobot(accent, name) {
  const m = mats();
  const g = new THREE.Group();
  const accentMat = accent;
  const base = cyl(0.25, 0.3, 0.12, m.darkSteel, 32); base.position.y = 0.06;
  const body = new THREE.Mesh(new THREE.CapsuleGeometry(0.22, 0.45, 8, 24), m.robot); body.position.y = 0.55; body.castShadow = true;
  const belt = cyl(0.225, 0.225, 0.06, accentMat, 32); belt.position.y = 0.5;
  const headG = new THREE.Group(); headG.position.y = 1.1;
  const head = rbox(0.42, 0.3, 0.34, m.robot, 0.1);
  const visor = rbox(0.34, 0.12, 0.05, m.visor, 0.03); visor.position.set(0, 0.02, 0.16);
  const ant = cyl(0.01, 0.01, 0.15, m.steel, 8); ant.position.y = 0.22;
  const tip = new THREE.Mesh(new THREE.SphereGeometry(0.03, 12, 8), accentMat); tip.position.y = 0.3;
  headG.add(head, visor, ant, tip);
  const armL = new THREE.Group(); armL.position.set(-0.27, 0.78, 0);
  const al = new THREE.Mesh(new THREE.CapsuleGeometry(0.05, 0.3, 4, 12), m.robot); al.position.y = -0.18; al.castShadow = true;
  armL.add(al);
  const armR = armL.clone(); armR.position.x = 0.27;
  const tag = makeLabel(name, { size: 0.1, accent: '#' + accentMat.color.getHexString() });
  tag.position.y = 1.55;
  g.add(base, body, belt, headG, armL, armR, tag);
  g.userData = { head: headG, armL, armR };
  return g;
}

// A38 見学用ベンチ
function makeBench() {
  const m = mats();
  const g = new THREE.Group();
  const seat = rbox(1.6, 0.08, 0.45, m.wood, 0.03); seat.position.y = 0.45;
  for (const x of [-0.65, 0.65]) { const l = rbox(0.08, 0.42, 0.4, m.darkSteel, 0.02); l.position.set(x, 0.21, 0); g.add(l); }
  g.add(seat);
  return g;
}

// A07 境界ポールとロープ
function makePost() {
  const m = mats();
  const g = new THREE.Group();
  const base = cyl(0.12, 0.14, 0.04, m.darkSteel, 24); base.position.y = 0.02;
  const pole = cyl(0.03, 0.03, 0.9, m.steel, 16); pole.position.y = 0.47;
  const cap = new THREE.Mesh(new THREE.SphereGeometry(0.045, 16, 12), m.steel); cap.position.y = 0.94;
  g.add(base, pole, cap);
  return g;
}

// ---------------------------------------------------------------------------
// 空間の組み立て
// ---------------------------------------------------------------------------
export const CATALOG = [
  { id: 'A01-A08', name: '展示基壇・床・壁・ガラス間仕切り・照明', station: 'overview', desc: '28m×20m の屋根なし展示施設。発行側（奥）と利用側（手前）を分ける。' },
  { id: 'A09-A11', name: 'ルートCA金庫・可動扉・鍵固定台', station: 'rootVault', desc: 'ルート鍵は金庫から出ない。中間CAへの署名のときだけ扉が開く。' },
  { id: 'A12', name: '中間CA署名コンソール', station: 'intermediate', desc: '押印ヘッドは電子署名のたとえ。CSR の拡張はコピーしない。' },
  { id: 'A13', name: 'RA 申請カウンター', station: 'ra', desc: 'CSR の署名確認と、名前を使う権限の確認を分けて行う窓口。' },
  { id: 'A16', name: 'HTTPS サーバーラック', station: 'server', desc: 'サーバー秘密鍵はガラスケースの中に固定。CA へ送らない。' },
  { id: 'A14-A15,A17', name: '利用者端末・信頼ストア', station: 'trust', desc: '利用者が自分で選んだルートだけが信頼の起点になる。' },
  { id: 'A18-A19', name: '検証ゲート ×6', station: 'gate2', desc: '端末内部の確認を見学できる大きさに拡大した比喩。' },
  { id: 'A20,A30', name: 'CRL 配布キャビネット・一覧ボード', station: 'crl', desc: '失効の登録 → 配布 → 利用側の確認。' },
  { id: 'A21,A31', name: 'OCSP 比較キオスク・応答ディスク', station: 'ocsp', desc: 'good / revoked / unknown を区別する比較展示（本編の外）。' },
  { id: 'A22', name: '監査記録キャビネット', station: 'audit', desc: '承認 ⇔ 台帳 ⇔ 証明書 ⇔ 失効 ⇔ CRL を照合する。' },
  { id: 'A24-A25', name: '秘密鍵（金）・公開鍵（青）', station: 'server', desc: '金の鍵は象徴。どの場面でも移動しない。' },
  { id: 'A26-A29', name: 'CSR・証明書カード（ルート／中間／サーバー）', station: 'intermediate', desc: 'カード表面に主要な項目を表示。' },
  { id: 'A32-A36', name: 'チェーン環・承認バッジ・期限クロック・遮断パネル', station: 'gate4', desc: '検証の結果を見える形にする補助教材。' },
  { id: 'A37', name: '案内・運用ロボット ×4', station: 'ra', desc: 'ルート管理者・発行担当・RA・利用者の役割を示す。' },
];

export function buildWorld(scene) {
  const m = mats();
  const S = (k) => new THREE.Vector3(...STATIONS[k]);

  // A01 展示基壇・A02 床タイル
  const base = rbox(30, 0.4, 22, m.plinth, 0.15); base.position.y = -0.2; base.castShadow = false;
  scene.add(base);
  const tiles = new THREE.InstancedMesh(new THREE.BoxGeometry(1.96, 0.02, 1.96), m.tile, 14 * 10);
  let n = 0;
  const mtx = new THREE.Matrix4();
  for (let x = 0; x < 14; x++) for (let z = 0; z < 10; z++) {
    mtx.makeTranslation(-13 + x * 2, 0.011, -9 + z * 2); tiles.setMatrixAt(n++, mtx);
  }
  tiles.receiveShadow = true;
  scene.add(tiles);

  // 区画の床色（ゾーン）
  const zone = (x, z, w, d, mat) => {
    const p = new THREE.Mesh(new THREE.PlaneGeometry(w, d), mat.clone());
    p.material.transparent = true; p.material.opacity = 0.22; p.material.depthWrite = false;
    p.rotation.x = -Math.PI / 2; p.position.set(x, 0.03, z); p.receiveShadow = true;
    scene.add(p);
  };
  zone(-11, -6, 5, 6, m.root); zone(-5, -6, 5.5, 6, m.inter); zone(2, -6, 5.5, 6, m.server);
  zone(9, -6, 5.5, 6, m.crl); zone(-8, 4.8, 6, 5, m.ra); zone(0, 5.4, 4.5, 5, m.client);
  zone(8.4, 5, 10.5, 3.2, m.wallDark);

  // A03 壁パネル（奥）・A06 線状照明
  for (let i = 0; i < 7; i++) {
    const w = rbox(3.9, 3.0, 0.2, m.wall, 0.03); w.position.set(-12 + i * 4, 1.5, -9.8);
    const lt = box(3.4, 0.05, 0.08, m.light); lt.position.set(-12 + i * 4, 2.9, -9.65); lt.castShadow = false;
    scene.add(w, lt);
  }
  const sideL = rbox(0.2, 3.0, 8, m.wall, 0.03); sideL.position.set(-14.4, 1.5, -5.8);
  scene.add(sideL);

  // A04 ガラス間仕切り（発行側の区画を区切る）
  for (const x of [-8.1, -1.6, 5.5]) {
    const glass = new THREE.Mesh(new THREE.BoxGeometry(0.04, 2.4, 5.4), m.glass); glass.position.set(x, 1.2, -6.5);
    const frameTop = box(0.08, 0.06, 5.4, m.steel); frameTop.position.set(x, 2.42, -6.5);
    const frameBottom = box(0.08, 0.06, 5.4, m.steel); frameBottom.position.set(x, 0.05, -6.5);
    scene.add(glass, frameTop, frameBottom);
  }
  // ルートCA室は四方をガラスで囲み「通常は隔離」を表す
  const rootGlass = new THREE.Mesh(new THREE.BoxGeometry(5.2, 2.4, 0.04), m.glass); rootGlass.position.set(-11, 1.2, -3.1);
  scene.add(rootGlass);

  // A05 入口フレーム
  const entry = new THREE.Group();
  const eL = rbox(0.25, 3.2, 0.25, m.steel, 0.05); eL.position.set(-1.8, 1.6, 9.6);
  const eR = eL.clone(); eR.position.x = 1.8;
  const eT = rbox(3.85, 0.3, 0.3, m.steel, 0.05); eT.position.set(0, 3.25, 9.6);
  const eLabel = makeLabel('信頼のアトリエ — CA の発行・検証・失効', { size: 0.24, accent: '#e0a526' });
  eLabel.position.set(0, 3.8, 9.6);
  entry.add(eL, eR, eT, eLabel);
  scene.add(entry);

  // A07 境界ポール（利用側の内部展示を囲う）
  for (let i = 0; i < 9; i++) {
    const p = makePost(); p.position.set(3.4 + i * 1.25, 0, 6.9); scene.add(p);
    const q = makePost(); q.position.set(3.4 + i * 1.25, 0, 3.1); scene.add(q);
  }

  // ---- 区画ごとの設備 ----
  const vault = makeVault(); vault.position.copy(S('rootVault')).setY(0); scene.add(vault);
  const signing = makeSigningConsole(); signing.position.copy(S('intermediate')).setY(0); signing.position.z -= 0.6; scene.add(signing);
  const audit = makeAuditCabinet(); audit.position.copy(S('audit')).setY(0); scene.add(audit);
  const rack = makeServerRack(); rack.position.copy(S('server')).setY(0); rack.position.z -= 1.2; rack.position.x += 0.4; scene.add(rack);
  const crlCab = makeCRLCabinet(); crlCab.position.copy(S('crl')).setY(0); crlCab.position.z -= 0.7; scene.add(crlCab);
  const ra = makeRACounter(); ra.position.copy(S('ra')).setY(0); ra.position.z -= 0.6; scene.add(ra);
  const ocsp = makeOCSPKiosk(); ocsp.position.copy(S('ocsp')).setY(0); ocsp.rotation.y = -0.6; scene.add(ocsp);
  const trust = makeTrustStore(); trust.position.copy(S('trust')).setY(0); trust.rotation.y = 0.3; scene.add(trust);
  const clientDesk = rbox(1.4, 0.75, 0.7, m.wallDark, 0.05); clientDesk.position.set(STATIONS.client[0], 0.375, STATIONS.client[2] + 0.2);
  const clientMon = makeMonitor(m.client); clientMon.position.set(STATIONS.client[0], 0.76, STATIONS.client[2] + 0.1);
  scene.add(clientDesk, clientMon);

  // 区画名
  const zoneLabels = [
    ['rootVault', 'ルートCA室（通常は隔離）', '#b3263a', 3.0],
    ['intermediate', '中間CA室（発行用）', '#e08a1e', 3.0],
    ['server', 'HTTPS サーバー区画', '#2f6fdb', 3.0],
    ['crl', '失効情報（CRL 配布）', '#7d4bd1', 3.3],
    ['ra', '申請窓口（RA）', '#1f9e8f', 2.3],
    ['client', '利用者端末（ブラウザ）', '#3aa35b', 2.3],
  ];
  const fadeLabels = [];
  for (const [k, text, color, y] of zoneLabels) {
    const l = makeLabel(text, { size: 0.24, accent: color });
    l.position.copy(S(k)).setY(y);
    scene.add(l); fadeLabels.push(l);
  }
  const insideLabel = makeLabel('利用者端末の内部（拡大展示）\n※ 並び順は説明用', { size: 0.17, accent: '#ffffff' });
  insideLabel.position.set(8.1, 3.4, 5);
  scene.add(insideLabel); fadeLabels.push(insideLabel);

  // ---- 固定された秘密鍵（どの場面でも移動しない） ----
  const keys = {};
  const placeKey = (name, p) => { const k = makePrivateKey(); k.position.copy(p); k.rotation.y = 0.4; scene.add(k); keys[name] = k; return k; };
  placeKey('root', new THREE.Vector3(STATIONS.rootVault[0], 1.06, STATIONS.rootVault[2] + 0.1));
  placeKey('intermediate', new THREE.Vector3(STATIONS.intermediate[0] + 0.7, 1.18, STATIONS.intermediate[2] - 0.8));
  placeKey('server', new THREE.Vector3(STATIONS.server[0] - 0.45, 1.15, STATIONS.server[2] - 0.6));

  // 中間CA室に置かれる中間CA証明書（委任後）・ルート証明書は金庫内
  const rootCertInVault = makeCertCard('root'); rootCertInVault.position.set(STATIONS.rootVault[0] - 0.4, 2.35, STATIONS.rootVault[2] + 0.2);
  scene.add(rootCertInVault);

  // ---- 動くトークン ----
  const tokens = {
    intCert: makeCertCard('inter'),
    rootCertCopy: makeCertCard('root'),
    pubKey: makePublicKey(),
    csr: makeCSRFolder(),
    approval: makeApprovalBadge(),
    leaf: makeCertCard('leaf'),
    chainCopy: makeCertCard('inter'),
    crlFetch: makeCRLBoard(1),
    crlNew: makeCRLBoard(2),
  };
  for (const t of Object.values(tokens)) { t.visible = false; t.scale.setScalar(1.6); scene.add(t); }
  // チェーン接続環（葉と中間をつなぐ）
  const link = makeChainLink(); link.visible = false; scene.add(link);

  // ---- 検証ゲート ----
  const gates = GATES.map((info, i) => {
    const gte = makeGate(i, info);
    gte.position.copy(S(`gate${i}`)).setY(0);
    scene.add(gte);
    const panel = makeRejectPanel(); panel.position.copy(S(`gate${i}`)).setY(0.9); panel.position.x += 0.15;
    panel.rotation.y = -Math.PI / 2; panel.visible = false; scene.add(panel);
    return { group: gte, panel, ...gte.userData };
  });
  const clock = makeClock(); clock.position.set(STATIONS.gate2[0], 2.35, STATIONS.gate2[2]); scene.add(clock);
  const tls = makeTLSSpark(); tls.position.set(STATIONS.gate5[0], 2.5, STATIONS.gate5[2]); tls.visible = false; scene.add(tls);

  // ---- ロボット ----
  const robots = [
    makeRobot(m.root, 'ルートCA管理者'), makeRobot(m.inter, '発行担当'),
    makeRobot(m.ra, 'RA 審査担当'), makeRobot(m.client, '利用者'),
  ];
  const robotPos = [[-12.8, -4.5, 0.6], [-6.8, -4.6, 0.5], [-9.7, 4.3, 0.9], [2.2, 6.8, -0.8]];
  robots.forEach((r, i) => { r.position.set(robotPos[i][0], 0, robotPos[i][1]); r.rotation.y = robotPos[i][2]; scene.add(r); });

  // A38 ベンチ・A39 床配線トレイ
  for (const [x, z] of [[-4, 8.4], [5, 8.4]]) { const b = makeBench(); b.position.set(x, 0, z); scene.add(b); }
  const tray = box(18, 0.04, 0.25, m.darkSteel); tray.position.set(-1.5, 0.04, -2.6); tray.castShadow = false; scene.add(tray);

  return {
    tokens, link, gates, clock, tls, keys, robots, fadeLabels,
    parts: { vault, signing, audit, crlCab, ra, trust },
    focus: Object.fromEntries(Object.keys(STATIONS).map((k) => [k, S(k)])),
  };
}
