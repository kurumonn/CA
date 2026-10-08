// 教材ロジックの試験: node --test viz/tests/
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DURATION, SCENES, SCENARIOS, GATES, STATIONS, lessonState, buildTracks, parseEvents, sample, EVENT_TO_SCENE,
} from '../js/lesson.js';

const times = (step = 0.25) => Array.from({ length: DURATION / step + 1 }, (_, i) => i * step);

test('18場面が0〜180秒を隙間なく覆う', () => {
  assert.equal(SCENES.length, 18);
  SCENES.forEach((s, i) => assert.equal(s.t, i * 10));
  for (const s of SCENES) {
    assert.ok(s.title && s.short && s.detail, s.title);
  }
});

test('全シナリオが結果コードと説明を持つ', () => {
  for (const [k, sc] of Object.entries(SCENARIOS)) {
    assert.ok(sc.label && sc.outcome && sc.verdict && sc.summary, k);
    const end = lessonState(DURATION, k);
    assert.deepEqual([end.result.verdict, end.result.code], [sc.verdict, sc.outcome], k);
  }
});

test('秘密鍵は軌跡を持たない（移動しない）', () => {
  for (const k of Object.keys(SCENARIOS)) {
    const names = Object.keys(buildTracks(k));
    assert.ok(!names.some((n) => /key/i.test(n) && n !== 'pubKey'), names.join(','));
  }
});

test('ルート証明書はサーバーから届かない（利用者が別経路で受け取る）', () => {
  const tr = buildTracks('lesson').rootCertCopy;
  const near = (p, station) => Math.hypot(p[0] - STATIONS[station][0], p[2] - STATIONS[station][2]) < 1.2;
  assert.ok(near(tr[0].at, 'rootVault'));
  assert.ok(near(tr[tr.length - 1].at, 'trust'));
  for (const kf of tr) if (kf.at) assert.ok(!near(kf.at, 'server'));
  // サーバーから送られるのは葉と中間CAのコピーだけ
  assert.ok(near(buildTracks('lesson').chainCopy[0].at, 'server'));
});

test('失敗シナリオは指定ゲートで止まり、以降のゲートは評価しない', () => {
  for (const [k, sc] of Object.entries(SCENARIOS)) {
    if (sc.failAt === null) continue;
    const end = lessonState(DURATION, k);
    const g = end.gates[sc.failAt];
    assert.equal(g.state, sc.verdict === 'INDETERMINATE' ? 'indeterminate' : 'fail', k);
    for (let i = sc.failAt + 1; i < GATES.length; i++) assert.equal(end.gates[i].state, 'skipped', k);
    for (let i = 0; i < sc.failAt; i++) assert.equal(end.gates[i].state, 'pass', k);
    const leaf = end.tokens.leaf.p;
    assert.ok(Math.abs(leaf[0] - (STATIONS[`gate${sc.failAt}`][0] - 0.55)) < 1e-9, k);
    assert.ok(end.tokens.chainCopy.p[1] - leaf[1] >= 0.55, '葉と中間のカードが重ならない');
  }
});

test('CRL が古い場合は「失効」ではなく「判定不能」', () => {
  const end = lessonState(DURATION, 'crlExpired');
  assert.equal(end.result.verdict, 'INDETERMINATE');
  assert.notEqual(end.result.code, 'LEAF_REVOKED');
});

test('本編：最初の接続は成功し、失効後の新規接続だけ拒否', () => {
  const mid = lessonState(165, 'lesson');
  assert.deepEqual([mid.result.verdict, mid.result.code], ['ACCEPT', 'OK']);
  assert.ok(mid.gates.every((g) => g.state === 'pass'));
  const end = lessonState(DURATION, 'lesson');
  assert.equal(end.gates[4].state, 'fail');
  assert.equal(end.gates[5].state, 'idle');
  assert.equal(end.result.code, 'LEAF_REVOKED');
  assert.ok(end.tokens.crlNew, '新しい CRL が配布される');
});

test('正常シナリオは全ゲート通過・TLS成立', () => {
  const end = lessonState(DURATION, 'normal');
  assert.ok(end.gates.every((g) => g.state === 'pass'));
  assert.equal(end.result.verdict, 'ACCEPT');
});

test('トークン位置は常に有限値で、床の範囲内', () => {
  for (const k of Object.keys(SCENARIOS)) {
    for (const t of times(0.5)) {
      const st = lessonState(t, k);
      for (const [name, v] of Object.entries(st.tokens)) {
        if (!v) continue;
        assert.ok(v.p.every(Number.isFinite), `${k} ${name} ${t}`);
        assert.ok(Math.abs(v.p[0]) <= 14 && Math.abs(v.p[2]) <= 10 && v.p[1] > 0 && v.p[1] < 8, `${k} ${name} ${t} ${v.p}`);
      }
      for (const val of Object.values(st.parts)) assert.ok(val >= 0 && val <= 1.6 + 1e-9);
    }
  }
});

test('sample: 非表示と補間', () => {
  const tr = [{ t: 0, at: [0, 0, 0] }, { t: 2, at: [2, 0, 0], move: true, arc: 0 }, { t: 3, at: null, hide: true }];
  assert.equal(sample(tr, -1), null);
  assert.deepEqual(sample(tr, 1).p, [1, 0, 0]);
  assert.equal(sample(tr, 3.5), null);
});

test('実測イベントの読込：形式確認と秘密情報の拒否', () => {
  const doc = { schema: 'pkilab-events/1', measured: true, events: [{ seq: 1, type: 'CERT_ISSUED', ts: 'x', role: 'issuer', result: 'ok' }] };
  const ev = parseEvents(doc);
  assert.equal(ev[0].scene, EVENT_TO_SCENE.CERT_ISSUED);
  assert.equal(ev[0].measured, true);
  assert.throws(() => parseEvents({ schema: 'x' }));
  assert.throws(() => parseEvents({ ...doc, events: [{ type: '-----BEGIN PRIVATE KEY-----' }] }));
});
