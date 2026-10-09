# Round 4：CA回帰修正と分割GLBの統合

基準コミット：`148518016f8996ffd1c55bbfa3cc87dd17fef8eb`。

## 結論

4件の既知失敗を「すべて古いテスト」とは扱わない。3件は新しい出力・明示確認仕様に合わせてテストを更新した。残る1件は実装のイベント名変更に追従していない不具合だった。追加試験で、両CRL欠落時に正しい署名済み証明書まで失効させる経路も検出して修正した。

3Dは従来の軽量表示を残し、40種類の分割GLBを使うバランス版（LOD1・共有2K）と高精細版（LOD0・共有4K）を追加した。美術の最終受入れやAAA完成を宣言したものではない。

## 1. 4件の切り分け

| 旧テスト | 分類 | 対応と維持した安全条件 |
|---|---|---|
| `test_resume_without_reachable_source_requires_explicit_decisions` | テスト手順のずれ | 明示的な偽のsourceは拒否を維持する。元環境を本当に到達不能にした演習でのみ、元環境停止と古い状態受入れの明示確認を試す。 |
| `test_tampered_source_log_is_not_evidence_of_freshness` | 出力階層の変更 | `checks.source`の監査異常と`checks.state`の状態不一致を両方確認する。`ready=false`を維持する。 |
| `test_missing_crls_detected_even_without_revocations` | 整合性と修復項目の分離 | CRL欠落は修復可能な`actions`だが、全体は失敗終了のまま。両CRL更新後に正常へ戻ることまで試す。 |
| `test_events_follow_observed_granularity` | **本体の不具合** | 失効完了の監査名が`revoke-completed`へ変わったのにExporterが旧名だけを参照していた。発行元のscopeを見て葉／中間の完了イベントへ正しく対応する。 |

`--accept-stale`を一般的な安全回復手順として推奨しない。履歴を失った古いCAを使い続ける判断には、失効状態の巻き戻りという重大な危険がある。本ラボでは、明示的にその制限を理解した隔離演習のための操作として残している。

## 2. 追加修正：署名後の両CRL欠落

空のCRLファイルをOpenSSLへ渡すと、ファイル解析の失敗が一般エラーになり、永続的な不正証明書と誤分類される経路があった。

CRL内容が空なら`-CRLfile`を省略する一方、`-crl_check`と`-crl_check_all`は常に要求する。CRLがない状態は成功にならず、修復待ちとして止まる。正しい証明書は`ISSUED`のまま残し、CRL更新後に同じシリアルで公開を再開する。検証を無効化する修正ではない。

## 3. 追加した6つの回帰試験

`lab/tests/test_round4.py`は使い捨て環境で実際のCLI、鍵、CSR、証明書、CRLを使う。

1. 葉の失効完了が1件だけ出力される。失効確認でも拒否される。
2. 中間CA失効は葉の失効と混同されず、Root側の完了として出る。
3. CRL公開失敗では完了イベントを出さず、再試行成功後に1件だけ出る。
4. 署名後に両CRLが欠落しても正しい葉を失効させない。更新後に同じシリアルで再開する。
5. 監査完了記録がない状態変更も、状態の指紋比較で検出する。
6. 新規署名前に両CRLがない場合は署名せず、申請を勝手に隔離しない。

## 4. 3Dの実装

| 表示モード | 読み込むモデル | 材質 | 用途 |
|---|---|---|---|
| 軽量教材 | 既存のコード生成モデル | 既存材質 | 初回・低負荷向け |
| バランス | A01〜A40、LOD1 | 共有2K Base Color／Normal／ORM | 学習空間の標準的な高品質表示 |
| 高精細 | A01〜A40、LOD0 | 共有4K Base Color／Normal／ORM | 接写確認・制作確認 |

`viz/js/atlas-world.js`が実際のGLBを読み込み、既存の`lessonState`を可動部へ反映する。証明書カード、CRL、信頼ストアは既存の条件データを使う。秘密鍵の象徴は固定し、実鍵データやCA操作APIとは接続しない。

共有アトラスの材質をモデル間で再利用する。床・壁・照明・ポールなどの反復配置にはInstancedMeshを使う。LODは利用者が選ぶ2段階であり、距離に応じた自動LODではない。

追加したモデル詳細は、金庫の取付金具、署名装置のパネル・ボタン、ラック取付レール、信頼ストアの引出し内部、案内ロボットのサービスパネル。既存形状を基にした改良であり、80種類の独立新規造形という意味ではない。

単体確認は`viz/models.html`。40種類の選択、LOD切替、6モデルの埋込クリップ、ワイヤーフレーム、外形寸法の表示を用意した。

## 5. 実行

リポジトリのルートで実行する。CAデモはLinux／WSL2の隔離環境を使う。

```bash
python3 -m unittest discover -s lab/tests -v
(cd viz && npm test)
python3 -m http.server 8765 --bind 127.0.0.1 --directory viz
```

ブラウザで `http://127.0.0.1:8765/?quality=balanced&autoplay=0` を開く。
高精細は `quality=hero`。単体は `http://127.0.0.1:8765/models.html`。

正常時は「分割GLB 40種」と表示される。モデルの読み込みに失敗した場合は成功に見せかけず、読込失敗を表示する。`file://`でHTMLを直接開く操作は対象外。

CLIテストの正常例は全試験OK。拒否を期待する試験で`ACCEPT`した場合も不合格。画面が見えるだけで秘密情報保護やモデル品質が検証されたとは判断しない。

## 6. 資産の再生成と検査

生成前に編集済みGLBを別途保管する。`tools/build_atlas.py`の出力先は生成物専用とし、手作業で編集したモデルの保管先へ向けない。既存catalogのない未知の出力先は上書きしない。

```bash
python3 -m pip install -r tools/requirements-art.txt
python3 tools/build_atlas.py
python3 tools/check_atlas.py
```

正常例：40種×2LODの生成成功と80 GLBの検査成功。異常例：ハッシュ不一致、画像参照切れ、非有限の頂点、範囲外インデックス、無面積の面。異常時は生成物を配布せず原因を修正する。

検査は本プロジェクト独自のもの。Khronos公式Validatorを実行したという意味ではない。

## 7. 検証実績と制限

今回の実コードによるローカル検証はPython 3.13.5、OpenSSL 3.5.5、Node.js 22.16.0。CAは86件、既存3Dロジックは15件が成功した。End-to-Endデモも最後まで実行した。これらは抽出関数だけの試験ではなく、取得したリポジトリの実装を使った。

コンテナーのブラウザはHTTPページへの通常遷移を制限するため、実描画のローカル確認ではファイルをメモリ経由で配信した。Chromium 144／SwiftShaderで実GLBとPBR画像を読み込み、実際のWebGL描画を確認した。URLパラメーターだけをテスト用に注入した。通常HTTP経由の操作とは区別する。CIには別途、HTTP経由でAtlas空間と単体ビューアを確認する試験を追加した。CIの最終結果はコミットにひも付いた実行ログで確認する。

## 8. 残る問題と受入れ条件

**美術品質はまだ最終段階ではない。** 固有UV、手作業の表面調整、実物材質との比較、接写での粗さと汚れの仕上げが残る。4Kや三角形数だけをAAAの根拠にしない。

**実GPUの負荷は未測定。** SwiftShaderの描画成功は端末FPSの保証ではない。KTX2、Meshopt、距離LOD、端末別のVRAM・フレーム時間測定は今後の工程。

**CAは学習専用のまま。** HTTPによるCRL取得・伝播、物理的なオフラインRoot、HSM、独立監査は未完了。今回の修正で他の境界条件まで全件安全と認定しない。

## 9. 参考一次資料

- OpenSSL CA: https://docs.openssl.org/3.5/man1/openssl-ca/
- OpenSSL verification: https://docs.openssl.org/3.5/man1/openssl-verification-options/
- Three.js GLTFLoader: https://threejs.org/docs/#examples/en/loaders/GLTFLoader
- glTF 2.0: https://registry.khronos.org/glTF/specs/2.0/glTF-2.0.html

三次元の鍵・証明書・金庫は説明用の比喩であり、暗号操作や物理的なセキュリティを保証する設備ではない。
