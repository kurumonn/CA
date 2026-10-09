# 自分だけの認証局（CA）— 学習用 PKI ラボと3D教材

ルートCA → 中間CA → localhost 用サーバー証明書の3階層を自分で構築し、
**発行・審査・失効・検証・監査・復旧**までを試せる学習用の私設CAと、
その流れを three.js の3Dアニメーションで見られる教材「信頼のアトリエ」です。

> 学習用です。公開認証局として運用できるものではありません。
> 本人確認、HSM、独立監査、CRL の継続配布、OCSP などは対象外です。

![信頼のアトリエ](articles/images/atelier-01-overview.png)

## 構成

| ディレクトリ | 内容 |
|---|---|
| [`lab/`](lab/) | CA を操作する CLI `pkilab.py`（Python 標準ライブラリ＋OpenSSL）、OpenSSL 設定、デモ、自動テスト |
| [`viz/`](viz/) | three.js の3D学習空間（three.js r169 同梱・CDN 不要） |
| [`docs/`](docs/) | 要件定義・基本設計・詳細設計・受入試験・3D空間設計 |
| [`articles/`](articles/) | ブログ記事の原稿（解説2本・日記1本）と画像 |

## すぐ試す

必要なもの: Python 3.9 以上、OpenSSL 3.x（Linux / WSL2 / macOS）

```bash
bash lab/scripts/demo.sh
```

CA 構築 → 申請 → RA 審査 → 発行 → 検証 → HTTPS 接続 → 失効 → 失効確認あり／なしの比較 → 監査・照合 → 3D 用イベント出力 までを順に実行します。作業ディレクトリ `lab/work/`（秘密鍵が作られる。Git 管理外）をやり直す場合は、既存の鍵・台帳・失効情報を保全し、別の空ディレクトリを指定してください。既存CAを安易に削除しないでください。

### 1つずつ操作する

```bash
cd lab
python3 pkilab.py init                         # ルートCA・中間CA・初期CRL
python3 pkilab.py request                      # [server-admin] 鍵とCSRを作って申請
python3 pkilab.py approve <REQ-ID>             # [ra] 審査・承認
python3 pkilab.py issue <REQ-ID>               # [issuer] 発行（冪等）
python3 pkilab.py verify --request <REQ-ID>    # [verifier] 証明書検証（CRL込み）
python3 pkilab.py serve-https <REQ-ID>         # [server-admin] 127.0.0.1:8443
python3 pkilab.py client                       # [verifier] 厳格な TLS 1.3 クライアント
python3 pkilab.py revoke <REQ-ID> --reason keyCompromise   # 失効＋CRL再発行
python3 pkilab.py revoke-intermediate          # [root-admin] 中間CAの失効
python3 pkilab.py init-issuer --new-generation # 失効した中間CAから新しい鍵の世代へ
python3 pkilab.py recover <REQ-ID>             # 止まった発行を台帳と照合して再開（再署名しない）
python3 pkilab.py audit-verify                 # 監査ログのハッシュ連鎖（読み取り専用。変更操作前の検査で凍結）
python3 pkilab.py audit-reanchor --confirm-head <hash> --reason ...  # 管理された再アンカー
python3 pkilab.py check                        # 承認・台帳・発行物の中身・配置物・CRL の照合
python3 pkilab.py backup                       # 暗号化＋HMAC 付きバックアップ
python3 pkilab.py restore <file> <dir>         # 隔離先へ復元し、整合・新しさ・鍵の準備を判定（保留状態）
python3 pkilab.py --home <復元先> resume --confirm  # 元環境の識別・停止と鮮度再確認。下記の運用手順を先に読む
python3 pkilab.py export-events                # 3D 教材向け（観測した粒度のまま・秘密情報なし）
```

`--role` を省略するとコマンドごとの標準の役割で実行されます。許可されていない役割では `ROLE_DENIED` になります。

### 結果コード

| コード | 意味 |
|---|---|
| `OK` | すべての確認に合格 |
| `UNTRUSTED_ANCHOR` | 信頼するルートまでたどれない |
| `SAN_MISMATCH` | 接続先名が SAN にない |
| `CERT_EXPIRED` | 期限切れ |
| `WRONG_EKU` | 用途が違う |
| `LEAF_REVOKED` / `INTERMEDIATE_REVOKED` | 葉／中間CAが失効（`verify`） |
| `REVOKED` | 実 TLS 接続で失効を検出（部位は同じ接続では確定できないため、推定は `diagnostic` に未検証の参考情報として出す） |
| `NAME_CONSTRAINT_VIOLATION` | 中間CAの名前制約の外 |
| `CRL_MISSING` / `CRL_EXPIRED` | 失効状態を確認できない（判定不能。接続はしない） |

## 3D 教材を開く

```bash
cd viz
python3 -m http.server 8765 --bind 127.0.0.1
# http://127.0.0.1:8765/ を開く
```

180秒・18場面のアニメーションと、9つの条件（正常・信頼していないルート・名前違い・期限切れ・用途違い・葉の失効・中間CAの失効・CRL期限切れ・本編）を切り替えられます。「実測イベント」から `lab/work/exports/events.json` を読み込むと、ラボで実際に起きた処理の場面に印が付きます（`measured: true` の記録だけ。検証・TLS は処理全体の結果のみで、段階ごとの実測ではありません）。

この3Dはコード生成による軽量の教材プロトタイプで、分割 GLB・LOD・AAA 品質のモデル納品ではありません（`docs/05_3d-space-design.md` 7章）。

ブログへの埋め込み: `viz/` を静的ファイルとして置き、`?embed=1&autoplay=0` を付けて iframe で表示します。

## テスト

```bash
python3 -m unittest discover -s lab/tests -v     # CA本体と境界条件の全テスト（件数はログ参照）
(cd viz && npm test)                              # 3D教材のロジック（件数はログ参照）
```

実ブラウザでの描画と表示内容の確認（CI の `viz-render` でも実行）:

```bash
(cd viz && npm ci && npx playwright install chromium)
python3 -m http.server 8765 --bind 127.0.0.1 --directory viz &
node viz/tests/render-check.mjs http://127.0.0.1:8765/ screenshots
```

終了コード: 0 成功・受理 / 1 拒否・判定不能・照合異常・復元未完了 / 2 業務上の拒否 / 3 環境エラー

## ライセンス・同梱物

- `viz/vendor/three/` は three.js（MIT License、`viz/vendor/three/LICENSE`）
- 秘密鍵・パスフレーズはリポジトリに含めていません


## Round 4：失敗4件の切り分けと再開の条件

基点 `1485180` の80試験中、3件の期待値不一致とExporterの実装不具合1件を切り分けた。`revoke-completed` のイベント対応を修正し、失効要求と公開完了を別々に出力する。失効確認の無効化やテストのskip追加で成功させる変更ではない。

[運用・復旧手順書](docs/06_operations.md) を正本とする。`check.ok`、`check.integrity_ok`、`restore.ready`、実際の接続許可はそれぞれ異なる。CRLの欠落が修復可能でも接続は拒否し、正常な証明書を一時的な障害だけで失効させない。

`--source` に存在しない場所や別のCAを指定した場合は、例外フラグでも再開しない。元CAが本当に失われた場合の `--source-stopped --accept-stale` は、失効履歴喪失の危険を伴う手動判断であり、安全な通常復旧の代替ではない。

テスト用環境変数 `PKILAB_TEST_NOW`、`PKILAB_CRASH_AT`、`PKILAB_FAULT`、`PKILAB_FORCE_POSTCHECK_FAIL` は通常の学習運用で設定しない。パスフレーズとCA鍵を同じ場所に置く構成、同一機械の監査アンカー、単一ユーザーの役割切替は学習用の制約である。
