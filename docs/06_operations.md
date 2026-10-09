# PKI Lab：発行・失効・監査・復旧の運用手順

更新：2026-10-09 / Round 4 / 学習用。公開CA・本番PKIへの流用を保証しない。

## 1. 判定項目を取り違えない

| 項目 | 意味 | falseの場合 |
|---|---|---|
| `check.integrity_ok` | 台帳・発行物・承認・監査の整合性に検出済みの異常がない | 調査・保全。空の台帳で再開しない |
| `check.ok` | 整合性違反と修復待ち作業がない | 終了値1。`problems`と`actions`を読む |
| `restore.ready` | 整合・鮮度・鍵アクセス・アーカイブ認証の準備判定 | 保留を維持。失敗項目を確認 |
| `resume.action` | `held` / `resumed` / `none` | `held`は再開していない |
| `verify.result` | `ACCEPT` / `REJECT` / `INDETERMINATE` | 後二つは接続を許可しない |

CRLの欠落・期限切れは修復可能な `actions`。その分類は、証明書が失効していないことの証明ではない。公開情報の欠落だけを理由に、正しい署名済み証明書を失効させない。

## 2. 通常の試験

**実行場所：** Linux/WSLのリポジトリ直下。Python 3とOpenSSL 3が必要。通常運用では障害注入変数を設定しない。

```bash
python3 -m unittest discover -s lab/tests -v
(cd viz && npm test)
```

**目的：** CA処理・境界条件と教材ロジックを検査する。**正常：** `OK`とfail 0。**異常：** `FAILED`、例外、非ゼロ終了。**判断：** 失敗の原因を仕様と照合し、成功条件を弱めない。テストは専用の一時CAを作り、終了後に削除する。停止したテストの一時ディレクトリも秘密情報として扱う。

## 3. 更新前の保全

ソースコードと、実行時の `--home` は別に保全する。秘密鍵だけでなく台帳、承認、失効情報、CA世代を保存する。バックアップ用パスワード、root/issuerの鍵解除情報、サーバー鍵は別保管。`secrets/`と`server/private/`はCAバックアップに含まれない。

以下の `<...>` は実環境のパスへ置き換える。削除・初期化の手順ではない。

```bash
python3 lab/pkilab.py --home <元環境> check
python3 lab/pkilab.py --home <元環境> backup --pass-file <別保管のバックアップ用パスワードファイル>
```

**目的：** 更新前の状態確認と認証付き暗号化バックアップ。**正常：** checkの `ok:true`、backupの `backup` / `manifest`パスが返る。**異常：** `AUDIT_FROZEN`や整合性違反。**判断：** 両ファイルと別保管情報を保全する。整合性違反を無視して通常の復旧可能バックアップと認定しない。`actions`がある場合は未完了作業を記録する。

## 4. CRLの更新・未完了失効の再試行

```bash
python3 lab/pkilab.py --home <対象環境> crl-root
python3 lab/pkilab.py --home <対象環境> crl-issuer
python3 lab/pkilab.py --home <対象環境> check
```

**目的：** 原因を除去した後、未完了の失効を公開・読み戻し確認まで進める。**正常：** `completed_revocations`とCRLパス、checkの `ok:true`。**異常：** `REVOCATION_PENDING`、`CA_NOT_ACTIVE`。**判断：** 公開失敗が残る間は完了ではない。失効済み中間CAの鍵で新しいCRLを作る手順ではなく、新世代へ移る。

失効要求は永続pending、要求監査、台帳変更、CRL生成、公開確認、完了監査の順。要求監査に失敗してもpendingは残る。再試行で要求記録が重複する可能性があり、`request_id`で関連付ける。公開完了前には完了イベントを出さない。

## 5. 隔離先へ復元する

```bash
python3 lab/pkilab.py --home <元環境> restore <backup.tar.gz.enc> <空の復元先> \
  --pass-file <バックアップ用パスワードファイル> \
  --root-pass-file <root鍵解除ファイル> --issuer-pass-file <issuer鍵解除ファイル>
```

**目的：** 破壊せず別領域に復元する。**正常：** `archive_integrity_ok:true`と判定項目が返り、復元先が `HELD`。**異常：** `RESTORING`のまま、HMAC不一致、`ready:false`。**判断：** 再開承認前に署名・失効・新規申請はできない。展開途中で停止した場合は、証跡を保全して別の空領域でやり直す。元環境の中へ復元しない。

`freshness_confirmed`は、現在の台帳などの指紋と検証済み監査ログを比較する。診断は `checks.state`、`checks.source`、指定時の `checks.external`。ログ改変の理由は `checks.source.source_audit`。読み取り専用操作を許すのは、比較元ログを検証できた場合だけ。

## 6. 元環境を停止して再開する

```bash
python3 lab/pkilab.py --home <復元先> resume --confirm \
  --root-pass-file <root鍵解除ファイル> --issuer-pass-file <issuer鍵解除ファイル>
python3 lab/pkilab.py --home <元環境> status
python3 lab/pkilab.py --home <復元先> check
```

**目的：** 最新性を確認し、二つのCAが並行して書き込む状態を避ける。**正常：** `action:resumed`、`source_fenced:true`。元環境は `superseded:true`。**異常：** `held`、`source_mismatch`、`source_unavailable`、ロック待ち。**判断：** `held`で作業を進めない。再開後の`actions_after_resume`に従ってCRL等を更新してから実接続を確認する。

再開は復元先のresumeロックで直列化し、元のissuer/root/requests/auditをロックした状態で鮮度を再確認する。停止対象は復元時に記録したinstance IDと一致させる。元を停止した直後の中断からも、復元先の整合性と鍵アクセスを再確認する。

元を本当に失った場合には、管理者の `--source-stopped --accept-stale --confirm` による例外判断が存在する。ただし不正な明示 `--source` や別のinstance IDは解除できない。この例外は失効履歴を復元しない。旧CA廃止・新鍵への移行を優先し、通常の安全な復旧として使用しない。

## 7. 教材イベントの確認

```bash
python3 lab/pkilab.py --home <対象環境> export-events
```

**目的：** 検証した監査snapshotから教材用JSONを作る。**正常：** 出力パスと件数。**異常：** `AUDIT_FROZEN` / `EVENT_SCOPE_INVALID` / `EXPORT_LEAK`。**判断：** 手作業でmeasuredを付け替えない。ブラウザの表示は真正性を外部検証したものではない。

| イベント・フィールド | 意味 |
|---|---|
| `REVOCATION_REQUESTED` | 要求が記録された。公開完了ではない |
| `CERT_REVOKED` | issuerによる葉の失効が公開確認まで完了 |
| `INTERMEDIATE_REVOKED` | rootによる中間CAの失効が公開確認まで完了 |
| `revocation_requested` | 失効確認を要求した設定 |
| `not_requested` | 確認を要求していない |
| `not_executed` | OpenSSL検証前の名前照合などで終了 |
| `reported` | 失効/CRLに関する結果を観測した |
| `not_observed` | 内部の失効確認到達を個別には観測していない |

## 8. 未達・制約

論理的役割分離と同一機械の監査アンカーは、独立監査・HSM・物理分離を代替しない。HTTP経由のCRL取得と伝播の統合検証、実GPUの性能計測、F16の分割GLB統合、美術的なAAA品質判定は未完了。通常の設定ではOS全体の信頼ストアを変更しない。
