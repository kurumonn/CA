# 03 詳細設計 — 学習用私設CA「PKI Lab」

実装: `lab/pkilab.py`（Python 標準ライブラリ＋OpenSSL 3.x CLI）

## 1. ファイル配置（`PKILAB_HOME`、既定 `lab/work/`）

```
root/{private,certs,db,newcerts,crl}         ルートCA（本来は Root VM）
issuer/{private,certs,db,newcerts,crl,lock}  中間CA（現在の世代）
issuer/state.json                            中間CAの運用状態と世代
archive/issuer-gen<N>/                       失効・廃止した旧世代（署名には使わない）
requests/REQ-*/{request.csr.pem,state.json,cert.json}
approvals/REQ-*.json      承認記録
journal/OP-*.json         署名操作の記録（開始時の台帳行数・署名結果）
audit/audit.jsonl         監査ログ（ハッシュ連鎖）
audit/FROZEN.json         監査異常による凍結の印
anchor/anchor.json        最新の連番とハッシュ（別媒体の代用）
incidents/incidents.jsonl 障害ログ（監査ログとは別。凍結中の記録もここ）
recovery/hold.json        復元直後の復旧保留の印
server/{private,certs}    サーバー鍵・証明書・フルチェーン
public/{certs,crl}        配布してよい公開情報だけ
verifier/{bundle,cache}   検証用バンドル・CRL キャッシュ
exports/events.json       3D 教材用イベント
secrets/                  学習用パスフレーズ（0600、バックアップに含めない）
backups/                  暗号化バックアップ＋マニフェスト（HMAC）
```

`serve-public` は `public/` だけを配信し、PUT/POST/DELETE を 405 で拒否する。
なお `verify` / `client` は CRL を `public/` から直接読む。HTTP 配布経由の取得・伝播・キャッシュ戻りは検証していない。

## 2. 永続化

JSON・証明書・CRL の書き込みは、同じディレクトリの一意な一時ファイル → `flush`/`fsync` → `rename` → ディレクトリ `fsync` の順で行う（`atomic_write`）。監査ログの追記も行ごとに `fsync` する。
OpenSSL の台帳（`index.txt` 等）の複数ファイル更新は単一トランザクションにならないため、署名操作は §6 の記録と §7 の照合で補う。

## 3. CSR 受付検査（`inspect_csr`）

表示テキスト（`openssl req -text`）は Subject などの自由記述を含むため、判定には使わない。CSR を DER で取り出し、最小限の DER 解析で `SubjectPublicKeyInfo` と要求拡張（extensionRequest）を構造として読む。

| 検査 | 拒否コード |
|---|---|
| 64 KiB 超 | `CSR_TOO_LARGE` |
| PEM でない・構造を解析できない | `CSR_BAD_FORMAT` |
| CSR 自己署名の不一致 | `CSR_BAD_SIGNATURE` |
| SPKI が EC P-256（非圧縮点・91バイト・固定の接頭部）でない | `CSR_BAD_KEY` |
| CA:TRUE / keyCertSign / cRLSign / serverAuth 以外の EKU を要求 | `CSR_FORBIDDEN_EXTENSION` |
| SAN なし | `SAN_REQUIRED` |
| 許可リスト外の SAN（型付き・完全一致） | `SAN_NOT_ALLOWED` |

発行時は `copy_extensions = none` とし、拡張は `server_localhost.ext` から CA 側で生成する。

## 4. 承認記録

```json
{ "approval_id", "request", "csr_sha256", "pubkey_sha256（SPKI DER の SHA-256）",
  "profile", "profile_sha256", "san", "eku", "days",
  "approver", "approved_at", "expires_at", "note" }
```

発行時に CSR ハッシュ・プロファイルハッシュ・期限を再確認し、違えば `APPROVAL_MISMATCH` / `APPROVAL_EXPIRED`。

## 5. 中間CAの運用状態と世代

`issuer/state.json` に `status`（PENDING / ACTIVE / SUSPENDED / REVOKED / RETIRED）と `generation` を持つ。

| 操作 | 状態 |
|---|---|
| `init-issuer` | PENDING（鍵と CSR のみ） |
| `sign-intermediate` | PENDING のときだけ署名 → ACTIVE。過去にルートが署名した鍵と同じなら `KEY_REUSE` |
| `revoke-intermediate` | ルートで失効 → ルート CRL 公開 → REVOKED |
| 発行後検査の失効に失敗 | SUSPENDED（`pending_revocation` を記録） |
| `init-issuer --new-generation` | REVOKED / RETIRED のときだけ。旧世代を `archive/issuer-gen<N>/` へ移し、新しい鍵で N+1 世代を作る |

`issue` は署名前に、状態が ACTIVE であること、ルート CRL が存在・署名検証可能・期限内であること、そのルート CRL に中間CAが載っていないことを確認する（`CA_NOT_ACTIVE` / `ROOT_CRL_UNAVAILABLE`）。

## 6. 発行処理（`cmd_issue`）

1. `issuer/lock/ca.lock` を `flock`（`PKILAB_LOCK_TIMEOUT` 秒で `LOCK_BUSY`）
2. 状態確認
   - PUBLISHED：配置物のハッシュが発行記録と一致するか確かめて返す（違えば台帳の証明書から再配置）
   - ISSUED：**再署名せず**、配置だけを再開する
   - SIGNING / NEEDS_RECOVERY：`NEEDS_RECOVERY` で停止（§7 の `recover` へ）
3. 中間CAの状態（§5）、承認・CSR・プロファイル・残存期間を再確認
4. 操作記録 `journal/OP-*.json` に **署名前の台帳行数**（`index_rows_before`）・申請・CSR ハッシュ・承認IDを書いてから SIGNING へ
5. `openssl ca -batch -notext -subj ... -extfile ... -startdate ... -enddate ...`
6. 台帳に追加された行がちょうど1行で、ステージングの証明書と DER ハッシュが一致することを確認（違えば `LEDGER_ANOMALY`）。シリアルと証明書ハッシュを操作記録へ
7. 発行後検査（`validate_issued`）：台帳状態 V、SAN・公開鍵が承認と一致、CA:FALSE、EKU=serverAuth のみ、KU=digitalSignature のみ、発行者、親より長くない
8. 不合格なら §8 の隔離
9. `cert.json`（発行者・シリアル・操作ID・世代・証明書ハッシュ）を書き、ISSUED、監査記録
10. 配置（`_publish`）：台帳の証明書を検査し直してからサーバー・公開領域へ原子的に書き、PUBLISHED

OpenSSL の `ca` は署名と同時に台帳へ記録する。「検査に通った証明書だけが台帳に載る」のではなく、不合格の証明書も台帳に残り、失効させたうえで隔離する。

## 7. 復旧（`cmd_recover`）

| 状態 | 処理 |
|---|---|
| PUBLISHED | 配置物の照合（必要なら再配置） |
| ISSUED | 配置だけを完了（`completed_publish`） |
| SIGNING / NEEDS_RECOVERY | 下記 |

1. 操作記録が無い、または申請・CSR ハッシュが一致しない → 隔離
2. 操作記録にシリアルがあれば、それだけを候補にする
3. 無ければ、`index_rows_before` 以降に台帳へ追加された行のうち、**他の申請の `cert.json` に結び付いておらず**、公開鍵と承認 SAN が一致するものを候補にする
4. 候補 0 件 → APPROVED に戻す（`returned_to_approved`）／2 件以上 → 自動選択せず隔離（`AMBIGUOUS`）
5. 候補 1 件 → 操作記録の証明書ハッシュと照合し、`validate_issued`（台帳状態・SAN・用途・鍵・発行者）に合格した場合だけ採用。不合格（失効済み・別用途など）は隔離

## 8. 隔離（`_quarantine`）

台帳で有効（V）なら `cessationOfOperation` で失効し、CRL を生成・署名検証・公開してから QUARANTINED にする。失効か CRL 公開に失敗したら、中間CAを SUSPENDED にし、`pending_revocation` を操作記録と状態に残す（照合 `check` でも異常として出る）。

## 9. 検証（`cmd_verify`）

1. 証明書を DER で解析し、SAN を**型付き**で読む（`DNS:` / `IP:` / `EMAIL:` / `URI:`）
2. SAN が無ければ `SAN_REQUIRED`
3. 接続先が IP アドレスなら `IP:<addr>`、それ以外は `DNS:<小文字の名前>` が SAN に**完全一致**で含まれなければ `SAN_MISMATCH`。
   `openssl verify -verify_hostname` は該当する型の SAN が無いと Subject の CN を参照するため、この事前判定で CN フォールバックを防ぐ（例：CN=localhost・SAN=IP:127.0.0.1 の証明書は localhost としては拒否）。ワイルドカードはラボのポリシー外なので扱わない
4. その後で OpenSSL によるチェーン検証

```
openssl verify -show_chain -x509_strict -auth_level 2 -verify_depth 1 \
  -purpose sslserver -verify_hostname localhost (IP の場合 -verify_ip) \
  -trusted root.cert.pem -untrusted intermediate.cert.pem \
  -CRLfile crls.pem -crl_check -crl_check_all  server.cert.pem
```

| OpenSSL エラー | 結果コード | 判定 |
|---|---|---|
| 2, 19, 20, 21 | `UNTRUSTED_ANCHOR` | REJECT |
| 62, 64 | `SAN_MISMATCH` | REJECT |
| 10 / 9 | `CERT_EXPIRED` / `NOT_YET_VALID` | REJECT |
| 26 | `WRONG_EKU` | REJECT |
| 23（深さ0 / 1） | `LEAF_REVOKED` / `INTERMEDIATE_REVOKED` | REJECT |
| 47, 48 | `NAME_CONSTRAINT_VIOLATION` | REJECT |
| 3 / 12 / 11 / 8 | `CRL_MISSING` / `CRL_EXPIRED` / … | INDETERMINATE |

## 10. 実 TLS 接続（`strict_client_context`）

- `PROTOCOL_TLS_CLIENT`（証明書必須・ホスト名検証）、TLS 1.3 以上
- `hostname_checks_common_name = False`
- `verify_flags = VERIFY_X509_STRICT | VERIFY_CRL_CHECK_CHAIN`（`PARTIAL_CHAIN` を外し中間CAを信頼の起点にしない）

失効（エラー23）の場合、Python の例外は失効した証明書の深さを返さないため、結果は `REVOKED`（部位不明）とする。葉か中間かの推定は、**検証なしの別接続**で得た葉のシリアルと現在の CRL から作る参考情報として `diagnostic`（`verified: false`、方法・観測時刻付き）に分けて返す。同じ接続の観測としては扱わない。

## 11. 監査ログ

各行: `seq, ts, actor, role, op, result, target, details, prev, hash`。`hash = SHA-256(正規化 JSON（hash を除く）)`、`prev` は直前の hash。

- **排他**：すべての追記は監査専用ロック（`audit/.lock`）の中で「末尾と基準ハッシュの一致確認 → 追記（fsync）→ 基準ハッシュ更新」を一度に行う。ロックの取得順は issuer → root → audit
- **凍結**：コマンド実行前（読み取り・管理操作を除く）に全行の連鎖と基準ハッシュを検証する。追記前の確認で末尾が基準と一致しない場合も同じ。異常なら `audit/FROZEN.json` を作り、障害は `incidents/` に記録し、**監査ログと基準ハッシュは変更しない**。以後の操作は `AUDIT_FROZEN` で止まる
- `check` / `restore` の結果は、監査ログが正常なときだけ追記し、異常時は障害ログへ書く（異常を検出した操作が基準を更新しない）
- **管理された再アンカー**：`audit-reanchor --confirm-head <現在の先頭> --reason ...`。内部の連鎖が正しいログ（末尾削除など）に限り、失われた履歴を受け入れる判断を障害ログに残してから基準を付け替え、凍結を解く。連鎖自体が壊れたログは `restore` で戻す
- 秘密鍵・パスフレーズ・セッション鍵は記録しない
- 制約：ログと基準ハッシュは同じ機械にある。両方の同時置換を検出するには、別媒体のチェックポイント（`restore --checkpoint`）が必要

## 12. 照合（`run_check` / `check`）

| 対象 | 確認内容 |
|---|---|
| 必須ファイル | ルート証明書・中間CA証明書・両台帳。公開 CRL の欠落は失効0件でも異常 |
| ルート台帳 | 各行の発行物を解析し、シリアル・発行者を照合。中間CA証明書がルートの発行物と同一か |
| 中間CA台帳（世代ごと） | 各行の発行物を解析（壊れた証明書は異常）、シリアル・発行者、台帳外の発行物 |
| 申請 | ISSUED / PUBLISHED に承認と発行記録があり、発行物の DER ハッシュ・SAN・公開鍵・用途が一致、配置物のハッシュが一致 |
| CRL | 該当CAで署名検証、発行者、nextUpdate、最後に生成した番号・ハッシュとの一致（ロールバック・差し替え検出）、台帳の失効との双方向一致 |
| 状態 | 未完了の失効、ルートで失効した中間CAが ACTIVE のまま、復旧が必要な申請、監査ログ・凍結 |

## 13. バックアップと復旧

**バックアップ**：root・issuer・archive・requests・approvals・journal・audit・anchor・incidents・public・server/certs を tar.gz にし、AES-256-CBC（PBKDF2）で暗号化。暗号化後のデータに HMAC-SHA256（バックアップ用パスフレーズから PBKDF2 で導出した鍵）を付け、マニフェスト（ハッシュ・HMAC・監査の連番と先頭）を書く。`secrets/` と `server/private/` は含めない（別経路で保管する前提）。

**復元**：空の隔離ディレクトリにだけ展開し、次の項目を**分けて**判定する。

| 項目 | 内容 |
|---|---|
| `archive_integrity_ok` | 復号**前**に HMAC を検証（改ざん・パスフレーズ違いなら展開しない） |
| `state_consistent` | 復元先で照合（§12）。復元先には書き込まない |
| `freshness_confirmed` | 別に保管した最新チェックポイント（既定は元の作業領域の anchor）を復元ログが含むか。元のログが読める場合、バックアップ後の差分が読み取り専用の操作（verify・backup 等）だけなら新しいとみなし、失効などの状態変更が含まれていれば `lost_changes` を返して不合格 |
| `key_access_ready` | 別保管のパスフレーズで両CA鍵を開けるか |
| `resume_authorized` | 常に false。復元先は `recovery/hold.json` により発行・CRL 公開・申請などが `RECOVERY_HOLD` で止まる |

`ready` は上の4項目がすべて真のときだけ真で、偽なら終了コード 1。
`resume --confirm [--root-pass-file ... --issuer-pass-file ...]` は、鍵解除情報を戻し、照合と鍵の確認をやり直してから保留を解く。新しさが確認できない場合は `--accept-stale`（失われた履歴を受け入れる判断）を明示しない限り再開しない。

台帳が壊れたときに空の `index.txt` を作って旧 CA 鍵で発行を再開することは禁止する（失効状態が消え、失効済み証明書が有効に戻るため）。状態を確定できない場合は旧世代を廃止し、新しい世代（§5）へ移行する。

## 14. 鍵漏えい時の手順

| 漏えい | 手順 |
|---|---|
| サーバー鍵 | 停止 → `revoke REQ --reason keyCompromise`（CRL 自動更新）→ 新しい鍵で再申請 |
| 中間CA鍵 | `revoke-intermediate --reason CACompromise`（発行停止・ルート CRL 公開）→ `init-issuer --new-generation` → `sign-intermediate` → `crl-issuer` → 再申請 |
| ルート鍵 | 旧階層停止 → 検証側で旧ルートの信頼を削除 → 新ルートを別経路で配布（ラボでは新しい作業領域を作る） |

## 15. 教材イベント出力（`export-events`、schema `pkilab-events/2`）

監査ログの連鎖を検証してから出力する（壊れていれば出力しない）。

- 観測した粒度のまま出す。`verify` は `CERT_VERIFICATION_COMPLETED`、TLS は `TLS_HANDSHAKE_COMPLETED` / `TLS_HANDSHAKE_FAILED` の**集約イベント**（`observation: "aggregate"`）1件だけ
- 段階（経路・名前・失効…）は個別に計測していないので `details.stages = "not_observed"`。失効確認の有無は `details.revocation = "checked" | "skipped"`
- 各イベントに `origin: "measured"`、文書に `measured: true` と、監査ログの先頭ハッシュ
- `target` は SHA-256 の先頭12桁、`details` は許可したキーだけ。出力に `PRIVATE KEY` / `-----BEGIN` が含まれたら出力しない

3D 側（`viz/js/lesson.js` の `parseEvents`）は、文書の `measured === true`（真偽値）かつイベントの `origin === "measured"` のものだけを「実測」と表示する。ファイルが本当にラボで生成されたかの真正性はブラウザでは検証していない。

## 16. 終了コード

| コード | 意味 |
|---|---|
| 0 | 成功・受理 |
| 1 | 検証の拒否・判定不能、照合の異常、復元の準備未完了、再開保留 |
| 2 | 業務上の拒否（`LabError`。JSON に `error` コード） |
| 3 | 環境エラー（想定外の例外。JSON に `ENV_ERROR`） |
