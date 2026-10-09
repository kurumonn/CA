# 04 受入試験

| 区分 | 実行方法 | 件数 |
|---|---|---|
| CA ラボ | `python3 -m unittest discover -s lab/tests -v` | 実行ログを正本とする |
| 3D ロジック | `cd viz && npm test` | 実行ログを正本とする |
| 実ブラウザ描画と表示内容 | `viz/tests/render-check.mjs`（Playwright / Chromium、CI の `viz-render` ジョブ） | 15 構図＋実測表示2件 |
| 一連の流れ | `bash lab/scripts/demo.sh`（CI でも実行） | — |

受入条件は「テストが緑」だけではなく、レビューで指摘された再現ケースが**正しく拒否・隔離・未測定表示になり、復旧後に再署名や履歴喪失が起きない**ことを含む。下表の「指摘」はレビュー（コミット 34e60be）の項目番号。

## PKI Lab（`lab/tests/test_pkilab.py`）

| 区分 | 試験 | 期待結果 | 指摘 |
|---|---|---|---|
| 鍵 | `test_keys_separated_and_encrypted` | ルート・中間鍵が暗号化PKCS#8・0600、issuer/ にルート鍵なし、public/ に秘密鍵なし | |
| 鍵 | `test_profiles` | 中間 pathlen:0＋名前制約、ルート pathlen:1、中間CA ACTIVE | |
| 権限 | `test_role_separation` | RA 役割での発行は `ROLE_DENIED` | |
| 発行 | `test_issue_and_verify_ok` | DNS/IP どちらでも OK、CA:FALSE・serverAuth・digitalSignature のみ | |
| 発行 | `test_idempotent_issue` | 再実行で同じ証明書、台帳は1件 | |
| 発行 | `test_reissue_republishes_tampered_deployment` | 配置物が壊れていたら台帳の証明書から再配置（再署名なし） | F03 |
| 審査 | `test_reject_disallowed_san` | example.com / sub.localhost / *.localhost / 10.0.0.1 を拒否 | |
| 審査 | `test_reject_forbidden_extensions` | CA:TRUE・clientAuth・keyCertSign・codeSigning を拒否 | |
| 審査 | `test_reject_non_p256_keys` | RSA-2048・P-384・Ed25519 を拒否 | F09 |
| 審査 | `test_key_type_not_spoofable_via_subject` | Subject に `id-ecPublicKey prime256v1` を書いた RSA の CSR を拒否 | F09 |
| 審査 | `test_requested_extension_text_in_subject_is_ignored` | Subject の文字列で SAN を偽装できない | F09 |
| 審査 | `test_reject_missing_san_oversize_and_tampered` | SAN なし・64KiB 超・署名改ざんを拒否 | |
| 承認 | `test_approval_bindings` | 未承認・CSR 差し替え・承認期限切れを拒否 | |
| 排他 | `test_lock_busy` | ロック保持中は `LOCK_BUSY`、解放後は成功 | |
| 隔離 | `test_postcheck_failure_revokes_and_publishes_crl` | 発行後検査の不合格で失効・CRL 公開まで確定して QUARANTINED | F14 |
| 復旧 | `test_crash_before_sign_returns_to_approved` | 署名前の停止 → APPROVED に戻して発行、台帳1件 | |
| 復旧 | `test_crash_after_sign_adopts_without_resigning` | 署名後の停止 → 操作記録のシリアルを採用、台帳1件 | F02 |
| 復旧 | `test_crash_after_issued_resumes_publish` | ISSUED 直後の停止 → `issue` でも `recover` でも配置だけ再開 | F03 |
| 復旧 | `test_recover_does_not_adopt_other_requests_revoked_cert` | 同じ鍵の失効済み別申請（SAN 違い）を採用しない | F02 |
| 復旧 | `test_recover_quarantines_ambiguous_candidates` | 候補が2件なら自動選択せず隔離 | F02 |
| 復旧 | `test_recover_rejects_cert_that_does_not_match_approval` | 台帳で失効済みの候補は採用せず隔離 | F02 |
| 検証 | `test_untrusted_anchor` | 別ルートを信頼 → `UNTRUSTED_ANCHOR` | |
| 検証 | `test_hostname_mismatch` | example.com / 127.0.0.2 → `SAN_MISMATCH` | |
| 検証 | `test_no_cn_fallback_when_only_ip_san` | CN=localhost・SAN=IP のみ → localhost では `SAN_MISMATCH`、127.0.0.1 では OK | F01 |
| 検証 | `test_no_cn_fallback_other_san_types` | email-SAN のみ・別の DNS-SAN → `SAN_MISMATCH` | F01 |
| 検証 | `test_cn_only_certificate_rejected` | CN だけの証明書は `SAN_REQUIRED` | |
| 検証 | `test_wrong_purpose_and_expired` | `WRONG_EKU`、45日後評価で `CERT_EXPIRED` | |
| 検証 | `test_crl_problems_are_indeterminate` | CRL 期限切れ・欠落は INDETERMINATE | |
| 失効 | `test_leaf_and_intermediate_revoked` | `LEAF_REVOKED`／確認なしなら OK／`INTERMEDIATE_REVOKED` | |
| 制約 | `test_name_constraints_block_misissuance` | 審査を迂回した example.com 証明書も `NAME_CONSTRAINT_VIOLATION` | |
| CA状態 | `test_revoked_intermediate_stops_issuance` | 中間CA失効後の `issue` は `CA_NOT_ACTIVE`、台帳に追加なし | F10 |
| CA状態 | `test_issuance_stops_when_root_crl_lists_intermediate` | ルート CRL に載っていれば状態ファイルが ACTIVE でも止まる | F10 |
| CA状態 | `test_new_generation_after_compromise` | 同じ鍵の再署名は不可、新世代で発行再開、旧世代の証明書は検証不可、照合 OK | F10 |
| CA状態 | `test_key_reuse_rejected` | 状態を書き換えても同じ鍵の再署名は `KEY_REUSE` | F10 |
| TLS | `test_tls_accept_then_reject_after_revocation` | TLS1.3 成功 → 失効後 `REVOKED`（推定は `diagnostic`、未検証）→ 確認なしなら接続できる | F12 |
| TLS | `test_tls_intermediate_revoked` | `REVOKED`、推定は `INTERMEDIATE_REVOKED` | F12 |
| TLS | `test_tls_wrong_host` | `SAN_MISMATCH` | |
| TLS | `test_curl_does_not_check_revocation_by_default` | curl は既定で成功、`--crlfile` で失敗 | |
| 監査 | `test_tamper_detected_and_frozen` | 1行改ざん → `AUDIT_TAMPERED`、以後 `AUDIT_FROZEN`、再アンカー不可 | F04 |
| 監査 | `test_truncation_is_not_normalized_by_later_operations` | 末尾削除後に check / request / verify を繰り返しても異常が消えず、ログと基準ハッシュは不変、障害ログに記録 | F04 |
| 監査 | `test_managed_reanchor` | 確認ハッシュと理由を付けた再アンカーだけが凍結を解く | F04 |
| 監査 | `test_concurrent_writers_keep_chain_valid` | 8プロセス同時の request / verify で連番重複なし・連鎖正常 | F05 |
| 照合 | `test_consistent_state` | 正常時 OK | |
| 照合 | `test_missing_crls_detected_even_without_revocations` | 失効0件でも両 CRL 欠落を検出 | F06 |
| 照合 | `test_corrupted_newcert_detected` | 発行物を証明書でない文章に置換すると検出 | F06 |
| 照合 | `test_swapped_or_rolled_back_crl_detected` | 古い CRL への巻き戻し・別CAの CRL を検出 | F06 |
| 照合 | `test_deployed_cert_mismatch_detected` | 配置物が別の証明書なら検出 | F06 |
| 復旧 | `test_latest_backup_restores_ready_and_is_held` | 4項目が真、保留中は発行・CRL 不可、resume 後に CRL 生成と発行ができる | F11 |
| 復旧 | `test_stale_backup_is_not_ready` | バックアップ後に失効があれば `freshness_confirmed=false`・`lost_changes` に revoke | F11 |
| 復旧 | `test_tampered_backup_rejected_before_decrypt` | 1ビット改ざん → HMAC 不一致、展開しない | F11 |
| 復旧 | `test_missing_key_passphrase_is_not_ready` | 鍵解除情報が無ければ `key_access_ready=false`、終了コード1 | F11 |
| 教材 | `test_events_follow_observed_granularity` | 段階イベントを出さず集約1件、`--no-crl` は `revocation_requested:false` と `revocation_observation:not_requested`、秘密・シリアルなし | F07 |
| 教材 | `test_export_refused_when_audit_broken` | 監査ログ異常時は出力しない | F07 |

## 3D 教材（`viz/tests/lesson.test.mjs`・`render-check.mjs`）

| 試験 | 期待結果 | 指摘 |
|---|---|---|
| 18場面・全シナリオの結果コード・秘密鍵の不動・ルートの別経路・失敗ゲート以降の非評価・判定不能の区別・本編の流れ・座標範囲 | 既存の11件 | |
| `measured` が true（真偽値）でない記録・origin が measured でない記録を実測扱いしない | false / 欠落 / "true" / 1 / simulated すべて非実測 | F08 |
| 集約された検証イベントの場面対応と「失効確認なし」の保持、旧段階イベントの廃止 | | F07 |
| 条件とカード・CRL・信頼ストア・接続先の表示が一致 | wrongEku は clientAuth のみ、leafRevoked は葉入り CRL、intermediateRevoked はルート署名の CRL、crlExpired は期限切れ、untrusted はルートを運ばない | F15 |
| 説明文が止まるゲートで結果コードを示し、以降は評価しない | | F15 |
| 実ブラウザ：15構図で WebGL 描画・場面タイトル・結果表示・カード内容・非表示トークンを検査 | | F17 |
| 実ブラウザ：measured=false の JSON で「実測」と表示されず、サンプル（実測）では印が付く | | F08, F17 |

## 未実装・対象外（試験で代替したと扱わないもの）

- 物理的に分離した Root VM・HSM・独立した二者承認・ログの別媒体保管
- HTTP 経由の CRL 取得・伝播、OCSP レスポンダー、ACME
- 長時間運用（CRL の定期再発行を自動で回す仕組み）
- 以前の分割 GLB・LOD・AAA アセットの統合（F16、`docs/05_3d-space-design.md` 7章）
- 実機 GPU での描画性能（FPS・VRAM）


## Round 4追加試験と4件の修正判定

- `test_resume_without_reachable_source_requires_explicit_decisions`：誤った明示sourceを拒否する試験と、記録された元環境が実際に不在の試験を分離。確認フラグ1個だけでは解除しない。
- `test_tampered_source_log_is_not_evidence_of_freshness`：トップレベルだけでなく `checks.source.source_audit` と `checks.state` の両方を検査。
- `test_missing_crls_detected_even_without_revocations`：CRL欠落が `actions` に入り、終了値1・`ok:false`・実検証拒否を維持することを確認。失効0件での黙認は禁止。
- `test_events_follow_observed_granularity`：要求と観測の期待値を弱めず、失効完了イベントの欠落をExporterで修正。

`test_continuation.py` は要求と失効完了の区別、公開失敗中の出力、未知scope、Exporterのsnapshot、要求監査のI/O障害、CRLの一時欠落、ルート署名直後の停止、再開中断後の鍵喪失・破損・再試行、再開同時実行、復元元の取り違えを検査する。

件数はソース内の試験一覧と実行ログから確定する。受入試験の成功は、未試験の攻撃・障害・実GPU性能の保証ではない。
