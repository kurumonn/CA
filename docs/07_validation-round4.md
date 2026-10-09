# Round 4：継続実装・検証記録

更新日：2026-10-09。実装修正コミット：`7ca97da69e7dbb179b42c8908bc8583304f6dbcd`。

## 対象と結論

`148518016f8996ffd1c55bbfa3cc87dd17fef8eb`の未完了作業を引き継いだ。4件の失敗を再現し、3件は仕様変更に伴う期待値、1件はExporter本体の回帰として修正した。テストの削除・skip・失敗の握りつぶしでは解決していない。

この記録は学習用CAの対象範囲に対する検証であり、公開CA・本番PKIの安全性認定やAAA美術品質の認定ではない。

## 4件の切り分け

| テスト | 原因 | 修正・維持した条件 |
|---|---|---|
| `test_resume_without_reachable_source_requires_explicit_decisions` | 明示的に誤った`--source`を指定した場合は、例外フラグでも解除しない仕様へ変更されていた | 誤指定と本当の復元元消失を別ケースにする。後者も必要な確認が1つでも欠ければ保留 |
| `test_tampered_source_log_is_not_evidence_of_freshness` | 診断がトップレベルから`checks.source`へ移動。台帳指紋の違いも検出 | 監査改変と状態差の両方をassert。`freshness_confirmed:false`、終了値1を維持 |
| `test_missing_crls_detected_even_without_revocations` | CRL欠落を恒久的破損ではなく修復可能な`actions`へ分類 | `ok:false`、終了値1を維持。実際のverifyが`INDETERMINATE/CRL_MISSING`、台帳がVのままかも確認 |
| `test_events_follow_observed_granularity` | 本体が`revoke-completed`を記録する一方、Exporterが旧イベント名だけを認識 | 要求と公開完了を区別してマッピング。葉と中間CAの完了イベントを復元。元の完了イベントassertは削除しない |

## 追加実装

失効要求を台帳変更前にpendingへ永続化し、そのあと要求監査を記録する。監査I/O障害時にも要求を残し、次回CRL処理で再試行する。要求IDで関連付けるat-least-once記録であり、重複なしのexactly-onceは保証しない。

復元先の`locks/resume.lock`で再開操作を直列化する。元環境をSUPERSEDEDにした直後の中断から再試行する場合も、復元先の整合性と鍵アクセスを再検査する。

Exporterは監査ロック内で検証した同一スナップショットを出力する。不明な失効対象CAを推測せず`EVENT_SCOPE_INVALID`で拒否する。3D教材の`REVOCATION_REQUESTED`は公開完了とは別に扱う。

デモは期待する終了値と結果コードを確認する。任意の異常を「期待した拒否」と扱う`|| true`を比較操作から除いた。CRL拒否比較のcurlは終了値60を確認する。

## 実行結果と出所

| 実行 | CA | 3Dロジック | 実TLSデモ |
|---|---|---|---|
| 修正前のローカル再現 | 80件中3失敗・1エラー | 対象外 | 対象外 |
| 修正後のローカル | 92件成功 | 16件成功 | 成功。失効前受理・失効後拒否・失効確認なしの比較 |
| GitHubの修正適用ジョブ | 全テスト成功後のみcommit/push | 同左 | 同左 |

ローカル環境：Python 3.13.5 / OpenSSL 3.5.5 / Node.js 22.16.0。
追加CA試験は`lab/tests/test_continuation.py`の12件。I/O障害の一部はモック注入であり、物理ディスク故障や電源断の実験ではない。

[修正適用ジョブと検証ログ](https://github.com/kurumonn/CA/actions/runs/37932116796)

ローカルでは通常のcloneが名前解決に失敗したため、GitHub Actionsの`git archive`による追跡ファイルのスナップショットを取得した。抽出した関数の代替実装ではなく、そのソース一式のテストを実行している。

- スナップショットのPRマージSHA：`1ac4478a1597de68dd24811ed224dcc0459c5072`
- アーカイブSHA256：`149955a737ea23c210ccb312970477b7c14ab2fae86ca5c6d465c0e63bb18e23`
- 適用パッチSHA256：`301c1163b21f8eb367f36f674ec57512b1bb2f00235bc02eeb30e18892d8c72d`

修正適用ジョブは元コミットとパッチのハッシュを確認し、検証成功後に通常のfast-forward pushを行った。転送用の一時ファイルと書込み用ワークフローはそのコミットで削除済み。mainへのマージ、実行時の秘密鍵・パスフレーズのコミットは行っていない。

## 描画とCIを混同しない

ローカルChromiumの統合描画試行は`ERR_BLOCKED_BY_ADMINISTRATOR`で初回のlocalhost遷移に失敗した。ローカルで3D描画が成功したとは扱わない。

通常のCIにはChromium/SwiftShaderによる15構図と実測表示2件の確認がある。この文書を追加したコミットも通常CIの対象になる。最終判定は[Actionsの当該コミットの実行結果](https://github.com/kurumonn/CA/actions)を参照し、過去の成功を新しいコミットの成功へ読み替えない。

## 残る品質上の制約

ルート・中間CA・監査アンカーは同じ機械上の論理分離であり、HSM、独立監査、物理分離を代替しない。外部レビューの全項目を解決済みとは認定していない。

HTTP経由のCRL取得・配布停止・伝播の統合試験と、実GPU上のFPS/VRAM測定は未実施。ファイル経由のCRL検証成功をそれらの成功としない。

F16の元GLB・共有テクスチャは別の提供ZIPにあるが、このコミットでは3Dへの統合・美術調整・性能最適化を行っていない。AAA品質への残工程は別途必要である。

## 実行方法

**目的：** 修正したCA境界と教材ロジックの回帰確認。
**場所：** Linux/WSLのリポジトリ直下。

```bash
python3 -m unittest discover -s lab/tests -v
(cd viz && npm test)
```

**正常：** CAは`OK`、Nodeはfail 0。**異常：** 非ゼロ終了、`FAILED`、例外。**判断：** 件数だけでなく失敗理由と条件を確認する。実行時の一時CAには秘密鍵が作られるため、異常停止後の一時領域も公開しない。

復旧操作は[運用手順書](06_operations.md)を使用する。既存CAをやり直すために鍵や台帳を安易に削除しない。
