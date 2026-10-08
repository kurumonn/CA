"""再レビュー（b17f5d2）で指摘された境界条件の回帰試験（NR01〜NR09）。

実行: python3 -m unittest discover -s lab/tests -v
"""

from __future__ import annotations

import datetime as dt
import io
import json
import os
import subprocess
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pkilab import LabCase, later, openssl, run  # noqa: E402

import pkilab  # noqa: E402


def secrets_args(home: Path) -> list[str]:
    return ["--root-pass-file", str(home / "secrets/root.pass"),
            "--issuer-pass-file", str(home / "secrets/issuer.pass")]


def rewrite_ops_without_rehash(home: Path, from_seq: int, new_op: str) -> None:
    """from_seq 以降の op だけを書き換える（hash・anchor は変えない）。"""
    log = home / "audit/audit.jsonl"
    out = []
    for line in log.read_text().splitlines():
        e = json.loads(line)
        if e["seq"] >= from_seq and e["op"] not in pkilab.READONLY_OPS:
            e["op"] = new_op
        out.append(json.dumps(e, ensure_ascii=False))
    log.write_text("\n".join(out) + "\n")


# ---------------------------------------------------------------------------
class TestFreshness(LabCase):
    """NR01・NR02: 新しさは検証できた記録だけで判断し、再開時に（元を止めて）判定し直す。"""

    def backup(self) -> str:
        rc, out = run(self.home, "backup")
        self.assertEqual(rc, 0, out)
        return out["backup"]

    def test_tampered_source_log_is_not_evidence_of_freshness(self):
        req = self.issue()
        b = self.backup()
        backup_seq = pkilab.read_json(Path(b + ".manifest.json"))["audit_seq"]
        run(self.home, "revoke", req)
        rewrite_ops_without_rehash(self.home, backup_seq + 1, "verify")  # 失効を「読み取り専用」に見せかける
        rc, rep = run(self.home, "restore", b, str(self.tmp / "r"))
        self.assertFalse(rep["freshness_confirmed"], rep)
        self.assertEqual(rep.get("source_audit"), "AUDIT_TAMPERED")
        self.assertEqual(rc, 1)

    def test_frozen_source_is_not_evidence_of_freshness(self):
        self.issue()
        b = self.backup()
        log = self.home / "audit/audit.jsonl"
        log.write_text("\n".join(log.read_text().splitlines()[:-1]) + "\n")
        run(self.home, "request")  # 監査異常を検出して凍結
        self.assertTrue(run(self.home, "status")[1]["frozen"])
        rc, rep = run(self.home, "restore", b, str(self.tmp / "r"))
        self.assertFalse(rep["freshness_confirmed"], rep)

    def test_resume_rechecks_and_detects_revocation_after_restore(self):
        req = self.issue()
        b = self.backup()
        dest = self.tmp / "r"
        rc, rep = run(self.home, "restore", b, str(dest))
        self.assertTrue(rep["ready"], rep)
        run(self.home, "revoke", req)  # restore 後・resume 前の失効
        rc, out = run(dest, "resume", "--confirm", *secrets_args(self.home))
        self.assertEqual(out["action"], "held", out)
        self.assertTrue(any(b_.startswith("freshness_confirmed") for b_ in out["blockers"]))
        self.assertTrue(any("revoke" in c for c in out["freshness"]["lost_changes"]), out)
        self.assertFalse(run(self.home, "status")[1]["superseded"])

    def test_resume_fences_source_so_later_changes_cannot_be_lost(self):
        req = self.issue()
        b = self.backup()
        dest = self.tmp / "r"
        run(self.home, "restore", b, str(dest))
        rc, out = run(dest, "resume", "--confirm", *secrets_args(self.home))
        self.assertEqual((out["action"], out["source_fenced"]), ("resumed", True), out)
        # 元の作業領域では、もう状態を変えられない（失効も CRL も申請も）
        for argv in (["revoke", req], ["crl-issuer"], ["request"]):
            self.assertEqual(run(self.home, *argv)[1]["error"], "SUPERSEDED", argv)
        # 復元先では運用を続けられる
        self.assertEqual(run(dest, "revoke", req)[0], 0)

    def test_resume_without_reachable_source_requires_explicit_decisions(self):
        self.issue()
        b = self.backup()
        dest = self.tmp / "r"
        run(self.home, "restore", b, str(dest))
        missing = str(self.tmp / "gone")
        rc, out = run(dest, "resume", "--confirm", "--source", missing, *secrets_args(self.home))
        self.assertEqual(out["action"], "held")
        self.assertTrue(any(x.startswith("source_not_fenced") for x in out["blockers"]), out)
        rc, out = run(dest, "resume", "--confirm", "--source", missing, "--source-stopped", "--accept-stale",
                      *secrets_args(self.home))
        self.assertEqual((out["action"], out["source_fenced"]), ("resumed", False), out)

    def test_external_checkpoint_detects_rehashed_source_log(self):
        """ログと基準ハッシュの両方を書き換えられても、別媒体のチェックポイントで検出する。"""
        req = self.issue()
        b = self.backup()
        run(self.home, "revoke", req)
        external = self.tmp / "checkpoint.json"
        external.write_bytes((self.home / "anchor/anchor.json").read_bytes())  # 別媒体に保管
        # 失効の記録を消し、連鎖と基準を作り直す（元の作業領域だけでは検出できない改ざん）
        backup_seq = pkilab.read_json(Path(b + ".manifest.json"))["audit_seq"]
        log = self.home / "audit/audit.jsonl"
        kept = log.read_text().splitlines()[:backup_seq]
        log.write_text("\n".join(kept) + "\n")
        last = json.loads(kept[-1])
        pkilab.write_json(self.home / "anchor/anchor.json", {"seq": last["seq"], "hash": last["hash"]})
        rc, rep = run(self.home, "restore", b, str(self.tmp / "r"), "--checkpoint", str(external))
        self.assertFalse(rep["freshness_confirmed"], rep)


# ---------------------------------------------------------------------------
class TestRestoreInProgress(LabCase):
    """NR03: 復元の途中で止まっても、復元先では発行・CRL 公開・再開ができない。"""

    def test_crash_after_extract_leaves_restoring_hold(self):
        self.issue()
        b = run(self.home, "backup")[1]["backup"]
        dest = self.tmp / "r"
        rc, out = run(self.home, "restore", b, str(dest), env={"PKILAB_CRASH_AT": "restore-after-extract"})
        self.assertEqual(out["error"], "SIMULATED_CRASH")
        self.assertTrue((dest / "issuer/private/intermediate.key.pem").exists())  # CA ファイルは展開済み
        self.assertEqual(pkilab.read_json(dest / "recovery/hold.json")["status"], "RESTORING")
        for argv in (["request"], ["crl-issuer"], ["crl-root"], ["revoke", "00"]):
            out = run(dest, *argv)[1]
            self.assertEqual((out["error"], out.get("hold_status")), ("RECOVERY_HOLD", "RESTORING"), argv)
        rc, out = run(dest, "resume", "--confirm", "--accept-stale", "--source-stopped", *secrets_args(self.home))
        self.assertEqual(out["action"], "held")
        self.assertTrue(out["blockers"][0].startswith("restore_incomplete"))

    def test_archive_cannot_carry_recovery_or_secrets(self):
        """アーカイブ内の recovery/（保留の印）や secrets/ は受け付けない。"""
        stage = self.tmp / "evil"
        (stage / "recovery").mkdir(parents=True)
        (stage / "recovery/hold.json").write_text("{}")
        tar_path = self.tmp / "evil.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(self.home / "root", arcname="root")
            tar.add(stage / "recovery", arcname="recovery")
        pass_file = self.home / "secrets/backup.pass"
        pkilab.ensure_passphrase(pass_file)
        enc = self.home / "backups/evil.tar.gz.enc"
        openssl("enc", "-aes-256-cbc", "-pbkdf2", "-iter", pkilab.KDF_ITER, "-salt", "-in", tar_path,
                "-out", enc, "-pass", f"file:{pass_file}")
        header = {"format": pkilab.BACKUP_FORMAT, "file": enc.name, "sha256": pkilab.sha256_file(enc),
                  "kdf_iter": pkilab.KDF_ITER, "hmac_salt": "00" * 16}
        pkilab.write_json(enc.with_name(enc.name + ".manifest.json"),
                          {**header, "hmac": pkilab._manifest_mac(pass_file, header, enc.read_bytes())})
        dest = self.tmp / "r"
        rc, out = run(self.home, "restore", str(enc), str(dest))
        self.assertEqual(out["error"], "BACKUP_UNSAFE")
        self.assertEqual(pkilab.read_json(dest / "recovery/hold.json")["status"], "RESTORING")


# ---------------------------------------------------------------------------
class TestBackupKdf(LabCase):
    """NR06: マニフェストに記録した保存時の KDF 設定で検証し、設定の改ざんも検出する。"""

    def tearDown(self):
        pkilab.KDF_ITER = 20000
        super().tearDown()

    def test_restore_with_different_current_kdf_setting(self):
        self.issue()
        b = run(self.home, "backup")[1]["backup"]
        pkilab.KDF_ITER = 200000  # 復旧側の設定が違っても
        rc, rep = run(self.home, "restore", b, str(self.tmp / "r"))
        self.assertTrue(rep["archive_integrity_ok"], rep)
        self.assertTrue(rep["ready"], rep)

    def test_backup_with_higher_iterations_restores_with_lower_setting(self):
        pkilab.KDF_ITER = 200000
        self.issue()
        b = run(self.home, "backup")[1]["backup"]
        pkilab.KDF_ITER = 20000
        self.assertTrue(run(self.home, "restore", b, str(self.tmp / "r"))[1]["archive_integrity_ok"])

    def test_manifest_tampering_and_unsupported_parameters_rejected(self):
        b = Path(run(self.home, "backup")[1]["backup"])
        man_path = b.with_name(b.name + ".manifest.json")
        original = man_path.read_text()
        for change in ({"kdf_iter": 30000}, {"kdf_iter": 10**9}, {"kdf_iter": "20000"},
                       {"format": "pkilab-backup/1"}, {"audit_seq": 1}, {"file": "other.enc"}):
            man = json.loads(original)
            man.update(change)
            man_path.write_text(json.dumps(man))
            dest = self.tmp / f"r{abs(hash(json.dumps(change)))}"
            rc, rep = run(self.home, "restore", str(b), str(dest))
            self.assertFalse(rep["archive_integrity_ok"], change)
            self.assertFalse((dest / "root").exists(), change)


# ---------------------------------------------------------------------------
class TestAdoptionChecks(LabCase):
    """NR04: 採用・配置の前に、期限・署名経路・失効・発行CAの状態を確認する。"""

    def crash(self, at: str) -> str:
        req = self.request()
        self.approve(req)
        self.assertEqual(run(self.home, "issue", req, env={"PKILAB_CRASH_AT": at})[1]["error"], "SIMULATED_CRASH")
        return req

    def test_recover_rejects_expired_signed_certificate(self):
        req = self.crash("after-sign")
        rc, out = run(self.home, "recover", req, env={"PKILAB_TEST_NOW": later(40)})
        self.assertEqual(out["action"], "quarantined", out)
        self.assertIn("expired", out["problems"])
        self.assertEqual(self.lab.state(req)["status"], "QUARANTINED")

    def test_recover_rejects_when_issuing_ca_revoked(self):
        req = self.crash("after-sign")
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        rc, out = run(self.home, "recover", req)
        self.assertEqual(out["action"], "quarantined", out)
        self.assertIn("issuer_ca_revoked", out["problems"])
        self.assertEqual(out["revocation"], "not_needed_issuer_revoked")

    def test_issued_resume_refused_when_issuing_ca_revoked(self):
        req = self.crash("after-issued")
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        rc, out = run(self.home, "issue", req)
        self.assertEqual(out["error"], "POST_ISSUE_CHECK_FAILED", out)
        self.assertIn("issuer_ca_revoked", out["problems"])
        self.assertFalse((self.home / f"server/certs/{req}.cert.pem").exists())

    def test_published_certificate_reported_unusable_after_expiry(self):
        req = self.issue()
        rc, out = run(self.home, "issue", req, env={"PKILAB_TEST_NOW": later(40)})
        self.assertEqual(out["error"], "CERT_NOT_USABLE")
        self.assertIn("expired", out["problems"])
        self.assertEqual(self.lab.state(req)["status"], "PUBLISHED")  # 正当に発行された記録は残す

    def test_issuer_name_match_is_not_a_valid_signature(self):
        """発行者名が同じでも、別の鍵で署名された証明書は採用しない。"""
        req = self.issue()
        rec = pkilab.read_json(self.home / f"requests/{req}/cert.json")
        apr = pkilab.read_json(self.home / f"approvals/{req}.json")
        fake_ca = self.tmp / "fake-ca.pem"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", self.tmp / "fake-ca.key", "-out", fake_ca, "-subj", "/CN=PKI Lab Issuing CA 1",
                "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE")
        ext = self.tmp / "e.cnf"
        ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")
        csr = self.tmp / "x.csr"
        openssl("req", "-new", "-key", self.home / self.lab.state(req)["server_key"], "-subj", "/CN=localhost",
                "-out", csr)
        forged = self.home / f"issuer/newcerts/{rec['serial']}.pem"
        openssl("x509", "-req", "-in", csr, "-CA", fake_ca, "-CAkey", self.tmp / "fake-ca.key", "-days", "5",
                "-set_serial", "0x" + rec["serial"], "-extfile", ext, "-out", forged)
        info = pkilab.cert_info(self.lab, forged)
        problems = pkilab.validate_issued(self.lab, {**rec, "cert_sha256": info["cert_sha256"]}, apr)
        self.assertTrue(any(p.startswith("chain_") for p in problems), problems)


# ---------------------------------------------------------------------------
class TestRevocationCompletion(LabCase):
    """NR08: 失効は公開 CRL への反映を確認するまで完了にしない。I/O 障害でも未完了として残る。"""

    def public_revoked(self) -> set[str]:
        return pkilab.crl_meta(self.lab, self.home / "public/crl/intermediate.crl.pem", self.lab.issuer_cert)["revoked"]

    def test_crl_publish_io_error_leaves_pending_and_blocks_signing(self):
        req = self.issue()
        serial = self.lab.state(req)["serial"]
        rc, out = run(self.home, "revoke", req, env={"PKILAB_FAULT": "crl-publish"})
        self.assertEqual(out["error"], "REVOCATION_PENDING", out)
        self.assertEqual(self.lab.ca_state()["status"], "SUSPENDED")
        self.assertNotIn(serial, self.public_revoked())
        self.assertFalse(run(self.home, "check")[1]["ok"])
        # 障害が続く間は、新しい署名の前に再試行して拒否する（台帳は増えない）
        req2 = self.request()
        self.approve(req2)
        rows = len(self.index_rows())
        rc, out = run(self.home, "issue", req2, env={"PKILAB_FAULT": "crl-publish"})
        self.assertEqual(out["error"], "REVOCATION_PENDING")
        self.assertEqual(len(self.index_rows()), rows)
        # 障害が取り除かれたら完了し、中間CAも ACTIVE に戻る
        rc, out = run(self.home, "crl-issuer")
        self.assertEqual(out["completed_revocations"], [serial], out)
        self.assertEqual(self.lab.ca_state()["status"], "ACTIVE")
        self.assertIn(serial, self.public_revoked())
        self.assertTrue(run(self.home, "check")[1]["ok"])

    def test_quarantine_with_crl_publish_failure_is_pending_not_done(self):
        req = self.request()
        self.approve(req)
        rc, out = run(self.home, "issue", req, env={"PKILAB_FORCE_POSTCHECK_FAIL": "1", "PKILAB_FAULT": "crl-publish"})
        self.assertEqual((out["error"], out["revocation"]), ("POST_ISSUE_CHECK_FAILED", "pending"), out)
        self.assertEqual(self.lab.ca_state()["status"], "SUSPENDED")
        self.assertEqual(len(pkilab.pending_revocations(self.lab, "issuer")), 1)

    def test_ledger_already_revoked_but_public_crl_stale_is_completed(self):
        req = self.issue()
        serial = self.lab.state(req)["serial"]
        stale = (self.home / "public/crl/intermediate.crl.pem").read_bytes()
        run(self.home, "revoke", req)
        (self.home / "public/crl/intermediate.crl.pem").write_bytes(stale)  # 公開物だけ古い
        self.assertNotIn(serial, self.public_revoked())
        rc, out = run(self.home, "revoke", req)  # 台帳は既に R
        self.assertEqual(rc, 0, out)
        self.assertIn(serial, self.public_revoked())
        self.assertTrue(run(self.home, "check")[1]["ok"])


# ---------------------------------------------------------------------------
class TestDeployment(LabCase):
    """NR07: fullchain・公開コピー・サーバー鍵まで確認し、壊れていれば正本から配置し直す。"""

    def test_missing_fullchain_detected_and_repaired(self):
        req = self.issue()
        (self.home / self.lab.state(req)["fullchain"]).unlink()
        out = run(self.home, "check")[1]
        self.assertTrue(any("fullchain_missing" in p for p in out["problems"]), out)
        rc, out = run(self.home, "issue", req)
        self.assertEqual((rc, out.get("republished")), (0, True), out)
        self.assertIn("fullchain_missing", out["repaired"])
        self.assertEqual(len(self.index_rows()), 1)
        self.assertTrue(run(self.home, "check")[1]["ok"])

    def test_wrong_fullchain_contents(self):
        req = self.issue()
        chain = self.home / self.lab.state(req)["fullchain"]
        leaf = (self.home / self.lab.state(req)["cert"]).read_bytes()
        root = (self.home / "public/certs/root.cert.pem").read_bytes()
        inter = (self.home / "public/certs/intermediate.cert.pem").read_bytes()
        key = (self.home / self.lab.state(req)["server_key"]).read_bytes()
        for content, expected in ((leaf, "fullchain_mismatch"), (inter + leaf, "fullchain_mismatch"),
                                  (leaf + inter + root, "fullchain_mismatch"),
                                  (leaf + key, "fullchain_bad_content")):
            chain.write_bytes(content)
            rc, out = run(self.home, "issue", req)
            self.assertIn(expected, out.get("repaired", []), out)
            self.assertEqual(pkilab.pem_cert_ders(chain.read_bytes()).__len__(), 2)

    def test_server_key_mismatch_reported(self):
        req = self.issue()
        key = self.home / self.lab.state(req)["server_key"]
        key.write_bytes(openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256").stdout)
        rc, out = run(self.home, "issue", req)
        self.assertEqual(out["error"], "SERVER_KEY_PROBLEM")


# ---------------------------------------------------------------------------
class TestRotation(LabCase):
    """NR09: ロックは世代ディレクトリの外に固定し、世代交代の途中停止から再開できる。"""

    def test_lock_lives_outside_generation_dir_and_blocks_rotation(self):
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        holder = pkilab.Lab(self.home, "other", "issuer")
        with holder.ca_lock("issuer"):
            self.assertTrue((self.home / "locks/issuer.lock").exists())
            rc, out = run(self.home, "init-issuer", "--new-generation", env={"PKILAB_LOCK_TIMEOUT": "0.3"})
            self.assertEqual(out["error"], "LOCK_BUSY")
        self.assertFalse((self.home / "issuer/lock").exists())

    def test_lock_inode_survives_rotation(self):
        """世代交代の前後で同じロックファイル（inode）を使う。"""
        lock = self.home / "locks/issuer.lock"
        run(self.home, "issue", self.request())  # ロックファイルを作らせる（承認なしで拒否されても可）
        before = lock.stat().st_ino
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        self.assertEqual(run(self.home, "init-issuer", "--new-generation")[0], 0)
        self.assertEqual(lock.stat().st_ino, before)

    def test_rotation_crash_blocks_operations_and_resumes(self):
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        rc, out = run(self.home, "init-issuer", "--new-generation", env={"PKILAB_CRASH_AT": "rotation-after-archive"})
        self.assertEqual(out["error"], "SIMULATED_CRASH")
        self.assertTrue((self.home / "rotation/issuer.json").exists())
        self.assertTrue((self.home / "archive/issuer-gen1/private/intermediate.key.pem").exists())
        for argv in (["request"], ["crl-issuer"], ["sign-intermediate"]):
            self.assertEqual(run(self.home, *argv)[1]["error"], "ROTATION_IN_PROGRESS", argv)
        self.assertEqual(run(self.home, "init-issuer")[1]["error"], "ROTATION_IN_PROGRESS")
        rc, out = run(self.home, "init-issuer", "--new-generation")
        self.assertEqual((rc, out["generation"]), (0, 2), out)
        self.assertFalse((self.home / "rotation/issuer.json").exists())
        self.assertEqual(run(self.home, "sign-intermediate")[0], 0)
        self.assertEqual(run(self.home, "crl-issuer")[0], 0)
        req = self.issue()
        self.assertEqual(run(self.home, "verify", "--request", req)[1]["code"], "OK")
        self.assertTrue(run(self.home, "check")[1]["ok"])


# ---------------------------------------------------------------------------
class TestObservationAndProfile(LabCase):
    def test_san_stop_is_not_reported_as_revocation_checked(self):
        """NR05: 名前の確認で止まった検証は、失効確認を「未実行」と記録する。"""
        req = self.issue()
        rc, out = run(self.home, "verify", "--request", req, "--host", "example.com")
        self.assertEqual((out["code"], out["stopped_at"], out["revocation_observation"]),
                         ("SAN_MISMATCH", "san_check", "not_executed"))
        rc, out = run(self.home, "export-events")
        ev = [e for e in json.loads(Path(out["events"]).read_text())["events"]
              if e["type"] == "CERT_VERIFICATION_COMPLETED"][-1]
        self.assertEqual((ev["details"]["revocation_requested"], ev["details"]["revocation_observation"],
                          ev["details"]["stopped_at"]), (True, "not_executed", "san_check"))

    def test_ip_only_certificate_passes_name_constraints(self):
        """IP だけの証明書は CN をホスト名に見えない値にし、中間CAの名前制約で拒否されない。"""
        req = self.issue("--san", "IP:127.0.0.1")
        info = pkilab.cert_info(self.lab, self.home / self.lab.state(req)["cert"])
        self.assertNotIn("127.0.0.1", info["subject"])
        self.assertEqual(run(self.home, "verify", "--request", req, "--host", "127.0.0.1")[1]["code"], "OK")
        self.assertEqual(run(self.home, "verify", "--request", req, "--host", "localhost")[1]["code"], "SAN_MISMATCH")


if __name__ == "__main__":
    unittest.main(verbosity=2)
