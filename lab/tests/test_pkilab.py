"""PKI Lab の受入試験（docs/04_acceptance-tests.md に対応）。

実行: python3 -m unittest discover -s lab/tests -v
"""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
import pkilab  # noqa: E402


def run(home: Path, *argv, role: str | None = None, env: dict | None = None) -> tuple[int, dict]:
    args = ["--home", str(home), "--actor", "tester"]
    if role:
        args += ["--role", role]
    buf = io.StringIO()
    old = dict(os.environ)
    if env:
        os.environ.update(env)
    try:
        with contextlib.redirect_stdout(buf):
            rc = pkilab.main(args + list(argv))
    finally:
        os.environ.clear()
        os.environ.update(old)
    return rc, json.loads(buf.getvalue())


def openssl(*args, **kw):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True, check=True, **kw)


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LabCase(unittest.TestCase):
    """CA を1回だけ作り、各試験はコピーした作業領域で行う。"""

    @classmethod
    def setUpClass(cls):
        pkilab.KDF_ITER = 20000  # 試験を速くする（鍵導出の反復回数を下げる）
        cls.base = Path(tempfile.mkdtemp(prefix="pkilab-base-"))
        rc, _ = run(cls.base, "init")
        assert rc == 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pkilab-t-"))
        self.home = self.tmp / "home"
        shutil.copytree(self.base, self.home, symlinks=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def issue(self, *req_args) -> str:
        rc, out = run(self.home, "request", *req_args)
        self.assertEqual(rc, 0, out)
        req = out["request"]
        rc, out = run(self.home, "approve", req)
        self.assertEqual(rc, 0, out)
        rc, out = run(self.home, "issue", req)
        self.assertEqual(rc, 0, out)
        return req

    def make_csr(self, *, key_alg=("EC", "ec_paramgen_curve:P-256"), san="DNS:localhost",
                 extra_ext: list[str] = ()) -> Path:
        key = self.tmp / "ext.key"
        alg, opt = key_alg
        cmd = ["genpkey", "-algorithm", alg, "-out", key]
        if opt:
            cmd[3:3] = ["-pkeyopt", opt]
        openssl(*cmd)
        csr = self.tmp / "ext.csr"
        args = ["req", "-new", "-key", key, "-subj", "/CN=localhost", "-out", csr]
        if san:
            args += ["-addext", f"subjectAltName={san}"]
        for e in extra_ext:
            args += ["-addext", e]
        openssl(*args)
        return csr


# ---------------------------------------------------------------------------
class TestInitAndKeys(LabCase):
    def test_keys_separated_and_encrypted(self):
        root_key = self.home / "root/private/root.key.pem"
        issuer_key = self.home / "issuer/private/intermediate.key.pem"
        self.assertIn(b"ENCRYPTED PRIVATE KEY", root_key.read_bytes())
        self.assertIn(b"ENCRYPTED PRIVATE KEY", issuer_key.read_bytes())
        self.assertEqual(root_key.stat().st_mode & 0o777, 0o600)
        # 発行用の領域（issuer/）にルート秘密鍵がない
        self.assertEqual([p for p in (self.home / "issuer").rglob("*") if "root.key" in p.name], [])
        # 公開領域に秘密鍵がない
        for p in (self.home / "public").rglob("*"):
            if p.is_file():
                self.assertNotIn(b"PRIVATE KEY", p.read_bytes())

    def test_profiles(self):
        text = openssl("x509", "-in", self.home / "issuer/certs/intermediate.cert.pem",
                       "-noout", "-text").stdout.decode()
        self.assertIn("CA:TRUE, pathlen:0", text)
        self.assertIn("Permitted:", text)
        root = openssl("x509", "-in", self.home / "root/certs/root.cert.pem", "-noout", "-text").stdout.decode()
        self.assertIn("CA:TRUE, pathlen:1", root)
        self.assertIn("prime256v1", root)

    def test_role_separation(self):
        rc, out = run(self.home, "request")
        rc, out = run(self.home, "issue", out["request"], role="ra")
        self.assertEqual(out["error"], "ROLE_DENIED")


# ---------------------------------------------------------------------------
class TestIssuance(LabCase):
    def test_issue_and_verify_ok(self):
        req = self.issue()
        rc, out = run(self.home, "verify", "--request", req)
        self.assertEqual((rc, out["result"], out["code"]), (0, "ACCEPT", "OK"))
        rc, out = run(self.home, "verify", "--request", req, "--host", "127.0.0.1")
        self.assertEqual(out["code"], "OK")
        cert = self.home / pkilab.read_json(self.home / f"requests/{req}/state.json")["cert"]
        text = openssl("x509", "-in", cert, "-noout", "-text").stdout.decode()
        self.assertIn("CA:FALSE", text)
        self.assertIn("TLS Web Server Authentication", text)
        self.assertNotIn("Client Authentication", text)

    def test_idempotent_issue(self):
        req = self.issue()
        _, a = run(self.home, "status")
        rc, out = run(self.home, "issue", req)
        self.assertTrue(out["reused"])
        self.assertEqual(len(pkilab.read_index(pkilab.Lab(self.home, "t", "auditor"), "issuer")), 1)

    def test_reject_disallowed_san(self):
        for san in ("DNS:example.com", "DNS:sub.localhost", "DNS:*.localhost", "IP:10.0.0.1"):
            rc, out = run(self.home, "request", "--san", san)
            rc, out = run(self.home, "approve", out["request"])
            self.assertEqual(out["error"], "SAN_NOT_ALLOWED", san)

    def test_reject_ca_request_in_csr(self):
        csr = self.make_csr(extra_ext=["basicConstraints=critical,CA:TRUE"])
        _, out = run(self.home, "request", "--csr", str(csr))
        rc, out = run(self.home, "approve", out["request"])
        self.assertEqual(out["error"], "CSR_FORBIDDEN_EXTENSION")

    def test_reject_client_auth_request(self):
        csr = self.make_csr(extra_ext=["extendedKeyUsage=clientAuth"])
        _, out = run(self.home, "request", "--csr", str(csr))
        rc, out = run(self.home, "approve", out["request"])
        self.assertEqual(out["error"], "CSR_FORBIDDEN_EXTENSION")

    def test_reject_rsa_key(self):
        csr = self.make_csr(key_alg=("RSA", "rsa_keygen_bits:2048"))
        _, out = run(self.home, "request", "--csr", str(csr))
        rc, out = run(self.home, "approve", out["request"])
        self.assertEqual(out["error"], "CSR_BAD_KEY")

    def test_reject_missing_san(self):
        csr = self.make_csr(san=None)
        _, out = run(self.home, "request", "--csr", str(csr))
        rc, out = run(self.home, "approve", out["request"])
        self.assertEqual(out["error"], "SAN_REQUIRED")

    def test_reject_oversized_csr(self):
        big = self.tmp / "big.csr"
        big.write_bytes(b"-----BEGIN CERTIFICATE REQUEST-----\n" + b"A" * (70 * 1024))
        rc, out = run(self.home, "request", "--csr", str(big))
        self.assertEqual(out["error"], "CSR_TOO_LARGE")

    def test_reject_tampered_csr_signature(self):
        csr = self.make_csr()
        der = openssl("req", "-in", csr, "-outform", "DER").stdout
        der = der[:-3] + bytes([der[-3] ^ 0xFF]) + der[-2:]  # 署名値を1バイト改変
        pem = openssl("req", "-inform", "DER", "-outform", "PEM", input=der).stdout
        bad = self.tmp / "bad.csr"
        bad.write_bytes(pem)
        _, out = run(self.home, "request", "--csr", str(bad))
        rc, out = run(self.home, "approve", out["request"])
        self.assertEqual(out["error"], "CSR_BAD_SIGNATURE")

    def test_issue_without_approval(self):
        _, out = run(self.home, "request")
        rc, out = run(self.home, "issue", out["request"])
        self.assertEqual(out["error"], "NOT_APPROVED")

    def test_csr_changed_after_approval(self):
        _, out = run(self.home, "request")
        req = out["request"]
        run(self.home, "approve", req)
        shutil.copy(self.make_csr(), self.home / f"requests/{req}/request.csr.pem")
        rc, out = run(self.home, "issue", req)
        self.assertEqual(out["error"], "APPROVAL_MISMATCH")

    def test_approval_expired(self):
        _, out = run(self.home, "request")
        req = out["request"]
        run(self.home, "approve", req)
        p = self.home / f"approvals/{req}.json"
        a = pkilab.read_json(p)
        a["expires_at"] = "2000-01-01T00:00:00Z"
        pkilab.write_json(p, a)
        rc, out = run(self.home, "issue", req)
        self.assertEqual(out["error"], "APPROVAL_EXPIRED")

    def test_lock_busy(self):
        _, out = run(self.home, "request")
        req = out["request"]
        run(self.home, "approve", req)
        lab = pkilab.Lab(self.home, "other", "issuer")
        with lab.ca_lock("issuer"):
            rc, out = run(self.home, "issue", req, env={"PKILAB_LOCK_TIMEOUT": "0.3"})
        self.assertEqual(out["error"], "LOCK_BUSY")
        rc, out = run(self.home, "issue", req)
        self.assertEqual(rc, 0)

    def test_crash_and_recover_without_double_issue(self):
        _, out = run(self.home, "request")
        req = out["request"]
        run(self.home, "approve", req)
        rc, out = run(self.home, "issue", req, env={"PKILAB_CRASH_AFTER_JOURNAL": "1"})
        self.assertEqual(out["error"], "SIMULATED_CRASH")
        rc, out = run(self.home, "issue", req)
        self.assertEqual(out["error"], "NEEDS_RECOVERY")
        rc, out = run(self.home, "recover", req)
        self.assertEqual(out["action"], "returned_to_approved")
        rc, out = run(self.home, "issue", req)
        self.assertEqual(rc, 0, out)

    def test_recover_adopts_already_signed_certificate(self):
        req = self.issue()
        lab = pkilab.Lab(self.home, "t", "issuer")
        serial = lab.state(req)["serial"]
        # 「署名は終わったが記録前に停止した」状態を再現
        st = pkilab.read_json(self.home / f"requests/{req}/state.json")
        st["status"] = "SIGNING"
        pkilab.write_json(self.home / f"requests/{req}/state.json", st)
        rc, out = run(self.home, "recover", req)
        self.assertEqual((out["action"], out["serial"]), ("adopted_existing_certificate", serial))
        self.assertEqual(len(pkilab.read_index(lab, "issuer")), 1)


# ---------------------------------------------------------------------------
class TestVerification(LabCase):
    def test_untrusted_anchor(self):
        other = self.tmp / "other"
        other.mkdir()
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", other / "k.pem", "-out", other / "root.pem", "-subj", "/CN=Other Root",
                "-days", "30", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        req = self.issue()
        rc, out = run(self.home, "verify", "--request", req, "--trust", str(other / "root.pem"), "--no-crl")
        self.assertEqual((rc, out["code"]), (1, "UNTRUSTED_ANCHOR"))

    def test_hostname_mismatch(self):
        req = self.issue()
        rc, out = run(self.home, "verify", "--request", req, "--host", "example.com")
        self.assertEqual(out["code"], "SAN_MISMATCH")
        rc, out = run(self.home, "verify", "--request", req, "--host", "127.0.0.2")
        self.assertEqual(out["code"], "SAN_MISMATCH")

    def test_wrong_purpose(self):
        req = self.issue()
        rc, out = run(self.home, "verify", "--request", req, "--purpose", "sslclient")
        self.assertEqual(out["code"], "WRONG_EKU")

    def test_expired(self):
        req = self.issue()
        later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rc, out = run(self.home, "verify", "--request", req, "--attime", later, "--no-crl")
        self.assertEqual(out["code"], "CERT_EXPIRED")

    def test_crl_expired_is_indeterminate(self):
        req = self.issue()
        later = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rc, out = run(self.home, "verify", "--request", req, "--attime", later)
        self.assertEqual((out["result"], out["code"]), ("INDETERMINATE", "CRL_EXPIRED"))

    def test_crl_missing_is_indeterminate(self):
        req = self.issue()
        (self.home / "public/crl/root.crl.pem").unlink()
        rc, out = run(self.home, "verify", "--request", req)
        self.assertEqual((rc, out["result"], out["code"]), (1, "INDETERMINATE", "CRL_MISSING"))

    def test_leaf_revoked(self):
        req = self.issue()
        run(self.home, "revoke", req, "--reason", "keyCompromise")
        rc, out = run(self.home, "verify", "--request", req)
        self.assertEqual(out["code"], "LEAF_REVOKED")
        # 失効確認をしなければ通ってしまう（前回実験の重要な結果）
        rc, out = run(self.home, "verify", "--request", req, "--no-crl")
        self.assertEqual(out["code"], "OK")

    def test_intermediate_revoked(self):
        req = self.issue()
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        rc, out = run(self.home, "verify", "--request", req)
        self.assertEqual(out["code"], "INTERMEDIATE_REVOKED")

    def test_name_constraints_block_misissuance(self):
        """CA の審査を迂回して中間CA鍵で直接署名した場合も、検証側で名前制約が働く。"""
        csr = self.make_csr(san="DNS:example.com")
        ext = self.tmp / "ext.cnf"
        ext.write_text("subjectAltName=DNS:example.com\nbasicConstraints=critical,CA:FALSE\n"
                       "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                       "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        bad = self.tmp / "bad.pem"
        openssl("x509", "-req", "-in", csr, "-CA", self.home / "issuer/certs/intermediate.cert.pem",
                "-CAkey", self.home / "issuer/private/intermediate.key.pem",
                "-passin", f"file:{self.home / 'secrets/issuer.pass'}", "-days", "1",
                "-extfile", ext, "-out", bad)
        rc, out = run(self.home, "verify", "--cert", str(bad), "--host", "example.com", "--no-crl")
        self.assertEqual(out["code"], "NAME_CONSTRAINT_VIOLATION")

    def test_cn_only_certificate_rejected(self):
        bad = self.tmp / "cn.pem"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", self.tmp / "k.pem", "-out", bad, "-subj", "/CN=localhost", "-days", "1")
        rc, out = run(self.home, "verify", "--cert", str(bad))
        self.assertEqual(out["code"], "SAN_REQUIRED")


# ---------------------------------------------------------------------------
class TestRealTLS(LabCase):
    def serve(self, req):
        lab = pkilab.Lab(self.home, "t", "server-admin")
        port = free_port()
        srv = pkilab.make_https_server(lab, req, "127.0.0.1", port)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return port

    def test_tls_accept_then_reject_after_revocation(self):
        req = self.issue()
        port = self.serve(req)
        rc, out = run(self.home, "client", "--port", str(port))
        self.assertEqual((out["result"], out["tls_version"]), ("ACCEPT", "TLSv1.3"))
        run(self.home, "revoke", req)
        rc, out = run(self.home, "client", "--port", str(port))
        self.assertEqual(out["code"], "LEAF_REVOKED")
        # 失効確認をしないクライアントは接続できてしまう
        rc, out = run(self.home, "client", "--port", str(port), "--no-crl")
        self.assertEqual(out["result"], "ACCEPT")

    def test_tls_intermediate_revoked(self):
        req = self.issue()
        port = self.serve(req)
        run(self.home, "revoke-intermediate")
        rc, out = run(self.home, "client", "--port", str(port))
        self.assertEqual(out["code"], "INTERMEDIATE_REVOKED")

    def test_tls_wrong_host(self):
        req = self.issue()
        port = self.serve(req)
        rc, out = run(self.home, "client", "--port", str(port), "--host", "example.com")
        self.assertEqual(out["code"], "SAN_MISMATCH")

    @unittest.skipUnless(shutil.which("curl"), "curl がありません")
    def test_curl_does_not_check_revocation_by_default(self):
        req = self.issue()
        port = self.serve(req)
        run(self.home, "revoke", req)
        root = self.home / "public/certs/root.cert.pem"
        url = f"https://localhost:{port}/"
        base = ["curl", "-sS", "--noproxy", "*", "--resolve", f"localhost:{port}:127.0.0.1",
                "--cacert", str(root), url]
        self.assertEqual(subprocess.run(base, capture_output=True).returncode, 0)
        crl = self.home / "public/crl/intermediate.crl.pem"
        r = subprocess.run(base[:-1] + ["--crlfile", str(crl), url], capture_output=True)
        self.assertNotEqual(r.returncode, 0)


# ---------------------------------------------------------------------------
class TestAuditAndRecovery(LabCase):
    def test_audit_chain_ok_and_tamper_detected(self):
        self.issue()
        rc, out = run(self.home, "audit-verify")
        self.assertTrue(out["ok"])
        log = self.home / "audit/audit.jsonl"
        lines = log.read_text().splitlines()
        e = json.loads(lines[2])
        e["result"] = "forged"
        lines[2] = json.dumps(e, ensure_ascii=False)
        log.write_text("\n".join(lines) + "\n")
        rc, out = run(self.home, "audit-verify")
        self.assertEqual(out["error"], "AUDIT_TAMPERED")

    def test_audit_truncation_detected_by_anchor(self):
        self.issue()
        log = self.home / "audit/audit.jsonl"
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:-2]) + "\n")
        rc, out = run(self.home, "audit-verify")
        self.assertEqual(out["error"], "AUDIT_TRUNCATED_OR_REWRITTEN")

    def test_consistency_check(self):
        req = self.issue()
        run(self.home, "revoke", req)
        rc, out = run(self.home, "check")
        self.assertTrue(out["ok"], out)
        # 発行物の消失を検出する
        lab = pkilab.Lab(self.home, "t", "auditor")
        (self.home / f"issuer/newcerts/{lab.state(req)['serial']}.pem").unlink()
        rc, out = run(self.home, "check")
        self.assertFalse(out["ok"])

    def test_backup_and_restore(self):
        self.issue()
        rc, out = run(self.home, "backup")
        self.assertEqual(rc, 0)
        blob = Path(out["backup"]).read_bytes()
        self.assertNotIn(b"PRIVATE KEY", blob)
        dest = self.tmp / "restored"
        rc, rep = run(self.home, "restore", out["backup"], str(dest))
        self.assertTrue(rep["ready"], rep)
        self.assertTrue((dest / "issuer/db/index.txt").exists())

    def test_export_events_has_no_secrets(self):
        req = self.issue()
        run(self.home, "verify", "--request", req)
        run(self.home, "revoke", req)
        run(self.home, "verify", "--request", req)
        rc, out = run(self.home, "export-events")
        doc = json.loads(Path(out["events"]).read_text())
        types = [e["type"] for e in doc["events"]]
        for t in ("CSR_CREATED", "REQUEST_AUTHORIZED", "CERT_ISSUED", "VERIFY_ACCEPTED",
                  "CERT_REVOKED", "CRL_PUBLISHED", "VERIFY_REJECTED"):
            self.assertIn(t, types)
        text = Path(out["events"]).read_text()
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn(pkilab.Lab(self.home, "t", "auditor").state(req)["serial"], text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
