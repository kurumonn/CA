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

ENV_FAST = {"PKILAB_KDF_ITER": "20000"}


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


def run_cli(home: Path, *argv) -> subprocess.CompletedProcess:
    """別プロセスで CLI を実行する（同時実行の試験用）。"""
    return subprocess.run([sys.executable, str(LAB / "pkilab.py"), "--home", str(home), *argv],
                          capture_output=True, text=True, env={**os.environ, **ENV_FAST})


def openssl(*args, **kw):
    return subprocess.run(["openssl", *map(str, args)], capture_output=True, check=True, **kw)


def free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def later(days: float) -> str:
    return (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


class LabCase(unittest.TestCase):
    """CA を1回だけ作り、各試験はコピーした作業領域で行う。"""

    @classmethod
    def setUpClass(cls):
        pkilab.KDF_ITER = 20000  # 試験を速くする（鍵導出の反復回数を下げる）
        cls.base = Path(tempfile.mkdtemp(prefix="pkilab-base-"))
        rc, out = run(cls.base, "init")
        assert rc == 0, out

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="pkilab-t-"))
        self.home = self.tmp / "home"
        shutil.copytree(self.base, self.home, symlinks=True)
        self.lab = pkilab.Lab(self.home, "tester", "auditor")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def request(self, *req_args) -> str:
        rc, out = run(self.home, "request", *req_args)
        self.assertEqual(rc, 0, out)
        return out["request"]

    def approve(self, req: str) -> None:
        rc, out = run(self.home, "approve", req)
        self.assertEqual(rc, 0, out)

    def issue(self, *req_args) -> str:
        req = self.request(*req_args)
        self.approve(req)
        rc, out = run(self.home, "issue", req)
        self.assertEqual(rc, 0, out)
        return req

    def index_rows(self) -> list[dict]:
        return pkilab.read_index(self.home / "issuer")

    def make_key(self, alg=("EC", "ec_paramgen_curve:P-256"), name="ext.key") -> Path:
        key = self.tmp / name
        cmd = ["genpkey", "-algorithm", alg[0], "-out", key]
        if alg[1]:
            cmd[3:3] = ["-pkeyopt", alg[1]]
        openssl(*cmd)
        return key

    def make_csr(self, *, key: Path | None = None, key_alg=("EC", "ec_paramgen_curve:P-256"),
                 san="DNS:localhost", subj="/CN=localhost", extra_ext=()) -> Path:
        key = key or self.make_key(key_alg)
        csr = self.tmp / "ext.csr"
        args = ["req", "-new", "-key", key, "-subj", subj, "-out", csr]
        if san:
            args += ["-addext", f"subjectAltName={san}"]
        for e in extra_ext:
            args += ["-addext", e]
        openssl(*args)
        return csr

    def misissue(self, ext_lines: str, subj="/CN=localhost") -> Path:
        """審査を迂回して中間CA鍵で直接署名した証明書（検証側の試験用）。"""
        csr = self.make_csr(san=None, subj=subj)
        ext = self.tmp / "mis.cnf"
        ext.write_text(ext_lines + "\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                       "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
        out = self.tmp / "mis.pem"
        openssl("x509", "-req", "-in", csr, "-CA", self.home / "issuer/certs/intermediate.cert.pem",
                "-CAkey", self.home / "issuer/private/intermediate.key.pem",
                "-passin", f"file:{self.home / 'secrets/issuer.pass'}", "-days", "1",
                "-extfile", ext, "-out", out)
        return out


# ---------------------------------------------------------------------------
class TestInitAndKeys(LabCase):
    def test_keys_separated_and_encrypted(self):
        root_key = self.home / "root/private/root.key.pem"
        issuer_key = self.home / "issuer/private/intermediate.key.pem"
        self.assertIn(b"ENCRYPTED PRIVATE KEY", root_key.read_bytes())
        self.assertIn(b"ENCRYPTED PRIVATE KEY", issuer_key.read_bytes())
        self.assertEqual(root_key.stat().st_mode & 0o777, 0o600)
        self.assertEqual([p for p in (self.home / "issuer").rglob("*") if "root.key" in p.name], [])
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
        self.assertEqual(self.lab.ca_state()["status"], "ACTIVE")

    def test_role_separation(self):
        req = self.request()
        rc, out = run(self.home, "issue", req, role="ra")
        self.assertEqual(out["error"], "ROLE_DENIED")


# ---------------------------------------------------------------------------
class TestIssuance(LabCase):
    def test_issue_and_verify_ok(self):
        req = self.issue()
        for host in ("localhost", "127.0.0.1"):
            rc, out = run(self.home, "verify", "--request", req, "--host", host)
            self.assertEqual((rc, out["result"], out["code"]), (0, "ACCEPT", "OK"), host)
        info = pkilab.cert_info(self.lab, self.home / self.lab.state(req)["cert"])
        self.assertEqual((info["ca"], info["eku"], info["ku"]), (False, ["serverAuth"], ["digitalSignature"]))

    def test_idempotent_issue(self):
        req = self.issue()
        rc, out = run(self.home, "issue", req)
        self.assertTrue(out["reused"])
        self.assertEqual(len(self.index_rows()), 1)

    def test_reissue_republishes_tampered_deployment(self):
        req = self.issue()
        leaf = self.home / self.lab.state(req)["cert"]
        leaf.write_text("garbage")
        rc, out = run(self.home, "issue", req)
        self.assertTrue(out.get("republished"), out)
        self.assertEqual(len(self.index_rows()), 1)
        self.assertEqual(pkilab.cert_info(self.lab, leaf)["serial"], out["serial"])

    def test_reject_disallowed_san(self):
        for san in ("DNS:example.com", "DNS:sub.localhost", "DNS:*.localhost", "IP:10.0.0.1"):
            req = self.request("--san", san)
            rc, out = run(self.home, "approve", req)
            self.assertEqual(out["error"], "SAN_NOT_ALLOWED", san)

    def test_reject_forbidden_extensions(self):
        for ext in ("basicConstraints=critical,CA:TRUE", "extendedKeyUsage=clientAuth",
                    "keyUsage=keyCertSign", "extendedKeyUsage=serverAuth,codeSigning"):
            csr = self.make_csr(extra_ext=[ext])
            req = self.request("--csr", str(csr))
            rc, out = run(self.home, "approve", req)
            self.assertEqual(out["error"], "CSR_FORBIDDEN_EXTENSION", ext)

    def test_reject_non_p256_keys(self):
        for alg in (("RSA", "rsa_keygen_bits:2048"), ("EC", "ec_paramgen_curve:P-384"), ("ED25519", None)):
            csr = self.make_csr(key_alg=alg)
            req = self.request("--csr", str(csr))
            rc, out = run(self.home, "approve", req)
            self.assertEqual(out["error"], "CSR_BAD_KEY", alg)

    def test_key_type_not_spoofable_via_subject(self):
        """F09: Subject に id-ecPublicKey / prime256v1 を書いた RSA の CSR も拒否する。"""
        csr = self.make_csr(key_alg=("RSA", "rsa_keygen_bits:2048"),
                            subj="/CN=localhost/O=id-ecPublicKey prime256v1 NIST CURVE: P-256")
        req = self.request("--csr", str(csr))
        rc, out = run(self.home, "approve", req)
        self.assertEqual(out["error"], "CSR_BAD_KEY")

    def test_requested_extension_text_in_subject_is_ignored(self):
        """表示テキストではなく構造で読むので、Subject の文字列で SAN を偽装できない。"""
        csr = self.make_csr(san=None, subj="/CN=localhost/O=X509v3 Subject Alternative Name: DNS:localhost")
        req = self.request("--csr", str(csr))
        rc, out = run(self.home, "approve", req)
        self.assertEqual(out["error"], "SAN_REQUIRED")

    def test_reject_missing_san_oversize_and_tampered(self):
        req = self.request("--csr", str(self.make_csr(san=None)))
        self.assertEqual(run(self.home, "approve", req)[1]["error"], "SAN_REQUIRED")
        big = self.tmp / "big.csr"
        big.write_bytes(b"-----BEGIN CERTIFICATE REQUEST-----\n" + b"A" * (70 * 1024))
        self.assertEqual(run(self.home, "request", "--csr", str(big))[1]["error"], "CSR_TOO_LARGE")
        csr = self.make_csr()
        der = openssl("req", "-in", csr, "-outform", "DER").stdout
        der = der[:-3] + bytes([der[-3] ^ 0xFF]) + der[-2:]  # 署名値を1バイト改変
        bad = self.tmp / "bad.csr"
        bad.write_bytes(openssl("req", "-inform", "DER", "-outform", "PEM", input=der).stdout)
        req = self.request("--csr", str(bad))
        self.assertEqual(run(self.home, "approve", req)[1]["error"], "CSR_BAD_SIGNATURE")

    def test_approval_bindings(self):
        req = self.request()
        self.assertEqual(run(self.home, "issue", req)[1]["error"], "NOT_APPROVED")
        self.approve(req)
        shutil.copy(self.make_csr(), self.home / f"requests/{req}/request.csr.pem")
        self.assertEqual(run(self.home, "issue", req)[1]["error"], "APPROVAL_MISMATCH")
        req2 = self.request()
        self.approve(req2)
        p = self.home / f"approvals/{req2}.json"
        a = pkilab.read_json(p)
        a["expires_at"] = "2000-01-01T00:00:00Z"
        pkilab.write_json(p, a)
        self.assertEqual(run(self.home, "issue", req2)[1]["error"], "APPROVAL_EXPIRED")

    def test_lock_busy(self):
        req = self.request()
        self.approve(req)
        with pkilab.Lab(self.home, "other", "issuer").ca_lock("issuer"):
            rc, out = run(self.home, "issue", req, env={"PKILAB_LOCK_TIMEOUT": "0.3"})
        self.assertEqual(out["error"], "LOCK_BUSY")
        self.assertEqual(run(self.home, "issue", req)[0], 0)

    def test_postcheck_failure_revokes_and_publishes_crl(self):
        """F14: 発行後検査の不合格は、失効と CRL 公開まで確定してから隔離する。"""
        req = self.request()
        self.approve(req)
        rc, out = run(self.home, "issue", req, env={"PKILAB_FORCE_POSTCHECK_FAIL": "1"})
        self.assertEqual(out["error"], "POST_ISSUE_CHECK_FAILED")
        self.assertEqual(out["revocation"], "done")
        serial = self.index_rows()[0]["serial"]
        self.assertEqual(self.index_rows()[0]["status"], "R")
        meta = pkilab.crl_meta(self.lab, self.home / "public/crl/intermediate.crl.pem", self.lab.issuer_cert)
        self.assertIn(serial, meta["revoked"])
        self.assertEqual(self.lab.state(req)["status"], "QUARANTINED")


# ---------------------------------------------------------------------------
class TestRecovery(LabCase):
    def crash(self, at: str) -> str:
        req = self.request()
        self.approve(req)
        rc, out = run(self.home, "issue", req, env={"PKILAB_CRASH_AT": at})
        self.assertEqual(out["error"], "SIMULATED_CRASH")
        return req

    def test_crash_before_sign_returns_to_approved(self):
        req = self.crash("before-sign")
        self.assertEqual(run(self.home, "issue", req)[1]["error"], "NEEDS_RECOVERY")
        self.assertEqual(run(self.home, "recover", req)[1]["action"], "returned_to_approved")
        self.assertEqual(run(self.home, "issue", req)[0], 0)
        self.assertEqual(len(self.index_rows()), 1)

    def test_crash_after_sign_adopts_without_resigning(self):
        req = self.crash("after-sign")
        rc, out = run(self.home, "recover", req)
        self.assertEqual(out["action"], "adopted_signed_certificate", out)
        self.assertEqual(len(self.index_rows()), 1)
        self.assertEqual(self.lab.state(req)["status"], "PUBLISHED")

    def test_crash_after_issued_resumes_publish(self):
        """F03: ISSUED 直後の停止から、再署名せずに配置だけ再開する（issue / recover の両方）。"""
        req = self.crash("after-issued")
        self.assertEqual(self.lab.state(req)["status"], "ISSUED")
        rc, out = run(self.home, "issue", req)
        self.assertEqual((rc, out.get("resumed")), (0, "publish"), out)
        self.assertEqual(len(self.index_rows()), 1)
        req2 = self.crash("after-issued")
        rc, out = run(self.home, "recover", req2)
        self.assertEqual(out["action"], "completed_publish", out)
        self.assertEqual(len(self.index_rows()), 2)

    def test_recover_does_not_adopt_other_requests_revoked_cert(self):
        """F02: 同じ鍵で発行・失効済みの別申請の証明書を採用しない。"""
        req_a = self.issue()
        run(self.home, "revoke", req_a)
        key = self.home / self.lab.state(req_a)["server_key"]
        req_b = self.request("--key", str(key), "--san", "IP:127.0.0.1")
        self.approve(req_b)
        run(self.home, "issue", req_b, env={"PKILAB_CRASH_AT": "before-sign"})
        rc, out = run(self.home, "recover", req_b)
        self.assertEqual(out["action"], "returned_to_approved", out)
        # 署名後に止まった場合は、B 自身の証明書（SAN=IP）だけを採用する
        run(self.home, "issue", req_b, env={"PKILAB_CRASH_AT": "after-sign"})
        rc, out = run(self.home, "recover", req_b)
        self.assertEqual(out["action"], "adopted_signed_certificate", out)
        info = pkilab.cert_info(self.lab, self.home / self.lab.state(req_b)["cert"])
        self.assertEqual(info["san"], ["IP:127.0.0.1"])
        self.assertNotEqual(info["serial"], self.lab.state(req_a)["serial"])

    def test_recover_quarantines_ambiguous_candidates(self):
        req_a = self.issue()
        key = self.home / self.lab.state(req_a)["server_key"]
        req_b = self.request("--key", str(key))
        self.approve(req_b)
        run(self.home, "issue", req_b, env={"PKILAB_CRASH_AT": "after-sign"})
        # A の発行記録が失われ、B の操作記録もシリアルを持たない状況を作る
        (self.home / f"requests/{req_a}/cert.json").unlink()
        op = self.lab.state(req_b)["op_id"]
        j = pkilab.read_json(self.home / f"journal/{op}.json")
        for k in ("serial", "cert_sha256"):
            j.pop(k)
        j["index_rows_before"] = 0
        pkilab.write_json(self.home / f"journal/{op}.json", j)
        rc, out = run(self.home, "recover", req_b)
        self.assertEqual(out["action"], "quarantined")
        self.assertEqual(len(out["candidates"]), 2)

    def test_recover_rejects_cert_that_does_not_match_approval(self):
        req = self.crash("after-sign")
        op = self.lab.state(req)["op_id"]
        serial = pkilab.read_json(self.home / f"journal/{op}.json")["serial"]
        # 台帳上で失効状態にしておく（承認内容と合わない発行物として扱われる）
        idx = self.home / "issuer/db/index.txt"
        idx.write_text(idx.read_text().replace("V\t", "R\t", 1).replace("\t\t", "\t261008000000Z\t", 1))
        rc, out = run(self.home, "recover", req)
        self.assertEqual(out["action"], "quarantined", out)
        self.assertEqual(self.lab.state(req)["status"], "QUARANTINED")
        self.assertIn(serial, self.lab.state(req)["serial"])


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
        for host in ("example.com", "127.0.0.2"):
            self.assertEqual(run(self.home, "verify", "--request", req, "--host", host)[1]["code"], "SAN_MISMATCH")

    def test_no_cn_fallback_when_only_ip_san(self):
        """F01: CN=localhost・SAN=IP のみの証明書は、localhost として受理しない。"""
        cert = self.misissue("subjectAltName=IP:127.0.0.1")
        rc, out = run(self.home, "verify", "--cert", str(cert), "--host", "localhost")
        self.assertEqual((out["result"], out["code"]), ("REJECT", "SAN_MISMATCH"))
        self.assertIn("DNS 型の SAN", out["detail"])
        # IP として接続する場合は通る（型どおり）
        self.assertEqual(run(self.home, "verify", "--cert", str(cert), "--host", "127.0.0.1")[1]["code"], "OK")

    def test_no_cn_fallback_other_san_types(self):
        for ext in ("subjectAltName=email:a@localhost", "subjectAltName=DNS:other.localhost"):
            cert = self.misissue(ext)
            rc, out = run(self.home, "verify", "--cert", str(cert), "--host", "localhost", "--no-crl")
            self.assertEqual(out["code"], "SAN_MISMATCH", ext)

    def test_cn_only_certificate_rejected(self):
        bad = self.tmp / "cn.pem"
        openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                "-keyout", self.tmp / "k.pem", "-out", bad, "-subj", "/CN=localhost", "-days", "1")
        self.assertEqual(run(self.home, "verify", "--cert", str(bad))[1]["code"], "SAN_REQUIRED")

    def test_wrong_purpose_and_expired(self):
        req = self.issue()
        self.assertEqual(run(self.home, "verify", "--request", req, "--purpose", "sslclient")[1]["code"], "WRONG_EKU")
        rc, out = run(self.home, "verify", "--request", req, "--attime", later(45), "--no-crl")
        self.assertEqual(out["code"], "CERT_EXPIRED")

    def test_crl_problems_are_indeterminate(self):
        req = self.issue()
        rc, out = run(self.home, "verify", "--request", req, "--attime", later(2))
        self.assertEqual((out["result"], out["code"]), ("INDETERMINATE", "CRL_EXPIRED"))
        (self.home / "public/crl/root.crl.pem").unlink()
        rc, out = run(self.home, "verify", "--request", req)
        self.assertEqual((rc, out["result"], out["code"]), (1, "INDETERMINATE", "CRL_MISSING"))

    def test_leaf_and_intermediate_revoked(self):
        req = self.issue()
        run(self.home, "revoke", req, "--reason", "keyCompromise")
        self.assertEqual(run(self.home, "verify", "--request", req)[1]["code"], "LEAF_REVOKED")
        # 失効確認をしなければ通ってしまう（前回実験の重要な結果）
        self.assertEqual(run(self.home, "verify", "--request", req, "--no-crl")[1]["code"], "OK")
        req2 = self.issue()
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        self.assertEqual(run(self.home, "verify", "--request", req2)[1]["code"], "INTERMEDIATE_REVOKED")

    def test_name_constraints_block_misissuance(self):
        cert = self.misissue("subjectAltName=DNS:example.com")
        rc, out = run(self.home, "verify", "--cert", str(cert), "--host", "example.com", "--no-crl")
        self.assertEqual(out["code"], "NAME_CONSTRAINT_VIOLATION")


# ---------------------------------------------------------------------------
class TestCAState(LabCase):
    def test_revoked_intermediate_stops_issuance(self):
        """F10: 中間CAを失効させたら、CLI 側の新規発行も止まる。"""
        req = self.request()
        self.approve(req)
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        rc, out = run(self.home, "issue", req)
        self.assertEqual((out["error"], out["ca_state"]), ("CA_NOT_ACTIVE", "REVOKED"))
        self.assertEqual(len(self.index_rows()), 0)

    def test_issuance_stops_when_root_crl_lists_intermediate(self):
        req = self.request()
        self.approve(req)
        # 状態ファイルは ACTIVE のまま、ルート CRL にだけ失効が載っている場合
        lab = pkilab.Lab(self.home, "t", "root-admin")
        pkilab._revoke_in(lab, pkilab.ROOT_CNF, self.home / f"root/newcerts/{pkilab.cert_info(lab, lab.issuer_cert)['serial']}.pem",
                          "CACompromise", lab.root_pass)
        run(self.home, "crl-root")
        self.assertEqual(run(self.home, "issue", req)[1]["error"], "CA_NOT_ACTIVE")

    def test_new_generation_after_compromise(self):
        old_req = self.issue()
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        # 同じ鍵のまま再署名して復帰することはできない
        self.assertEqual(run(self.home, "sign-intermediate")[1]["error"], "ALREADY_SIGNED")
        self.assertEqual(run(self.home, "init-issuer")[1]["error"], "ALREADY_INITIALIZED")
        rc, out = run(self.home, "init-issuer", "--new-generation")
        self.assertEqual((rc, out["generation"]), (0, 2), out)
        self.assertEqual(run(self.home, "sign-intermediate")[0], 0)
        self.assertEqual(run(self.home, "crl-issuer")[0], 0)
        req = self.issue()
        self.assertEqual(run(self.home, "verify", "--request", req)[1]["code"], "OK")
        self.assertEqual(run(self.home, "verify", "--request", old_req)[1]["code"], "UNTRUSTED_ANCHOR")
        rc, out = run(self.home, "check")
        self.assertTrue(out["ok"], out)

    def test_key_reuse_rejected(self):
        run(self.home, "revoke-intermediate", "--reason", "CACompromise")
        st = pkilab.read_json(self.home / "issuer/state.json")
        st["status"] = "PENDING"  # 状態だけを書き換えて、同じ鍵で再署名させようとする
        pkilab.write_json(self.home / "issuer/state.json", st)
        self.assertEqual(run(self.home, "sign-intermediate")[1]["error"], "KEY_REUSE")


# ---------------------------------------------------------------------------
class TestRealTLS(LabCase):
    def serve(self, req):
        lab = pkilab.Lab(self.home, "t", "server-admin")
        port = free_port()
        srv = pkilab.make_https_server(lab, req, "127.0.0.1", port)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
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
        # F12: 同じ接続で部位を確定できないので REVOKED。推定は未検証の参考情報として分ける
        self.assertEqual((out["result"], out["code"]), ("REJECT", "REVOKED"))
        self.assertEqual(out["diagnostic"]["probable"], "LEAF_REVOKED")
        self.assertFalse(out["diagnostic"]["verified"])
        rc, out = run(self.home, "client", "--port", str(port), "--no-crl")
        self.assertEqual(out["result"], "ACCEPT")

    def test_tls_intermediate_revoked(self):
        req = self.issue()
        port = self.serve(req)
        run(self.home, "revoke-intermediate")
        rc, out = run(self.home, "client", "--port", str(port))
        self.assertEqual((out["code"], out["diagnostic"]["probable"]), ("REVOKED", "INTERMEDIATE_REVOKED"))

    def test_tls_wrong_host(self):
        port = self.serve(self.issue())
        self.assertEqual(run(self.home, "client", "--port", str(port), "--host", "example.com")[1]["code"],
                         "SAN_MISMATCH")

    @unittest.skipUnless(shutil.which("curl"), "curl がありません")
    def test_curl_does_not_check_revocation_by_default(self):
        req = self.issue()
        port = self.serve(req)
        run(self.home, "revoke", req)
        root = self.home / "public/certs/root.cert.pem"
        url = f"https://localhost:{port}/"
        base = ["curl", "-sS", "--noproxy", "*", "--resolve", f"localhost:{port}:127.0.0.1", "--cacert", str(root)]
        self.assertEqual(subprocess.run(base + [url], capture_output=True).returncode, 0)
        crl = self.home / "public/crl/intermediate.crl.pem"
        self.assertNotEqual(subprocess.run(base + ["--crlfile", str(crl), url], capture_output=True).returncode, 0)


# ---------------------------------------------------------------------------
class TestAudit(LabCase):
    def test_tamper_detected_and_frozen(self):
        self.issue()
        self.assertTrue(run(self.home, "audit-verify")[1]["ok"])
        log = self.home / "audit/audit.jsonl"
        lines = log.read_text().splitlines()
        e = json.loads(lines[2])
        e["result"] = "forged"
        lines[2] = json.dumps(e, ensure_ascii=False)
        log.write_text("\n".join(lines) + "\n")
        self.assertEqual(run(self.home, "audit-verify")[1]["error"], "AUDIT_TAMPERED")
        self.assertEqual(run(self.home, "request")[1]["error"], "AUDIT_FROZEN")
        self.assertEqual(run(self.home, "audit-reanchor", "--reason", "x", "--confirm-head", "x")[1]["error"],
                         "AUDIT_TAMPERED")

    def test_truncation_is_not_normalized_by_later_operations(self):
        """F04: 末尾削除の検出後に check や request を実行しても、異常が消えない。"""
        req = self.issue()
        log = self.home / "audit/audit.jsonl"
        anchor_before = (self.home / "anchor/anchor.json").read_text()
        lines = log.read_text().splitlines()
        log.write_text("\n".join(lines[:-2]) + "\n")
        log_after_truncate = log.read_text()
        for _ in range(2):
            rc, out = run(self.home, "check")
            self.assertFalse(out["ok"])
            self.assertEqual(run(self.home, "audit-verify")[1]["error"], "AUDIT_TRUNCATED_OR_REWRITTEN")
            self.assertEqual(run(self.home, "request")[1]["error"], "AUDIT_FROZEN")
            self.assertEqual(run(self.home, "verify", "--request", req)[1]["error"], "AUDIT_FROZEN")
        # 元のログと基準ハッシュは変更されず、障害は別ログに残る
        self.assertEqual(log.read_text(), log_after_truncate)
        self.assertEqual((self.home / "anchor/anchor.json").read_text(), anchor_before)
        self.assertTrue((self.home / "incidents/incidents.jsonl").exists())
        self.assertTrue(run(self.home, "status")[1]["frozen"])

    def test_managed_reanchor(self):
        self.issue()
        log = self.home / "audit/audit.jsonl"
        log.write_text("\n".join(log.read_text().splitlines()[:-1]) + "\n")
        run(self.home, "audit-verify")
        run(self.home, "request")  # → 凍結
        rc, out = run(self.home, "audit-reanchor", "--reason", "drill")
        self.assertEqual(out["error"], "CONFIRMATION_REQUIRED")
        rc, out = run(self.home, "audit-reanchor", "--reason", "drill", "--confirm-head", out["head"])
        self.assertEqual(out["action"], "reanchored")
        self.assertTrue(run(self.home, "audit-verify")[1]["ok"])
        self.assertEqual(run(self.home, "request")[0], 0)

    def test_concurrent_writers_keep_chain_valid(self):
        """F05: 別プロセスの同時操作でも、連番が重複せず連鎖が壊れない。"""
        req = self.issue()
        procs = [subprocess.Popen([sys.executable, str(LAB / "pkilab.py"), "--home", str(self.home),
                                   *(["verify", "--request", req] if i % 2 else ["request"])],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  env={**os.environ, **ENV_FAST, "PKILAB_LOCK_TIMEOUT": "30"})
                 for i in range(8)]
        self.assertEqual([p.wait() for p in procs], [0] * 8)
        rc, out = run(self.home, "audit-verify")
        self.assertTrue(out["ok"], out)
        seqs = [json.loads(x)["seq"] for x in (self.home / "audit/audit.jsonl").read_text().splitlines()]
        self.assertEqual(seqs, list(range(1, len(seqs) + 1)))


# ---------------------------------------------------------------------------
class TestCheck(LabCase):
    def test_consistent_state(self):
        req = self.issue()
        run(self.home, "revoke", req)
        rc, out = run(self.home, "check")
        self.assertTrue(out["ok"], out)

    def test_missing_crls_detected_even_without_revocations(self):
        """F06: 失効0件でも、公開 CRL の欠落を異常とする。"""
        self.issue()
        (self.home / "public/crl/root.crl.pem").unlink()
        (self.home / "public/crl/intermediate.crl.pem").unlink()
        rc, out = run(self.home, "check")
        self.assertFalse(out["ok"])
        self.assertEqual(sum("公開 CRL がない" in p for p in out["problems"]), 2)

    def test_corrupted_newcert_detected(self):
        req = self.issue()
        (self.home / f"issuer/newcerts/{self.lab.state(req)['serial']}.pem").write_text("not a certificate\n")
        rc, out = run(self.home, "check")
        self.assertFalse(out["ok"])
        self.assertTrue(any("解析できない" in p for p in out["problems"]), out)

    def test_swapped_or_rolled_back_crl_detected(self):
        self.issue()
        crl_dir = self.home / "public/crl"
        old = (crl_dir / "intermediate.crl.pem").read_bytes()
        req = self.issue()
        run(self.home, "revoke", req)
        (crl_dir / "intermediate.crl.pem").write_bytes(old)  # 古い CRL に戻す
        self.assertFalse(run(self.home, "check")[1]["ok"])
        shutil.copy(crl_dir / "root.crl.pem", crl_dir / "intermediate.crl.pem")  # 別CAの CRL
        out = run(self.home, "check")[1]
        self.assertTrue(any("署名" in p for p in out["problems"]), out)

    def test_deployed_cert_mismatch_detected(self):
        req = self.issue()
        other = self.issue()
        shutil.copy(self.home / self.lab.state(other)["cert"], self.home / self.lab.state(req)["cert"])
        out = run(self.home, "check")[1]
        self.assertTrue(any("配置された証明書" in p for p in out["problems"]), out)


# ---------------------------------------------------------------------------
class TestBackupRestore(LabCase):
    def backup(self) -> str:
        rc, out = run(self.home, "backup")
        self.assertEqual(rc, 0, out)
        self.assertNotIn(b"PRIVATE KEY", Path(out["backup"]).read_bytes())
        return out["backup"]

    def test_latest_backup_restores_ready_and_is_held(self):
        req = self.issue()
        b = self.backup()
        run(self.home, "verify", "--request", req)  # 読み取り専用の操作は巻き戻りではない
        dest = self.tmp / "restored"
        rc, rep = run(self.home, "restore", b, str(dest))
        self.assertEqual(rc, 0, rep)
        for k in ("archive_integrity_ok", "state_consistent", "freshness_confirmed", "key_access_ready"):
            self.assertTrue(rep[k], (k, rep))
        self.assertFalse(rep["resume_authorized"])
        # 再開を承認するまでは発行・CRL 公開をしない
        self.assertEqual(run(dest, "request")[1]["error"], "RECOVERY_HOLD")
        self.assertEqual(run(dest, "crl-issuer")[1]["error"], "RECOVERY_HOLD")
        self.assertEqual(run(dest, "resume")[1]["action"], "held")
        rc, out = run(dest, "resume", "--confirm", "--root-pass-file", str(self.home / "secrets/root.pass"),
                      "--issuer-pass-file", str(self.home / "secrets/issuer.pass"))
        self.assertEqual(out["action"], "resumed", out)
        self.assertEqual(run(dest, "crl-issuer")[0], 0)
        req = run(dest, "request")[1]["request"]
        run(dest, "approve", req)
        self.assertEqual(run(dest, "issue", req)[0], 0)

    def test_stale_backup_is_not_ready(self):
        """F11: バックアップ後の失効が失われる復元は ready にしない。"""
        req = self.issue()
        b = self.backup()
        run(self.home, "revoke", req)
        rc, rep = run(self.home, "restore", b, str(self.tmp / "restored"))
        self.assertEqual(rc, 1)
        self.assertFalse(rep["freshness_confirmed"])
        self.assertFalse(rep["ready"])
        self.assertTrue(any("revoke" in c for c in rep["lost_changes"]), rep)

    def test_tampered_backup_rejected_before_decrypt(self):
        b = Path(self.backup())
        data = bytearray(b.read_bytes())
        data[-20] ^= 0x01
        b.write_bytes(bytes(data))
        rc, rep = run(self.home, "restore", str(b), str(self.tmp / "restored"))
        self.assertEqual((rc, rep["archive_integrity_ok"], rep["ready"]), (1, False, False))
        # 展開はしない。復元先には「拒否した」という保留の印だけが残る
        restored = self.tmp / "restored"
        self.assertEqual(sorted(p.name for p in restored.iterdir()), ["recovery"])
        self.assertEqual(pkilab.read_json(restored / "recovery/hold.json")["status"], "REJECTED")

    def test_missing_key_passphrase_is_not_ready(self):
        b = self.backup()
        rc, rep = run(self.home, "restore", b, str(self.tmp / "restored"),
                      "--root-pass-file", str(self.tmp / "nope.pass"))
        self.assertFalse(rep["key_access_ready"])
        self.assertEqual(rc, 1)


# ---------------------------------------------------------------------------
class TestExport(LabCase):
    def test_events_follow_observed_granularity(self):
        """F07: 失効確認をしていない検証を、失効確認の実測として出さない。"""
        req = self.issue()
        run(self.home, "verify", "--request", req)
        run(self.home, "verify", "--request", req, "--no-crl")
        run(self.home, "revoke", req)
        run(self.home, "verify", "--request", req)
        rc, out = run(self.home, "export-events")
        doc = json.loads(Path(out["events"]).read_text())
        self.assertEqual(doc["schema"], "pkilab-events/2")
        types = [e["type"] for e in doc["events"]]
        for t in ("CSR_CREATED", "REQUEST_AUTHORIZED", "CERT_ISSUED", "CERT_REVOKED", "CRL_PUBLISHED",
                  "CERT_VERIFICATION_COMPLETED"):
            self.assertIn(t, types)
        for banned in ("PATH_VALIDATED", "SAN_CHECKED", "REVOCATION_CHECKED", "TRUST_ANCHOR_SELECTED"):
            self.assertNotIn(banned, types)
        verifies = [e for e in doc["events"] if e["type"] == "CERT_VERIFICATION_COMPLETED"]
        # 要求（設定）と観測を分ける：成功は未観測、--no-crl は要求なし、失効は結果あり
        self.assertEqual([(v["details"]["revocation_requested"], v["details"]["revocation_observation"])
                          for v in verifies],
                         [(True, "not_observed"), (False, "not_requested"), (True, "reported")])
        self.assertTrue(all(v["details"]["stages"] == "not_observed" for v in verifies))
        text = Path(out["events"]).read_text()
        self.assertNotIn("PRIVATE", text)
        self.assertNotIn(self.lab.state(req)["serial"], text)

    def test_export_refused_when_audit_broken(self):
        self.issue()
        log = self.home / "audit/audit.jsonl"
        log.write_text("\n".join(log.read_text().splitlines()[:-1]) + "\n")
        rc, out = run(self.home, "export-events")
        self.assertEqual(out["error"], "AUDIT_FROZEN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
