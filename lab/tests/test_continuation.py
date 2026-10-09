"""Round 4: executable boundary regressions, not weakened success expectations.

All CA state is temporary. Failure injection is restricted to the selected method.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pkilab import LabCase, run
import pkilab


def key_args(home):
    return ["--root-pass-file", str(home / "secrets/root.pass"),
            "--issuer-pass-file", str(home / "secrets/issuer.pass")]


class TestContinuationEvents(LabCase):
    def exported(self):
        rc, result = run(self.home, "export-events")
        self.assertEqual(rc, 0, result)
        return json.loads(Path(result["events"]).read_text())

    def test_completed_revocations_preserve_both_ca_scopes(self):
        req = self.issue()
        self.assertEqual(run(self.home, "revoke", req)[0], 0)
        self.assertEqual(run(self.home, "revoke-intermediate")[0], 0)
        ev = self.exported()["events"]
        requested = [e for e in ev if e["type"] == "REVOCATION_REQUESTED"]
        completed = [e for e in ev if e["type"] in ("CERT_REVOKED", "INTERMEDIATE_REVOKED")]
        self.assertEqual([e["details"]["which"] for e in requested], ["issuer", "root"])
        self.assertEqual([e["type"] for e in completed], ["CERT_REVOKED", "INTERMEDIATE_REVOKED"])
        for scope, completion in zip(("issuer", "root"), completed):
            crl = [e for e in ev if e["type"] == "CRL_PUBLISHED" and e["seq"] < completion["seq"]][-1]
            self.assertEqual(completion["details"]["which"], scope)
            self.assertEqual(completion["details"]["crl_number"], crl["details"]["crl_number"])

    def test_pending_revocation_never_exports_completion(self):
        req = self.issue()
        rc, result = run(self.home, "revoke", req, env={"PKILAB_FAULT": "crl-publish"})
        self.assertEqual(result["error"], "REVOCATION_PENDING")
        before = self.exported()["events"]
        self.assertIn("REVOCATION_REQUESTED", [e["type"] for e in before])
        self.assertNotIn("CERT_REVOKED", [e["type"] for e in before])
        self.assertEqual(run(self.home, "crl-issuer")[0], 0)
        after = self.exported()["events"]
        self.assertEqual(sum(e["type"] == "CERT_REVOKED" for e in after), 1)

    def test_unknown_revocation_scope_is_not_guessed(self):
        self.lab.audit("revoke-completed", "ok", "opaque-test-id", which="unknown")
        rc, result = run(self.home, "export-events")
        self.assertEqual((rc, result["error"]), (2, "EVENT_SCOPE_INVALID"))
        self.assertFalse((self.home / "exports/events.json").exists())

    def test_export_head_is_the_validated_snapshot(self):
        self.issue()
        before = pkilab.verify_audit_chain(self.home)
        doc = self.exported()
        self.assertEqual(doc["audit_head"], before["head"])
        self.assertLessEqual(max(e["seq"] for e in doc["events"]), before["entries"])
        self.assertGreater(pkilab.verify_audit_chain(self.home)["entries"], before["entries"])


class TestContinuationRecovery(LabCase):
    def prepared(self):
        req = self.issue()
        rc, b = run(self.home, "backup")
        self.assertEqual(rc, 0, b)
        dest = self.tmp / "restored"
        rc, out = run(self.home, "restore", b["backup"], str(dest))
        self.assertTrue(out["ready"], out)
        return req, dest

    def fence_and_stop(self):
        req, dest = self.prepared()
        rc, out = run(dest, "resume", "--confirm", *key_args(self.home),
                      env={"PKILAB_CRASH_AT": "resume-after-fence"})
        self.assertEqual(out["error"], "SIMULATED_CRASH")
        self.assertTrue(self.lab.superseded())
        return req, dest

    def test_post_fence_retry_revalidates_key_access(self):
        req, dest = self.fence_and_stop()
        (dest / "secrets/issuer.pass").unlink()
        rc, out = run(dest, "resume", "--confirm")
        self.assertEqual((rc, out["action"]), (1, "held"), out)
        self.assertIn("key_access_ready", out["blockers"])
        self.assertTrue((dest / "recovery/hold.json").exists())

    def test_post_fence_retry_revalidates_integrity(self):
        req, dest = self.fence_and_stop()
        serial = self.lab.state(req)["serial"]
        (dest / f"issuer/newcerts/{serial}.pem").write_text("not a certificate\n")
        rc, out = run(dest, "resume", "--confirm")
        self.assertEqual((rc, out["action"]), (1, "held"), out)
        self.assertIn("state_consistent", out["blockers"])

    def test_post_fence_retry_can_complete_once(self):
        req, dest = self.fence_and_stop()
        rc, out = run(dest, "resume", "--confirm")
        self.assertEqual((rc, out["action"], out["source_fenced"]), (0, "resumed", True), out)
        self.assertTrue(out["resumed_after_interruption"])
        self.assertEqual(run(dest, "resume", "--confirm")[1]["action"], "none")
        self.assertEqual(run(self.home, "request")[1]["error"], "SUPERSEDED")

    def test_resume_destination_lock_serializes_attempts(self):
        req, dest = self.prepared()
        holder = pkilab.Lab(dest, "holder", "operator")
        with holder._flock(holder.p("locks", "resume.lock"), "test"):
            rc, out = run(dest, "resume", "--confirm", *key_args(self.home),
                          env={"PKILAB_LOCK_TIMEOUT": "0.1"})
        self.assertEqual(out["error"], "LOCK_BUSY", out)
        self.assertFalse(self.lab.superseded())

    def test_wrong_source_identity_cannot_be_overridden(self):
        req, dest = self.prepared()
        other = self.tmp / "other"
        self.assertEqual(run(other, "init")[0], 0)
        rc, out = run(dest, "resume", "--source", str(other), "--confirm", "--source-stopped",
                      "--accept-stale", *key_args(self.home))
        self.assertEqual((rc, out["action"]), (1, "held"), out)
        self.assertTrue(any(s.startswith("source_mismatch") for s in out["blockers"]), out)
        self.assertFalse(self.lab.superseded())
        self.assertFalse(pkilab.Lab(other, "t", "operator").superseded())


class TestContinuationIntent(LabCase):
    def test_intent_survives_audit_io_failure_and_is_retried(self):
        req = self.issue()
        real = pkilab.Lab.audit
        def fail_request_audit(lab, op, result, target="", **details):
            if op == "revoke-requested":
                raise OSError("injected audit storage failure")
            return real(lab, op, result, target, **details)
        with mock.patch.object(pkilab.Lab, "audit", fail_request_audit):
            rc, out = run(self.home, "revoke", req)
        self.assertNotEqual(rc, 0)
        pending = pkilab.pending_revocations(self.lab, "issuer")
        self.assertEqual(len(pending), 1)
        self.assertFalse(pending[0]["audit_requested"])
        self.assertEqual(self.index_rows()[0]["status"], "V")
        rc, out = run(self.home, "crl-issuer")
        self.assertEqual(rc, 0, out)
        self.assertEqual(pkilab.pending_revocations(self.lab, "issuer"), [])
        self.assertEqual(run(self.home, "verify", "--request", req)[1]["code"], "LEAF_REVOKED")

    def test_transient_crl_absence_preserves_signed_certificate(self):
        req = self.request()
        self.approve(req)
        self.assertEqual(run(self.home, "issue", req, env={"PKILAB_CRASH_AT": "after-issued"})[1]["error"],
                         "SIMULATED_CRASH")
        crl = self.home / "public/crl/intermediate.crl.pem"
        saved = crl.read_bytes()
        crl.unlink()
        before = self.index_rows()
        rc, out = run(self.home, "issue", req)
        self.assertEqual(out["error"], "ISSUER_NOT_READY", out)
        self.assertEqual(self.lab.state(req)["status"], "ISSUED")
        self.assertEqual(self.index_rows(), before)
        crl.write_bytes(saved)
        self.assertEqual(run(self.home, "issue", req)[0], 0)
        self.assertEqual(len(self.index_rows()), 1)

    def test_root_sign_crash_adopts_without_second_signature(self):
        home = self.tmp / "root-sign-lab"
        self.assertEqual(run(home, "init-root")[0], 0)
        self.assertEqual(run(home, "init-issuer")[0], 0)
        rc, out = run(home, "sign-intermediate", env={"PKILAB_CRASH_AT": "after-root-sign"})
        self.assertEqual(out["error"], "SIMULATED_CRASH", out)
        rows = pkilab.read_index(home / "root")
        self.assertEqual(len(rows), 1)
        self.assertEqual(run(home, "sign-intermediate")[0], 0)
        self.assertEqual(pkilab.read_index(home / "root"), rows)
