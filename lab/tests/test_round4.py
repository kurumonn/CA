"""Round 4 integration regressions. Uses real CLI, keys, certificates and CRLs.
All state is created under LabCase's disposable temporary directory.
"""
from pathlib import Path
import json
from test_pkilab import LabCase, run
import pkilab


class TestRound4(LabCase):
    def events(self):
        rc, out = run(self.home, 'export-events')
        self.assertEqual(rc, 0, out)
        return json.loads(Path(out['events']).read_text())['events']

    def test_leaf_completion_keeps_measured_revocation_event(self):
        req = self.issue()
        self.assertEqual(run(self.home, 'revoke', req)[0], 0)
        events = self.events()
        completed = [e for e in events if e['type'] == 'CERT_REVOKED']
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]['details']['issuer_scope'], 'issuer')
        self.assertTrue(any(e['type'] == 'CRL_PUBLISHED' and e['seq'] < completed[0]['seq'] for e in events))
        self.assertEqual(run(self.home, 'verify', '--request', req)[1]['code'], 'LEAF_REVOKED')

    def test_root_completion_is_not_exported_as_leaf_revocation(self):
        self.issue()
        self.assertEqual(run(self.home, 'revoke-intermediate', '--reason', 'CACompromise')[0], 0)
        events = self.events()
        completed = [e for e in events if e['type'] == 'INTERMEDIATE_REVOKED']
        self.assertEqual(len(completed), 1)
        self.assertEqual(completed[0]['details']['issuer_scope'], 'root')
        self.assertFalse(any(e['type'] == 'CERT_REVOKED' for e in events))

    def test_failed_crl_publication_never_exports_completed_revocation(self):
        req = self.issue()
        rc, out = run(self.home, 'revoke', req, env={'PKILAB_FAULT': 'crl-publish'})
        self.assertEqual((rc, out['error']), (2, 'REVOCATION_PENDING'))
        self.assertFalse(any(e['type'] == 'CERT_REVOKED' for e in self.events()))
        self.assertEqual(self.lab.ca_state()['status'], 'SUSPENDED')
        self.assertEqual(run(self.home, 'crl-issuer')[0], 0)
        completed = [e for e in self.events() if e['type'] == 'CERT_REVOKED']
        self.assertEqual(len(completed), 1)

    def test_both_crls_missing_during_publish_keeps_signed_certificate(self):
        req = self.request()
        self.approve(req)
        rc, out = run(self.home, 'issue', req, env={'PKILAB_CRASH_AT': 'after-issued'})
        self.assertEqual(out['error'], 'SIMULATED_CRASH')
        serial = self.lab.state(req)['serial']
        for name in ('root.crl.pem', 'intermediate.crl.pem'):
            (self.home / 'public/crl' / name).unlink()
        rc, out = run(self.home, 'recover', req)
        self.assertEqual((rc, out['error']), (2, 'ISSUER_NOT_READY'), out)
        self.assertEqual(self.lab.state(req)['status'], 'ISSUED')
        self.assertEqual(self.index_rows()[0]['status'], 'V')
        self.assertFalse(pkilab.pending_revocations(self.lab, 'issuer'))
        self.assertEqual(run(self.home, 'crl-root')[0], 0)
        self.assertEqual(run(self.home, 'crl-issuer')[0], 0)
        self.assertEqual(run(self.home, 'recover', req)[0], 0)
        self.assertEqual(self.lab.state(req)['serial'], serial)
        self.assertEqual(len(self.index_rows()), 1)
        self.assertEqual(run(self.home, 'verify', '--request', req)[1]['code'], 'OK')

    def test_state_fingerprint_detects_changes_without_audit_append(self):
        self.issue()
        rc, backup = run(self.home, 'backup')
        self.assertEqual(rc, 0)
        state = self.home / 'issuer/state.json'
        st = pkilab.read_json(state)
        st['status'] = 'SUSPENDED'
        pkilab.write_json(state, st)  # Simulated stop before a completion audit.
        rc, report = run(self.home, 'restore', backup['backup'], str(self.tmp / 'restore'))
        self.assertEqual(rc, 1, report)
        self.assertFalse(report['freshness_confirmed'])
        self.assertIn('issuer_state', report['checks']['state']['state_differs'])

    def test_missing_crls_block_new_signing_without_quarantining_request(self):
        req = self.request()
        self.approve(req)
        (self.home / 'public/crl/root.crl.pem').unlink()
        (self.home / 'public/crl/intermediate.crl.pem').unlink()
        rc, out = run(self.home, 'issue', req)
        self.assertNotEqual(rc, 0)
        self.assertEqual(out['error'], 'ROOT_CRL_UNAVAILABLE')
        self.assertEqual(self.lab.state(req)['status'], 'APPROVED')
        self.assertEqual(len(self.index_rows()), 0)
