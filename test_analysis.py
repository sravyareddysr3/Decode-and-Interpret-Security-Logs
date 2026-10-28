#!/usr/bin/env python3
"""Verification tests for Task 6.

Regenerates the dataset and re-runs the analysis in a temporary folder, then checks
that (a) the numbers quoted in FINDINGS.md are correct, (b) every seeded attack is
detected, and (c) the benign decoys are NOT escalated.

Run:  python3 -m unittest -v test_analysis.py
"""
import csv
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        for script in ("generate_logs.py", "analyze_logs.py"):
            subprocess.run([sys.executable, os.path.join(HERE, script)],
                           cwd=cls.tmp.name, check=True, capture_output=True)
        with open(os.path.join(cls.tmp.name, "auth_logs.csv")) as f:
            cls.logs = list(csv.DictReader(f))
        with open(os.path.join(cls.tmp.name, "findings.csv")) as f:
            cls.findings = list(csv.DictReader(f))
        with open(os.path.join(cls.tmp.name, "baseline.txt")) as f:
            cls.baseline = f.read()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def find(self, fid, user=None):
        return [r for r in self.findings if r["id"] == fid and (user is None or r["user"].startswith(user))]

    # ---- numbers quoted in the report
    def test_dataset_counts(self):
        self.assertEqual(len(self.logs), 741)
        failures = [r for r in self.logs if r["event"] == "LOGIN_FAILURE"]
        self.assertEqual(len(failures), 198)
        attacker = [r for r in failures if r["src_ip"] in ("198.51.100.23", "192.0.2.77")]
        self.assertEqual(len(attacker), 175)  # 140 + 35

    def test_python_requests_share(self):
        pr = [r for r in self.logs if r["user_agent"] == "python-requests/2.31"]
        self.assertEqual(len(pr), 143)
        self.assertEqual(sum(r["src_ip"] == "198.51.100.23" for r in pr), 142)

    def test_baseline_values(self):
        self.assertIn("Total events      : 741", self.baseline)
        self.assertIn("In-country failure rate (typical user typo rate): 4.2%", self.baseline)

    # ---- seeded attacks are detected
    def test_brute_force_detected(self):
        r = self.find("F1", "admin")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["severity"], "CRITICAL")
        self.assertIn("140 failures", r[0]["evidence"])
        self.assertIn("SUCCESS at", r[0]["evidence"])

    def test_privilege_grant_detected(self):
        self.assertEqual(len(self.find("F9")), 1)

    def test_password_spraying_detected(self):
        r = self.find("F2")
        self.assertEqual(len(r), 1)
        self.assertIn("24 distinct accounts", r[0]["evidence"])
        self.assertIn("dpatel", r[0]["evidence"])

    def test_impossible_travel_detected(self):
        users = {r["user"] for r in self.find("F3")}
        self.assertTrue({"asharma", "dpatel", "tnair"} <= users)

    def test_mfa_fatigue_detected(self):
        r = self.find("F4", "tnair")
        self.assertEqual(len(r), 1)
        self.assertIn("12 push denials", r[0]["evidence"])

    def test_service_account_misuse_detected(self):
        r = self.find("F5", "svc_backup")
        self.assertEqual(len(r), 1)
        self.assertIn("198.51.100.88", r[0]["src_ip"])

    def test_scripted_client_detected(self):
        self.assertEqual(len(self.find("F6", "lfernandes")), 1)

    # ---- benign decoys are not over-escalated
    def test_decoys_not_escalated(self):
        for user in ("jroy", "mkhan"):
            sev = {r["severity"] for r in self.findings if r["user"] == user}
            self.assertTrue(sev <= {"LOW", "INFO"}, f"{user} escalated: {sev}")

    def test_normal_users_have_no_findings(self):
        flagged = {r["user"].split(",")[0] for r in self.findings}
        quiet = {"rgupta", "snair", "vsingh", "kiyer", "pmehta", "nrao", "bdas", "hjoshi"}
        self.assertFalse(quiet & flagged, quiet & flagged)

    def test_report_row_count(self):
        self.assertEqual(len(self.findings), 12)


if __name__ == "__main__":
    unittest.main(verbosity=2)
