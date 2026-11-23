import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from api_security_toolkit.__main__ import load_json, markdown
from api_security_toolkit.assessment import InputError, assess

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.evidence = load_json(FIXTURES / "evidence.json")
        self.policy = load_json(FIXTURES / "policy.json")

    def results(self):
        return {case["id"]: case for case in assess(self.evidence, self.policy)["cases"]}

    def test_all_checks_and_classifications(self):
        expected = {
            "01-bola": ("idor_bola", "confirmed"),
            "02-function": ("broken_function_level_authorization", "confirmed"),
            "03-tenant": ("cross_tenant_access", "confirmed"),
            "04-suspected": ("idor_bola", "suspected"),
            "05-no-finding": ("cross_tenant_access", "no_finding"),
            "06-insufficient": ("broken_function_level_authorization", "insufficient_evidence"),
        }
        self.assertEqual(
            {key: (case["check"], case["classification"]) for key, case in self.results().items()},
            expected,
        )

    def test_preserves_evidence_and_policy_references_in_both_reports(self):
        report = assess(self.evidence, self.policy)
        case = report["cases"][0]
        self.assertEqual(case["subject_references"], ["ev-bola-subject"])
        self.assertEqual(case["control_references"], ["ev-bola-control"])
        self.assertEqual(case["subject_rule_id"], "p-read-peer")
        rendered = markdown(report)
        for source_case in self.evidence["cases"]:
            for observation in source_case["observations"]:
                self.assertIn(f"`{observation['ref']}`", rendered)
        self.assertIn("`p-read-own`", rendered)

    def test_no_explicit_policy_is_insufficient(self):
        self.policy["rules"] = [rule for rule in self.policy["rules"] if rule["id"] != "p-read-peer"]
        self.assertEqual(self.results()["01-bola"]["classification"], "insufficient_evidence")

    def test_policy_must_permit_control(self):
        rule = next(rule for rule in self.policy["rules"] if rule["id"] == "p-read-own")
        rule["decision"] = "deny"
        case = self.results()["01-bola"]
        self.assertEqual(case["control_references"], [])
        self.assertEqual(case["classification"], "suspected")

    def test_inconclusive_control_does_not_confirm(self):
        self.evidence["cases"][0]["observations"][1]["outcome"] = "inconclusive"
        self.assertEqual(self.results()["01-bola"]["classification"], "suspected")

    def test_allowed_control_with_different_role_does_not_confirm_tenant_case(self):
        self.evidence["cases"][2]["observations"][1]["actor"] = "drew"
        self.policy["rules"].append(dict(id="p-settings-admin", operation="read-settings",
                                         role="admin", relation="tenant", decision="allow"))
        self.assertEqual(self.results()["03-tenant"]["classification"], "suspected")

    def test_denial_without_positive_control_is_insufficient(self):
        self.evidence["cases"][4]["observations"].pop()
        self.assertEqual(self.results()["05-no-finding"]["classification"], "insufficient_evidence")

    def test_expected_allow_denied_is_insufficient(self):
        rule = next(rule for rule in self.policy["rules"] if rule["id"] == "p-summary-cross")
        rule["decision"] = "allow"
        self.assertEqual(self.results()["05-no-finding"]["classification"], "insufficient_evidence")

    def test_expected_allow_observed_is_no_finding(self):
        rule = next(rule for rule in self.policy["rules"] if rule["id"] == "p-read-peer")
        rule["decision"] = "allow"
        self.assertEqual(self.results()["04-suspected"]["classification"], "no_finding")

    def test_case_without_subject_observation_is_insufficient(self):
        self.evidence["cases"][0]["observations"].pop(0)
        self.assertEqual(self.results()["01-bola"]["classification"], "insufficient_evidence")

    def test_rejects_cross_case_contradiction(self):
        conflict = copy.deepcopy(self.evidence["cases"][0])
        conflict["id"] = "another-case"
        conflict["observations"] = [dict(ref="other-subject", actor="blair", outcome="denied")]
        self.evidence["cases"].append(conflict)
        with self.assertRaisesRegex(InputError, "contradictory observations:.*ev-bola-subject.*other-subject"):
            self.results()

    def test_rejects_policy_contradiction(self):
        self.policy["rules"].append(dict(self.policy["rules"][0], id="conflict", decision="deny"))
        with self.assertRaisesRegex(InputError, "contradictory policy rules:.*p-read-own.*conflict"):
            self.results()

    def test_rejects_duplicate_evidence_reference(self):
        self.evidence["cases"][1]["observations"][0]["ref"] = "ev-bola-subject"
        with self.assertRaisesRegex(InputError, "duplicate evidence reference"):
            self.results()

    def test_rejects_unknown_actor(self):
        self.evidence["cases"][0]["observations"][0]["actor"] = "unknown"
        with self.assertRaisesRegex(InputError, "unknown actor"):
            self.results()

    def test_rejects_check_with_incompatible_subject_relation(self):
        self.evidence["cases"][0]["subject"] = "casey"
        with self.assertRaisesRegex(InputError, "incompatible with check"):
            self.results()

    def test_rejects_missing_synthetic_marker(self):
        self.evidence["synthetic"] = False
        with self.assertRaisesRegex(InputError, "must declare synthetic"):
            self.results()

    def test_deterministic_across_input_order(self):
        first = assess(self.evidence, self.policy)
        for key in ("actors", "resources", "cases"):
            self.evidence[key].reverse()
        for case in self.evidence["cases"]:
            case["observations"].reverse()
        self.policy["rules"].reverse()
        second = assess(self.evidence, self.policy)
        self.assertEqual(json.dumps(first), json.dumps(second))
        self.assertEqual(markdown(first), markdown(second))


class CliTests(unittest.TestCase):
    def invoke(self, evidence, out_dir):
        return subprocess.run(
            [sys.executable, "-m", "api_security_toolkit", "--evidence", str(evidence),
             "--policy", str(FIXTURES / "policy.json"), "--out-dir", str(out_dir)],
            cwd=ROOT, capture_output=True, text=True,
        )

    def test_writes_both_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory)
            command = self.invoke(FIXTURES / "evidence.json", out_dir)
            self.assertEqual(command.returncode, 0, command.stderr)
            self.assertIn("confirmed: 3", command.stdout)
            self.assertEqual(load_json(out_dir / "report.json")["summary"]["confirmed"], 3)
            self.assertIn("ev-tenant-control", (out_dir / "report.md").read_text(encoding="utf-8"))

    def test_contradictory_evidence_fails_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory) / "reports"
            command = self.invoke(FIXTURES / "contradictory-evidence.json", out_dir)
            self.assertEqual(command.returncode, 2)
            self.assertIn("ev-conflict-allow and ev-conflict-deny", command.stderr)
            self.assertFalse(out_dir.exists())

    def test_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_text('{"synthetic": true, "synthetic": false}', encoding="utf-8")
            command = self.invoke(path, Path(directory) / "reports")
            self.assertEqual(command.returncode, 2)
            self.assertIn("duplicate JSON key", command.stderr)

    def test_does_not_overwrite_input(self):
        with tempfile.TemporaryDirectory() as directory:
            out_dir = Path(directory)
            evidence = out_dir / "report.json"
            original = (FIXTURES / "evidence.json").read_bytes()
            evidence.write_bytes(original)
            command = self.invoke(evidence, out_dir)
            self.assertEqual(command.returncode, 2)
            self.assertEqual(evidence.read_bytes(), original)
            self.assertFalse((out_dir / "report.md").exists())


if __name__ == "__main__":
    unittest.main()
