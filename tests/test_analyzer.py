import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from analyzer import PolicyError, analyze_policy, format_report

ROOT = Path(__file__).resolve().parent.parent


def policy(**changes):
    statement = {"Effect": "Allow", "Action": "*", "Resource": "*"}
    statement.update(changes)
    return {"Statement": [statement]}


class AnalysisTests(unittest.TestCase):
    def test_all_actions_and_resources(self):
        findings = analyze_policy(policy(Sid="Broad"))
        self.assertEqual([f.code for f in findings], ["ACTION_ALL", "RESOURCE_ALL"])
        self.assertTrue(all(f.sid == "Broad" and f.statement == 1 for f in findings))

    def test_action_patterns_and_duplicate_values(self):
        findings = analyze_policy(policy(Action=["s3:*", "iam:Get?", "s3:*", "ec2:DescribeInstances"]))
        self.assertEqual([f.pattern for f in findings if f.field == "Action"], ["s3:*", "iam:Get?"])

    def test_specific_policy(self):
        self.assertEqual(analyze_policy(policy(Action="s3:GetObject", Resource="arn:aws:s3:::bucket/file")), [])
        self.assertIn("does not establish", format_report([]))

    def test_single_statement_and_resource_list(self):
        document = policy(Resource=["arn:aws:s3:::bucket", "*"])
        document["Statement"] = document["Statement"][0]
        self.assertEqual(len(analyze_policy(document)), 2)

    def test_deny_and_condition_context(self):
        findings = analyze_policy(policy(Effect="Deny", Condition={"Bool": {"aws:SecureTransport": "false"}}))
        self.assertTrue(all(f.effect == "Deny" and f.conditional for f in findings))
        report = format_report(findings)
        self.assertIn("not a permission grant", report)
        self.assertIn("not evaluated", report)

    def test_complements_are_not_positive_wildcards(self):
        document = {"Statement": {"Effect": "Allow", "NotAction": "iam:*", "NotResource": "*"}}
        findings = analyze_policy(document)
        self.assertEqual([f.code for f in findings], ["COMPLEMENT_REVIEW", "COMPLEMENT_REVIEW"])

    def test_statement_indices_and_no_mutation(self):
        document = {"Statement": [policy()["Statement"][0], policy(Sid="Second")["Statement"][0]]}
        original = copy.deepcopy(document)
        findings = analyze_policy(document)
        self.assertEqual([f.statement for f in findings], [1, 1, 2, 2])
        self.assertEqual(document, original)

    def test_invalid_structure(self):
        invalid = [None, [], {}, {"Statement": []}, {"Statement": "bad"}, {"Statement": [None]},
                   policy(Effect="allow"), policy(Action=[]), policy(Action=[1]), policy(Action=""),
                   policy(Action=None), policy(Resource={}), policy(Sid=1), policy(Condition=[]),
                   policy(NotAction="s3:*"), policy(NotResource="*")]
        for document in invalid:
            with self.subTest(document=document), self.assertRaises(PolicyError):
                analyze_policy(document)
        for field in ("Action", "Resource"):
            document = policy()
            del document["Statement"][0][field]
            with self.subTest(missing=field), self.assertRaises(PolicyError):
                analyze_policy(document)


class CLITests(unittest.TestCase):
    def run_cli(self, *args, script=None, cwd=None):
        return subprocess.run([sys.executable, str(script or ROOT / "analyzer.py"), *map(str, args)],
                              cwd=cwd, capture_output=True, text=True)

    def test_broad_example(self):
        result = self.run_cli(ROOT / "examples/broad_policy.json")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ACTION_ALL", result.stdout)
        self.assertIn("RESOURCE_ALL", result.stdout)

    def test_json_and_finding_exit_code(self):
        result = self.run_cli(ROOT / "examples/broad_policy.json", "--format", "json", "--fail-on-findings")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["findings"]), 2)

    def test_no_findings_exit_code(self):
        result = self.run_cli(ROOT / "examples/scoped_policy.json", "--fail-on-findings")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No targeted patterns", result.stdout)

    def test_errors_are_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "invalid.json"
            for contents in ('{', '{"Statement": []}', '\ufffd'):
                path.write_text(contents)
                result = self.run_cli(path)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Error:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(result.stdout, "")
            path.write_bytes(b'\xff')
            self.assertEqual(self.run_cli(path).returncode, 2)
            self.assertEqual(self.run_cli(Path(temp) / "missing.json").returncode, 2)

    def test_compatibility_entry_point_from_other_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_cli(script=ROOT / "examples/analyzer.py", cwd=temp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ACTION_ALL", result.stdout)

    def test_pattern_example(self):
        result = self.run_cli(ROOT / "examples/pattern_policy.json", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        findings = json.loads(result.stdout)["findings"]
        self.assertEqual(len(findings), 5)
        self.assertEqual({f["effect"] for f in findings}, {"Allow", "Deny"})

    def test_help_and_missing_argument(self):
        self.assertEqual(self.run_cli("--help").returncode, 0)
        self.assertEqual(self.run_cli().returncode, 2)


if __name__ == "__main__":
    unittest.main()
