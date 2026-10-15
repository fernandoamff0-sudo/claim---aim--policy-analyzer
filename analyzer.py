"""Offline IAM policy pattern review. No AWS calls or third-party dependencies."""

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sys


class PolicyError(ValueError):
    """The input cannot be analyzed as an IAM policy document."""


@dataclass(frozen=True)
class Finding:
    statement: int
    sid: str
    effect: str
    code: str
    field: str
    pattern: str
    message: str
    conditional: bool


def _values(statement, field, index):
    value = statement[field]
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(
        not isinstance(item, str) or not item.strip() for item in values
    ):
        raise PolicyError(f"Statement {index}: {field} must be a nonempty string or list of nonempty strings.")
    return values


def validate_policy(policy):
    """Validate the structure needed for review, not the complete AWS grammar."""
    if not isinstance(policy, dict):
        raise PolicyError("Policy must be a JSON object.")
    statements = policy.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise PolicyError("Statement must be an object or a nonempty list of objects.")
    for index, statement in enumerate(statements, 1):
        if not isinstance(statement, dict):
            raise PolicyError(f"Statement {index} must be an object.")
        if statement.get("Effect") not in ("Allow", "Deny"):
            raise PolicyError(f"Statement {index}: Effect must be Allow or Deny.")
        if "Sid" in statement and not isinstance(statement["Sid"], str):
            raise PolicyError(f"Statement {index}: Sid must be a string.")
        for positive, negative in (("Action", "NotAction"), ("Resource", "NotResource")):
            if (positive in statement) == (negative in statement):
                raise PolicyError(f"Statement {index}: provide exactly one of {positive} or {negative}.")
            _values(statement, positive if positive in statement else negative, index)
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            raise PolicyError(f"Statement {index}: Condition must be an object.")
    return statements


def analyze_policy(policy):
    """Return review findings, preserving statement identity and effect."""
    findings = []
    for index, statement in enumerate(validate_policy(policy), 1):
        def add(code, field, pattern, message):
            findings.append(Finding(index, statement.get("Sid", "(no Sid)"),
                                    statement["Effect"], code, field, pattern,
                                    message, bool(statement.get("Condition"))))

        for action in dict.fromkeys(_values(statement, "Action", index) if "Action" in statement else []):
            if action == "*":
                add("ACTION_ALL", "Action", action, "Matches all actions; review the statement's scope.")
            elif "*" in action or "?" in action:
                add("ACTION_PATTERN", "Action", action, "Wildcard action pattern; review all matching actions.")
        if "Resource" in statement and "*" in _values(statement, "Resource", index):
            add("RESOURCE_ALL", "Resource", "*", "Matches all applicable resources; some actions require this value.")
        for field in ("NotAction", "NotResource"):
            if field in statement:
                add("COMPLEMENT_REVIEW", field, ", ".join(_values(statement, field, index)),
                    "Complement expression; review the excluded values and the remaining scope manually.")
    return findings


def load_policy(path):
    try:
        with Path(path).open(encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, ValueError, RecursionError) as exc:
        raise PolicyError(f"Cannot read policy {path}: {exc}") from exc


def format_report(findings):
    lines = ["CLOUD IAM POLICY ANALYZER", "=========================",
             "Review patterns only; this report does not determine effective access."]
    if not findings:
        lines.append("No targeted patterns found. This does not establish that the policy is secure.")
    else:
        lines.append(f"{len(findings)} finding(s) for review:")
        for finding in findings:
            lines.extend(["", f"[{finding.code}] Statement {finding.statement} ({finding.sid}) | {finding.effect}",
                          f"  {finding.field}: {finding.pattern}", f"  {finding.message}"])
            if finding.effect == "Deny":
                lines.append("  This is a Deny statement, not a permission grant.")
            if finding.conditional:
                lines.append("  Conditions are present and are not evaluated.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", type=Path, help="Path to a local IAM policy JSON file")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="Report format (default: text)")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit 1 when review findings exist")
    args = parser.parse_args(argv)
    try:
        findings = analyze_policy(load_policy(args.policy))
    except (PolicyError, RecursionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps({"findings": [asdict(item) for item in findings],
                          "notice": "Patterns for review only; effective access is not evaluated."}, indent=2))
    else:
        print(format_report(findings))
    return 1 if args.fail_on_findings and findings else 0


if __name__ == "__main__":
    sys.exit(main())
