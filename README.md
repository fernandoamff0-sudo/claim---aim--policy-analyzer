# Cloud IAM Policy Analyzer

An offline Python command-line tool that reads a local AWS IAM policy JSON file
and reports broad permission patterns for contextual review. No AWS account,
credentials, network access, or third-party Python packages are required.

## Requirements and quick start

Python 3.10 or newer. From the repository root:

```bash
python3 analyzer.py examples/broad_policy.json
python3 analyzer.py examples/pattern_policy.json --format json
python3 analyzer.py examples/scoped_policy.json --fail-on-findings
```

The original example command also works, with the bundled broad policy as its default:

```bash
python3 examples/analyzer.py
```

Pass any local file path as the positional argument. Relative policy paths are
resolved from your current working directory. Use `--help` for options.
Files are read as UTF-8; input files are never modified.

## Findings

| Code | Pattern | Meaning |
| --- | --- | --- |
| `ACTION_ALL` | `Action: "*"` | All actions match; review scope. |
| `ACTION_PATTERN` | `s3:*`, `iam:Get*`, or patterns containing `?` | Review the matching actions. |
| `RESOURCE_ALL` | `Resource: "*"` | All applicable resources match; some actions require this value. |
| `COMPLEMENT_REVIEW` | `NotAction` or `NotResource` | Review complement semantics manually. |

Both strings and lists are supported for action and resource fields. `Statement`
can be one object or a nonempty list. Reports identify statements by their
one-based position, optional `Sid`, and `Effect`. Duplicate actions within a
statement produce one finding per distinct action pattern.

Example text output:

```text
[ACTION_ALL] Statement 1 (BroadPermissions) | Allow
  Action: *
  Matches all actions; review the statement's scope.
```

JSON output has a `findings` array and a `notice`. Each finding includes
`statement`, `sid`, `effect`, `code`, `field`, `pattern`, `message`, and
`conditional`. The latter indicates a nonempty `Condition` object; conditions
are not evaluated. Errors are written to stderr, without a partial report.

## Exit codes

- `0`: analysis succeeded; findings may exist.
- `1`: analysis succeeded with findings when `--fail-on-findings` is set.
- `2`: invalid arguments, unreadable file, invalid JSON, or unsupported input structure.

For example, `python3 analyzer.py examples/broad_policy.json --fail-on-findings`
returns `1`. A `Deny` pattern or complement review finding also counts toward
this exit status; it does not mean a permission grant was found.

## Scope and limitations

This is an educational pattern reviewer, not a complete IAM validator or an
AWS authorization simulator. A finding is a prompt for review, not proof of
excessive access. No findings does not establish that a policy is secure.

- `Allow` and `Deny` are reported separately; a broad deny is not a permission grant.
- Conditions are preserved in the input but not evaluated.
- `NotAction` and `NotResource` are flagged for manual review rather than
  interpreted as positive action/resource lists.
- Principal scope, resource ARN wildcard patterns, service-specific action
  validity, policy versions, SCPs, permissions boundaries, session policies,
  and interactions among policies are not evaluated.
- Structural validation requires `Effect`, exactly one of `Action`/`NotAction`,
  and exactly one of `Resource`/`NotResource`. Policies outside this supported
  shape are rejected, even if valid in another IAM context.

Use AWS documentation and appropriate authorization analysis tools for real
access decisions. Avoid committing real policies containing sensitive identifiers.

## Development and tests

```bash
python3 -m unittest discover -s tests -v
```

The suite covers detection, input validation, conditions and deny context,
complements, output formats, CLI exit codes, and the compatibility entry point.
GitHub Actions runs it on Python 3.10 and 3.12.

```text
analyzer.py                  Reusable analysis functions and CLI
examples/analyzer.py         Compatibility entry point
examples/broad_policy.json   All actions and resources
examples/pattern_policy.json Service patterns, conditions, and deny example
examples/scoped_policy.json  Specific action and resource example
tests/test_analyzer.py       Standard-library unit and CLI tests
docs/learning-notes.md       Design decisions and learning prompts
```

## Development process

Developed with AI assistance. See [learning notes](docs/learning-notes.md) for
implementation decisions and exercises. Personal contributions and conclusions
should be recorded by the learner; generated notes do not claim work or learning
on their behalf.
