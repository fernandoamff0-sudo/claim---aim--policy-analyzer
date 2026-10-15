# Learning notes

## Implementation decisions

- The analysis module uses only Python's standard library so policies can be
  reviewed offline without AWS credentials or dependency installation.
- Analysis is separate from file loading and report formatting. Tests can check
  policy objects directly, while CLI tests exercise actual subprocess behavior.
- Statement indices remain available when `Sid` is absent or repeated.
- Wildcards are reported as review patterns. `Resource: "*"` can be required by
  certain AWS actions; it is not automatically a vulnerability.
- `Deny` statements retain their effect and receive an explicit explanation.
  The tool does not calculate the interaction between allow and deny statements.
- Complement fields require separate interpretation: `NotAction: "iam:*"` does
  not mean the statement grants IAM actions. They are flagged for manual review.
- The original example resolved its policy path beneath an extra `examples`
  directory. The compatibility entry point now locates the bundled policy from
  the repository root and works independently of the current directory.
- Validation checks the structure this analyzer needs. It deliberately does not
  attempt to implement the full IAM grammar or a service action catalog.

## Suggested learning exercises

1. Compare the reports for the broad and scoped examples. Explain which action
   and resource choices changed and how they relate to least privilege.
2. Change an example in a temporary file from `Allow` to `Deny`. Explain why a
   matching wildcard has a different authorization meaning.
3. Add a condition and explain why evaluating its effect needs request context.
4. Look up an AWS action that requires `Resource: "*"` and document the source.
5. Add a test before extending a detection rule, and document its limitations.

## Personal contributions

Record your own changes, decisions, references, and conclusions here as you work.
These prompts and implementation notes were prepared with AI assistance; they
are not a record of exercises completed by the repository owner.
