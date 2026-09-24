# Cloud IAM Policy Analyzer

A Python project for identifying broad permission patterns
in AWS IAM policies.

## Project status

Under development.

## Objective

Build an offline tool that reads an IAM policy from a JSON
file and reports permission patterns that require review.

## Planned features

- Detect wildcard actions such as `Action: "*"`.
- Detect action patterns such as `s3:*`.
- Flag `Resource: "*"` for contextual review.
- Generate readable reports.
- Include sample policies and automated tests.

## Technologies

- Python
- JSON
- Git and GitHub
- AWS IAM concepts

## Scope

This educational tool will analyze local files.
An AWS account and credentials will not be required.

Findings will identify patterns for review, not prove
effective access or guarantee that a policy is secure.

## Learning goals

- Understand IAM policy structure.
- Practice the principle of least privilege.
- Build and test a Python command-line tool.
- Document security findings and limitations.

## Development process

Developed step by step with AI assistance.
My contributions and learning notes will be documented
as the project progresses.
