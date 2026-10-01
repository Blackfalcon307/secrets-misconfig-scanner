# Secrets & Misconfiguration Scanner

A CLI security scanner built from real mistakes made while building other
projects: committed secrets, overly broad security groups, and permissive
IAM policies.

## Features
- Scans repo files AND full git history for secrets (AWS keys, API keys,
  passwords, private keys) — catches secrets even if they were later
  "removed" in a subsequent commit
- Scans a live AWS account for:
  - S3 buckets without public access blocking
  - Security groups exposing sensitive ports (SSH, RDP, databases) to 0.0.0.0/0
  - IAM policies granting wildcard (*) permissions

## Usage

    python scanner.py scan-repo /path/to/repo --history
    python scanner.py scan-aws

## Why this exists

Built directly from real debugging sessions where a Terraform provider
binary and a virtual environment got accidentally committed to git, and
after repeatedly configuring (and having to remember to clean up) wide-open
security group rules during AWS projects. This tool automates catching
exactly those classes of mistakes before they ship.