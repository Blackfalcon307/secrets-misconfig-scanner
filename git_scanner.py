import os
import subprocess
from patterns import SECRET_PATTERNS, IGNORE_DIRS, IGNORE_EXTENSIONS


def scan_text(text: str, source: str):
    """Run all secret patterns against a block of text, return findings."""
    findings = []
    for name, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append({
                "pattern": name,
                "severity": severity,
                "source": source,
                "snippet": match.group(0)[:60]  # truncate so we don't print a full secret
            })
    return findings


def scan_working_directory(repo_path: str):
    """Scan every current file in the repo (not history) for secrets."""
    all_findings = []

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for filename in files:
            if any(filename.endswith(ext) for ext in IGNORE_EXTENSIONS):
                continue

            filepath = os.path.join(root, filename)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            rel_path = os.path.relpath(filepath, repo_path)
            findings = scan_text(content, source=f"file: {rel_path}")
            all_findings.extend(findings)

    return all_findings


def scan_git_history(repo_path: str):
    """Scan every commit's diff for secrets that may have been added and later removed —
    the classic 'I deleted the secret but it's still in history' mistake."""
    all_findings = []

    try:
        result = subprocess.run(
            ["git", "log", "-p", "--all"],
            cwd=repo_path,
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=60,
        )
        full_diff = result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Could not read git history — is this a git repository?")
        return all_findings

    findings = scan_text(full_diff, source="git history (all commits)")
    all_findings.extend(findings)

    return all_findings