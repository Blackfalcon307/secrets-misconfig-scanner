import argparse
from rich.console import Console
from rich.table import Table

from git_scanner import scan_working_directory, scan_git_history
from aws_scanner import scan_s3_public_buckets, scan_open_security_groups, scan_iam_wildcard_policies

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
}


def print_findings(findings, title):
    if not findings:
        console.print(f"[green]No issues found for: {title}[/green]")
        return

    table = Table(title=title)
    table.add_column("Severity", style="bold")
    table.add_column("Issue")
    table.add_column("Location")

    # sort so CRITICAL shows first
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings_sorted = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "LOW"), 4))

    for f in findings_sorted:
        severity = f.get("severity", "LOW")
        color = SEVERITY_COLORS.get(severity, "white")
        issue_text = f.get("pattern") or f.get("issue")
        location = f.get("source") or f.get("resource")
        table.add_row(f"[{color}]{severity}[/{color}]", issue_text, location)

    console.print(table)


def main():
    parser = argparse.ArgumentParser(description="Scan for secrets and AWS misconfigurations")
    subparsers = parser.add_subparsers(dest="command", required=True)

    repo_parser = subparsers.add_parser("scan-repo", help="Scan a git repo for committed secrets")
    repo_parser.add_argument("path", help="Path to the git repository")
    repo_parser.add_argument("--history", action="store_true", help="Also scan full git history (slower)")

    subparsers.add_parser("scan-aws", help="Scan your AWS account for misconfigurations")

    args = parser.parse_args()

    if args.command == "scan-repo":
        console.print(f"\n[bold]Scanning working directory: {args.path}[/bold]\n")
        findings = scan_working_directory(args.path)
        print_findings(findings, "Secrets in Current Files")

        if args.history:
            console.print(f"\n[bold]Scanning git history (this may take a moment)...[/bold]\n")
            history_findings = scan_git_history(args.path)
            print_findings(history_findings, "Secrets in Git History")

    elif args.command == "scan-aws":
        console.print("\n[bold]Scanning S3 buckets for public access...[/bold]\n")
        print_findings(scan_s3_public_buckets(), "Public S3 Buckets")

        console.print("\n[bold]Scanning security groups for open ports...[/bold]\n")
        print_findings(scan_open_security_groups(), "Open Security Groups")

        console.print("\n[bold]Scanning IAM policies for wildcard permissions...[/bold]\n")
        print_findings(scan_iam_wildcard_policies(), "Overly Permissive IAM Policies")


if __name__ == "__main__":
    main()