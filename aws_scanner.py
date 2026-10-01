import boto3
from botocore.exceptions import ClientError


def scan_s3_public_buckets():
    """Flag any S3 bucket that allows public access."""
    findings = []
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]
    except ClientError as e:
        print(f"Could not list S3 buckets: {e}")
        return findings

    for bucket in buckets:
        name = bucket["Name"]
        try:
            public_access = s3.get_public_access_block(Bucket=name)
            config = public_access["PublicAccessBlockConfiguration"]
            if not all(config.values()):
                findings.append({
                    "resource": f"S3 bucket: {name}",
                    "issue": "Public access block is NOT fully enabled",
                    "severity": "HIGH",
                })
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append({
                    "resource": f"S3 bucket: {name}",
                    "issue": "No public access block configuration at all (fully open by default)",
                    "severity": "CRITICAL",
                })

    return findings


def scan_open_security_groups():
    """Flag security groups with sensitive ports open to the entire internet."""
    findings = []
    ec2 = boto3.client("ec2")
    SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}

    try:
        security_groups = ec2.describe_security_groups()["SecurityGroups"]
    except ClientError as e:
        print(f"Could not list security groups: {e}")
        return findings

    for sg in security_groups:
        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    service = SENSITIVE_PORTS.get(from_port, f"port {from_port}")
                    severity = "CRITICAL" if from_port in SENSITIVE_PORTS else "MEDIUM"
                    findings.append({
                        "resource": f"Security Group: {sg['GroupId']} ({sg.get('GroupName', 'unnamed')})",
                        "issue": f"{service} open to 0.0.0.0/0 (entire internet)",
                        "severity": severity,
                    })

    return findings


def scan_iam_wildcard_policies():
    """Flag IAM policies that grant wildcard (*) actions or resources."""
    findings = []
    iam = boto3.client("iam")

    try:
        policies = iam.list_policies(Scope="Local")["Policies"]  # customer-managed only
    except ClientError as e:
        print(f"Could not list IAM policies: {e}")
        return findings

    for policy in policies:
        try:
            version = iam.get_policy_version(
                PolicyArn=policy["Arn"],
                VersionId=policy["DefaultVersionId"]
            )
            statements = version["PolicyVersion"]["Document"]["Statement"]
            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                actions = statement.get("Action", [])
                resources = statement.get("Resource", [])
                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if "*" in actions and "*" in resources and statement.get("Effect") == "Allow":
                    findings.append({
                        "resource": f"IAM Policy: {policy['PolicyName']}",
                        "issue": "Grants wildcard (*) actions on wildcard (*) resources — effectively admin access",
                        "severity": "CRITICAL",
                    })
        except ClientError:
            continue

    return findings