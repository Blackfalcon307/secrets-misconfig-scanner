import re

# Each pattern: (name, compiled regex, severity)
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    ("AWS Secret Access Key (likely)", re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]"), "CRITICAL"),
    ("Generic API Key", re.compile(r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"), "HIGH"),
    ("Generic Secret/Token", re.compile(r"(?i)(secret|token)\s*[:=]\s*['\"][A-Za-z0-9_\-]{20,}['\"]"), "HIGH"),
    ("Hardcoded Password", re.compile(r"(?i)password\s*[:=]\s*['\"][^'\"]{4,}['\"]"), "MEDIUM"),
    ("Private Key Header", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("Slack Webhook URL", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"), "HIGH"),
    ("Anthropic API Key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}"), "CRITICAL"),
    ("OpenAI API Key", re.compile(r"sk-[A-Za-z0-9]{32,}"), "CRITICAL"),
]

# Files/folders we never want to scan (binary, huge, or irrelevant)
IGNORE_DIRS = {".git", "venv", "node_modules", "__pycache__", ".terraform"}
IGNORE_EXTENSIONS = {".exe", ".dll", ".png", ".jpg", ".jpeg", ".zip", ".pyc", ".ico"}