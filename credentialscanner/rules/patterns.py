import re

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}'), "CRITICAL"),
    ("AWS Secret Key", re.compile(r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]'), "CRITICAL"),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "CRITICAL"),
    ("GitHub Token", re.compile(r'ghp_[0-9a-zA-Z]{36}'), "CRITICAL"),
    ("GitHub OAuth", re.compile(r'gho_[0-9a-zA-Z]{36}'), "CRITICAL"),
    ("Slack Token", re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'), "HIGH"),
    ("Stripe Secret Key", re.compile(r'sk_live_[0-9a-zA-Z]{24}'), "CRITICAL"),
    ("Stripe Publishable Key", re.compile(r'pk_live_[0-9a-zA-Z]{24}'), "MEDIUM"),
    ("Private Key Header", re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "CRITICAL"),
    ("Generic API Key", re.compile(r'(?i)(api_key|apikey|api-key)\s*[=:]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?'), "HIGH"),
    ("Generic Password", re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]{6,})[\'"]'), "HIGH"),
    ("Generic Secret", re.compile(r'(?i)(secret|token)\s*[=:]\s*[\'"]([a-zA-Z0-9_\-]{16,})[\'"]'), "HIGH"),
    ("JWT Token", re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'), "MEDIUM"),
    ("Basic Auth URL", re.compile(r'https?://[^:]+:[^@]+@[^\s]+'), "HIGH"),
    ("Database URL", re.compile(r'(?i)(postgres|mysql|mongodb|redis)://[^\s]+:[^\s]+@[^\s]+'), "CRITICAL"),
]