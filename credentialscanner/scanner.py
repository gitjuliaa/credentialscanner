import os
from pathlib import Path
from .rules.patterns import SECRET_PATTERNS
from .entropy import find_high_entropy_strings

SKIP_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf',
                   '.zip', '.tar', '.gz', '.exe', '.bin', '.lock'}
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}

def scan_line(line: str, line_number: int, filepath: str) -> list[dict]:
    findings = []

    for name, pattern, severity in SECRET_PATTERNS:
        match = pattern.search(line)
        if match:
            findings.append({
                "type": "pattern",
                "name": name,
                "severity": severity,
                "file": filepath,
                "line": line_number,
                "match": match.group(0)[:80],
                "context": line.strip()[:120],
            })

    for hit in find_high_entropy_strings(line):
        findings.append({
            "type": "entropy",
            "name": f"High Entropy String (entropy={hit['entropy']})",
            "severity": hit["severity"],
            "file": filepath,
            "line": line_number,
            "match": hit["token"][:80],
            "context": line.strip()[:120],
        })

    return findings

def scan_file(filepath: str) -> list[dict]:
    path = Path(filepath)
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return []
    findings = []
    try:
        with open(filepath, 'r', errors='ignore') as f:
            for i, line in enumerate(f, 1):
                findings.extend(scan_line(line, i, filepath))
    except (OSError, PermissionError):
        pass
    return findings

def scan_directory(directory: str) -> list[dict]:
    findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            filepath = os.path.join(root, filename)
            findings.extend(scan_file(filepath))
    return findings