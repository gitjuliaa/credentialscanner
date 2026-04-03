import math
from collections import Counter

MIN_LENGTH = 16
ENTROPY_THRESHOLD = 3.8

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
    )
    return round(entropy, 4)

def find_high_entropy_strings(line: str, threshold: float = ENTROPY_THRESHOLD) -> list[dict]:
    """Extract tokens from a line and flag those with high entropy."""
    findings = []
    tokens = line.replace('"', ' ').replace("'", ' ').replace('=', ' ').replace(':', ' ').split()
    for token in tokens:
        if len(token) < MIN_LENGTH:
            continue
        entropy = shannon_entropy(token)
        if entropy >= threshold:
            findings.append({
                "token": token,
                "entropy": entropy,
                "severity": entropy_to_severity(entropy)
            })
    return findings

def entropy_to_severity(entropy: float) -> str:
    if entropy >= 4.5:
        return "HIGH"
    elif entropy >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"