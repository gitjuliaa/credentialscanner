SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",  
    "HIGH":     "\033[31m",  
    "MEDIUM":   "\033[33m",  
    "LOW":      "\033[34m",  
    "INFO":     "\033[37m",  
}
RESET = "\033[0m"

def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), 0)

def colorize(text: str, severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), "")
    return f"{color}{text}{RESET}"

def summarize(findings: list[dict]) -> dict:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW").upper()
        if sev in summary:
            summary[sev] += 1
    return summary