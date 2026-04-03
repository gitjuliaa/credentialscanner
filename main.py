
import click
import sys
from credentialscanner.scanner import scan_directory, scan_file
from credentialscanner.git_history import scan_git_history
from credentialscanner.severity import colorize, summarize, severity_rank, RESET

BANNER = """
\033[36m
  ███████╗███████╗ ██████╗██████╗ ███████╗████████╗
  ██╔════╝██╔════╝██╔════╝██╔══██╗██╔════╝╚══██╔══╝
  ███████╗█████╗  ██║     ██████╔╝█████╗     ██║   
  ╚════██║██╔══╝  ██║     ██╔══██╗██╔══╝     ██║   
  ███████║███████╗╚██████╗██║  ██║███████╗   ██║   
  ╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝  
       ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
       ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
\033[0m
  \033[90mSecret Scanner v1.0.0 — Entropy + Pattern + Git History Analysis\033[0m
"""

def print_finding(f: dict, show_context: bool = True):
    sev = f.get("severity", "LOW")
    label = colorize(f"[{sev}]", sev)
    name = f.get("name", "Unknown")
    file_loc = f.get("file", "")
    line = f.get("line", "?")
    match = f.get("match", "")

    print(f"  {label} {name}")
    print(f"         \033[90mFile:\033[0m {file_loc}:{line}")
    print(f"         \033[90mMatch:\033[0m {match[:60]}{'...' if len(match) > 60 else ''}")

    if "commit" in f:
        print(f"         \033[90mCommit:\033[0m {f['commit']} — {f.get('commit_message','')[:60]}")
        print(f"         \033[90mAuthor:\033[0m {f.get('author','')}")

    if show_context and f.get("context"):
        print(f"         \033[90mContext:\033[0m {f['context'][:80]}")
    print()

@click.command()
@click.argument('path', default='.')
@click.option('--git', 'scan_git', is_flag=True, help='Scan git commit history')
@click.option('--commits', default=50, help='Max commits to scan (default: 50)')
@click.option('--min-severity', default='LOW', type=click.Choice(['LOW','MEDIUM','HIGH','CRITICAL']), help='Minimum severity to report')
@click.option('--no-context', is_flag=True, help='Hide line context in output')
def cli(path, scan_git, commits, min_severity, no_context):
    """
    \b
    SecretScanner — find secrets, tokens and high-entropy strings in your codebase.

    \b
    Examples:
      python main.py .                     
      python main.py ./myproject --git     
      python main.py . --min-severity HIGH 
    """
    print(BANNER)
    all_findings = []

    print(f"\033[36m[*]\033[0m Scanning files in: \033[1m{path}\033[0m\n")
    file_findings = scan_directory(path)
    if file_findings:
        print(f"\033[36m[*]\033[0m Found {len(file_findings)} potential secret(s) in files:\n")
        for f in sorted(file_findings, key=lambda x: severity_rank(x.get('severity','LOW')), reverse=True):
            if severity_rank(f.get('severity','LOW')) >= severity_rank(min_severity):
                print_finding(f, show_context=not no_context)
    else:
        print("  \033[32m✓ No secrets found in files.\033[0m\n")
    all_findings.extend(file_findings)

    if scan_git:
        print(f"\033[36m[*]\033[0m Scanning git history (last {commits} commits)...\n")
        git_findings = scan_git_history(path, max_commits=commits)
        if git_findings:
            print(f"\n\033[36m[*]\033[0m Found {len(git_findings)} potential secret(s) in git history:\n")
            for f in sorted(git_findings, key=lambda x: severity_rank(x.get('severity','LOW')), reverse=True):
                if severity_rank(f.get('severity','LOW')) >= severity_rank(min_severity):
                    print_finding(f, show_context=not no_context)
        else:
            print("  \033[32m✓ No secrets found in git history.\033[0m\n")
        all_findings.extend(git_findings)

    summary = summarize(all_findings)
    total = sum(summary.values())
    print("\033[90m" + "─" * 60 + "\033[0m")
    print(f"\033[1mScan Complete — {total} finding(s) total\033[0m")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = summary[sev]
        if count:
            print(f"  {colorize(sev, sev)}: {count}")
    print("\033[90m" + "─" * 60 + "\033[0m\n")

    if summary["CRITICAL"] > 0 or summary["HIGH"] > 0:
        sys.exit(1)

if __name__ == '__main__':
    cli()