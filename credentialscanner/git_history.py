import os
from .scanner import scan_line

def scan_git_history(repo_path: str, max_commits: int = 100) -> list[dict]:
    """Scan git commit history for secrets in diffs."""
    try:
        import git
    except ImportError:
        print("GitPython not installed. Run: pip install gitpython")
        return []

    findings = []
    try:
        repo = git.Repo(repo_path, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        print(f"No git repository found at {repo_path}")
        return []

    commits = list(repo.iter_commits('HEAD', max_count=max_commits))
    total = len(commits)

    for i, commit in enumerate(commits, 1):
        print(f"\r  Scanning commit {i}/{total}: {commit.hexsha[:8]}...", end='', flush=True)
        try:
            if commit.parents:
                diffs = commit.parents[0].diff(commit, create_patch=True)
            else:
                diffs = commit.diff(git.NULL_TREE, create_patch=True)

            for diff in diffs:
                try:
                    patch = diff.diff.decode('utf-8', errors='ignore')
                except Exception:
                    continue

                for line_num, line in enumerate(patch.splitlines(), 1):
                    if not line.startswith('+'):
                        continue
                    line_content = line[1:]  
                    hits = scan_line(line_content, line_num, f"[git:{commit.hexsha[:8]}] {diff.b_path or diff.a_path}")
                    for hit in hits:
                        hit["commit"] = commit.hexsha[:8]
                        hit["commit_message"] = commit.message.strip()[:80]
                        hit["author"] = str(commit.author)
                        findings.append(hit)
        except Exception:
            continue

    print()  
    return findings