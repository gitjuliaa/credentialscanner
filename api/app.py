import tempfile
import shutil
import subprocess
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from credentialscanner.scanner import scan_directory, scan_file
from credentialscanner.git_history import scan_git_history
from credentialscanner.severity import summarize

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    path = data.get('path', '.')
    include_git = data.get('git', False)
    max_commits = data.get('commits', 50)
    min_severity = data.get('min_severity', 'LOW')

    if not os.path.exists(path):
        return jsonify({"error": f"Path '{path}' does not exist"}), 400

    findings = []

    file_findings = scan_directory(path)
    for f in file_findings:
        f['source'] = 'file'
    findings.extend(file_findings)

    if include_git:
        git_findings = scan_git_history(path, max_commits=max_commits)
        for f in git_findings:
            f['source'] = 'git'
        findings.extend(git_findings)

    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    min_rank = severity_order.get(min_severity.upper(), 1)
    filtered = [f for f in findings if severity_order.get(f.get('severity', 'LOW').upper(), 1) >= min_rank]

    filtered.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW').upper(), 1), reverse=True)

    summary = summarize(filtered)

    return jsonify({
        "findings": filtered,
        "summary": summary,
        "total": len(filtered),
        "path": path,
    })

@app.route('/api/scan/github', methods=['POST'])
def scan_github():
    data = request.get_json()
    github_url = data.get('url', '').strip()
    include_git = data.get('git', True)
    max_commits = data.get('commits', 50)
    min_severity = data.get('min_severity', 'LOW')

    if not github_url:
        return jsonify({"error": "Please provide a GitHub URL."}), 400

    if not github_url.startswith('https://github.com/'):
        return jsonify({"error": "Only public GitHub URLs are supported."}), 400

    tmp_dir = tempfile.mkdtemp()
    try:
        result = subprocess.run(
            ['git', 'clone', '--depth', str(max_commits), github_url, tmp_dir],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            return jsonify({"error": f"Failed to clone repo: {result.stderr.strip()}"}), 400

        findings = []

        file_findings = scan_directory(tmp_dir)
        for f in file_findings:
            f['source'] = 'file'
            f['file'] = f['file'].replace(tmp_dir, github_url)
        findings.extend(file_findings)

        if include_git:
            git_findings = scan_git_history(tmp_dir, max_commits=max_commits)
            for f in git_findings:
                f['source'] = 'git'
                f['file'] = f['file'].replace(tmp_dir, github_url)
            findings.extend(git_findings)

        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_rank = severity_order.get(min_severity.upper(), 1)
        filtered = [f for f in findings if severity_order.get(f.get('severity', 'LOW').upper(), 1) >= min_rank]
        filtered.sort(key=lambda x: severity_order.get(x.get('severity', 'LOW').upper(), 1), reverse=True)

        summary = summarize(filtered)

        return jsonify({
            "findings": filtered,
            "summary": summary,
            "total": len(filtered),
            "path": github_url,
        })

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Repo clone timed out. Try a smaller repo."}), 408
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "version": "1.0.0"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)