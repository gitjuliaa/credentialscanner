const API = '/api';
let allFindings = [];

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    const page = item.dataset.page;

    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));

    item.classList.add('active');
    const target = document.getElementById(`page-${page}`);
    target.classList.remove('hidden');
    target.classList.add('active');
  });
});

document.getElementById('scan-btn').addEventListener('click', async () => {
  const path = document.getElementById('scan-path').value.trim();
  const githubUrl = document.getElementById('github-url').value.trim();
  const minSeverity = document.getElementById('min-severity').value;
  const maxCommits = parseInt(document.getElementById('max-commits').value);
  const includeGit = document.getElementById('include-git').checked;

  if (!path && !githubUrl) {
    showError('Please enter a project path or GitHub URL.');
    return;
  }

  hideError();
  showLoading(true);
  document.getElementById('summary').classList.add('hidden');
  document.getElementById('scan-btn').disabled = true;

  try {
    let res, data;

    if (githubUrl) {
      res = await fetch(`${API}/scan/github`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: githubUrl,
          git: includeGit,
          commits: maxCommits,
          min_severity: minSeverity,
        })
      });
    } else {
      res = await fetch(`${API}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          path,
          git: includeGit,
          commits: maxCommits,
          min_severity: minSeverity,
        })
      });
    }

    data = await res.json();

    if (!res.ok) {
      showError(data.error || 'Scan failed.');
      return;
    }

    allFindings = data.findings;
    renderSummary(data.summary);
    renderFindings(allFindings);
    updateResultsMeta(data);
    navigateTo('results');

  } catch (err) {
    showError('Could not connect to the SecretScanner API. Make sure it is running on port 5000.');
  } finally {
    showLoading(false);
    document.getElementById('scan-btn').disabled = false;
  }
});

function renderSummary(summary) {
  document.getElementById('count-critical').textContent = summary.CRITICAL || 0;
  document.getElementById('count-high').textContent = summary.HIGH || 0;
  document.getElementById('count-medium').textContent = summary.MEDIUM || 0;
  document.getElementById('count-low').textContent = summary.LOW || 0;
  document.getElementById('summary').classList.remove('hidden');
}

function renderFindings(findings) {
  const tbody = document.getElementById('findings-body');
  const noFindings = document.getElementById('no-findings');
  tbody.innerHTML = '';

  if (findings.length === 0) {
    noFindings.classList.remove('hidden');
    return;
  }

  noFindings.classList.add('hidden');

  findings.forEach(f => {
    const tr = document.createElement('tr');
    const sev = (f.severity || 'LOW').toLowerCase();
    const type = (f.type || 'pattern').toLowerCase();

    tr.innerHTML = `
      <td><span class="badge badge-${sev}">${f.severity || 'LOW'}</span></td>
      <td>${escapeHtml(f.name || '')}</td>
      <td>${escapeHtml(shortPath(f.file || ''))}</td>
      <td>${f.line || '?'}</td>
      <td class="match-cell" title="${escapeHtml(f.match || '')}">${escapeHtml(f.match || '')}</td>
      <td><span class="badge badge-${type}">${f.source || f.type || 'file'}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById('filter-input').addEventListener('input', applyFilters);
document.getElementById('filter-severity').addEventListener('change', applyFilters);
document.getElementById('filter-type').addEventListener('change', applyFilters);

function applyFilters() {
  const text = document.getElementById('filter-input').value.toLowerCase();
  const severity = document.getElementById('filter-severity').value.toUpperCase();
  const type = document.getElementById('filter-type').value.toLowerCase();

  const filtered = allFindings.filter(f => {
    const matchesText = !text ||
      (f.file || '').toLowerCase().includes(text) ||
      (f.name || '').toLowerCase().includes(text) ||
      (f.match || '').toLowerCase().includes(text);

    const matchesSeverity = !severity || (f.severity || '').toUpperCase() === severity;
    const matchesType = !type || (f.type || '').toLowerCase() === type;

    return matchesText && matchesSeverity && matchesType;
  });

  renderFindings(filtered);
}

function showLoading(show) {
  document.getElementById('loading').classList.toggle('hidden', !show);
}

function showError(msg) {
  const box = document.getElementById('error-box');
  box.textContent = msg;
  box.classList.remove('hidden');
}

function hideError() {
  document.getElementById('error-box').classList.add('hidden');
}

function updateResultsMeta(data) {
  document.getElementById('results-meta').textContent =
    `${data.total} finding(s) in ${data.path}`;
}

function navigateTo(page) {
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.page === page);
  });
  document.querySelectorAll('.page').forEach(p => {
    p.classList.add('hidden');
    p.classList.remove('active');
  });
  const target = document.getElementById(`page-${page}`);
  target.classList.remove('hidden');
  target.classList.add('active');
}

function shortPath(filepath) {
  const parts = filepath.split('/');
  return parts.length > 3 ? '...' + parts.slice(-2).join('/') : filepath;
}

function escapeHtml(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

document.getElementById('export-btn').addEventListener('click', () => {
  if (!allFindings.length) return;
  const headers = ['Severity', 'Name', 'File', 'Line', 'Match', 'Source'];
  const rows = allFindings.map(f => [
    f.severity, f.name, f.file, f.line, f.match, f.source
  ].map(v => `"${String(v || '').replace(/"/g, '""')}"`).join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'credentialscanner-results.csv';
  a.click();
  URL.revokeObjectURL(url);
});