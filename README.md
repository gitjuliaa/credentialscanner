# Credential Scanner

A security tool that detects leaked API keys, tokens, and secrets. The tool utilises regex pattern matching and Shannon entropy analysis to catch code that looks like secrets.

Built with Python/Flask (Gunicorn in production), JavaScript frontend, Docker and deployed on Railway. 
**Live Demo**: [credentialscanner-production.up.railway.app](https://credentialscanner-production.up.railway.app)


## What it detects

Regex patterns for 15+ known secret formats — AWS keys, GitHub tokens, Stripe keys, private keys, JWTs, etc. On top of that, Shannon entropy analysis flags high-randomness strings that don't match any pattern but probably shouldn't be in your code:

```
H = -∑ p(x) log₂ p(x)
```

It also scans git history, so secrets that were deleted from code but still live in old commits won't slip through. Findings come back with severity levels (Critical / High / Medium / Low) and can be exported to CSV.


## Running Locally

Clone the repo first:
```bash
git clone https://github.com/gitjuliaa/credentialscanner.git
cd credentialscanner
```

### With Docker
```bash
docker compose up --build
```

### Without Docker
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
Then open http://localhost:5000

## API 

Scan a local directory:
```bash
curl -X POST https://credentialscanner-production.up.railway.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"path": "./myproject", "git": true, "min_severity": "HIGH"}'
```

Scan a GitHub repo:
```bash
curl -X POST https://credentialscanner-production.up.railway.app/api/scan/github \
  -H "Content-Type: application/json" \
  -d '{"url": "https://github.com/username/repo", "git": true}'
```
Example response:

```json
{
  "total": 2,
  "findings": [
    {
      "severity": "CRITICAL",
      "name": "AWS Access Key",
      "file": "config.py",
      "line": 14,
      "match": "AKIA...",
      "source": "file"
    },
    {
      "severity": "HIGH",
      "name": "High Entropy String",
      "file": "utils.py",
      "line": 67,
      "entropy": 4.82,
      "source": "git"
    }
  ]
}
```

## License

MIT