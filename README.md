# CheckingApp – DevSecOps Assignment

Python Flask microservice that exposes two endpoints:

- `POST /scan/secrets` – clones a repo and runs **Gitleaks** to detect potential secrets.  
- `POST /scan/code` – clones a repo and searches for dangerous patterns loaded from `config.txt`
  (e.g., `eval`, `exec`, `pickle.load`).

The service is containerized with Docker.  
CI/CD is implemented with **GitHub Actions** and **Trivy** to scan the image for **vulnerabilities** before pushing to Docker Hub.

---

## Endpoints

### 1) `POST /scan/secrets`
**Body**
```json
{ "url": "https://github.com/owner/repo.git" }

Response(Examples):
When Gitleaks returns JSON:
{
  "repository": "...",
  "scan_type": "secrets",
  "status": "completed",
  "summary": { "leaks_found": false, "total_findings": 0 },
  "findings": []
}
When only logs are available:
{
  "repository": "...",
  "scan_type": "secrets",
  "status": "completed",
  "summary": {
    "leaks_found": false,
    "commits_scanned": 1,
    "data_scanned_kb": 8.85,
    "message": "No leaks found"
  },
  "findings": []
}

### 1) `POST /scan/code`

config.txt example:
appPort=6000
searchPatterns=password;secret;eval(;exec(;pickle.load;eval;subprocess.run(

Repo to check(Example): 
{ "url": "https://github.com/owner/repo.git" }

Response:
{
  "repository": "...",
  "scan_type": "code",
  "status": "Valid!/Invalid!!",
  "issues": [
    {
      "file": "path/in/repo.py",
      "line": 14,
      "pattern": "eval",
      "content": "result = eval(user_input)"
    }
  ]
}

#How to Run it ?#
Run locally:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# start the API
python scanApi.py
# the service runs on http://127.0.0.1:6000 (unless overridden by config.txt)

Run with curl:

curl -s -X POST http://127.0.0.1:6000/scan/secrets \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com/owner/repo.git"}' | jq

curl -s -X POST http://127.0.0.1:6000/scan/code \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com/owner/repo.git"}' | jq


Run with Docker
docker build -t checkingapp:dev .
docker run --rm -p 6000:6000 checkingapp:dev

Unit tests:
pip install pytest
pytest -v


