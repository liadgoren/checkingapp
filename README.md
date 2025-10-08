# CheckingApp – DevSecOps Assignment

Python Flask microservice that exposes two endpoints:

- `POST /scan/secrets` – clones a repo and runs **Gitleaks** to detect potential secrets.  
- `POST /scan/code` – clones a repo and searches for dangerous patterns loaded from `config.txt`
  (e.g., `eval`, `exec`, `pickle.load`).

The service is containerized with **Docker** and continuously integrated using **GitHub Actions**.  
Each build performs:
- **Unit tests** (Pytest)
- **Security scanning** with **Trivy**
- **Automated Docker image build and push** to Docker Hub (only if all tests pass)
---

## Endpoints

### 1) `POST /scan/secrets`
**Body**
```json
{ "url": "https://github.com/owner/repo.git" }
```
Response(Examples):

When Gitleaks returns JSON:
```json
{
  "repository": "...",
  "scan_type": "secrets",
  "status": "completed",
  "summary": { "leaks_found": false, "total_findings": 0 },
  "findings": [] 
}
```
When only logs are available:
```json
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
```

### 2) `POST /scan/code`

config.txt example:
appPort=6000
searchPatterns=password;secret;eval(;exec(;pickle.load;eval;subprocess.run(

Repo to check(Example): 
{ "url": "https://github.com/owner/repo.git" }

Response:
```json
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
```

### How to Run it?

#### Run locally
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
# start the API
```bash
python scanApi.py
```
# The service runs on http://127.0.0.1:6000 (unless overridden by config.txt)

# Run with curl Scan for secrets
```bash
curl -s -X POST http://127.0.0.1:6000/scan/secrets \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com/owner/repo.git"}' | jq
```

# Run with curl Scan for code issues
```bash
curl -s -X POST http://127.0.0.1:6000/scan/code \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com/owner/repo.git"}' | jq
  ```

# Run with Docker
```bash
docker build -t checkingapp:dev .
docker run --rm -p 6000:6000 checkingapp:dev
```

#### Unit tests
To run tests locally:
```bash
pip install pytest
pytest -v
```

Notes:
Tests use Flask’s test_client and unittest.mock.patch to stub git clone and gitleaks, so no external tools are needed during tests.