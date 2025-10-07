import json
from unittest.mock import patch
from scanApi import app

app.testing = True
client = app.test_client()


def test_scan_secrets_missing_url():
    resp = client.post("/scan/secrets", json={})
    assert resp.status_code == 400
    assert "error" in resp.get_json()


@patch("scanApi.clone_repo", return_value=(True, None))
@patch("subprocess.run")
def test_scan_secrets_ok(mock_run, _):
    mock_run.return_value = type("R", (), {"stderr": "[]", "stdout": "", "returncode": 0})
    resp = client.post("/scan/secrets", json={"url": "https://example.com/repo.git"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["scan_type"] == "secrets"
    assert data["status"] == "completed"

