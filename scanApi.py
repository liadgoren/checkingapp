import os
import tempfile
import subprocess
import shutil
import json
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

CONFIG_FILE = "config.txt"
SEARCH_PATTERNS = []
APP_PORT = 5000  # default


def clone_repo(repo_url, dest_dir):
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, dest_dir],
            check=True,
            capture_output=True
        )
        return True, None
    except subprocess.CalledProcessError as e:
        return False, e.stderr.decode("utf-8")


def load_config():
    """
    Reads config.txt with keys:
    - appPort=<number>
    - searchPatterns=pattern1;pattern2;...
    """
    global SEARCH_PATTERNS, APP_PORT

    if not os.path.exists(CONFIG_FILE):
        print("⚠️ Config file not found, using defaults")
        return

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    for line in lines:
        if line.lower().startswith("appport="):
            try:
                APP_PORT = int(line.split("=", 1)[1].strip())
            except ValueError:
                print("⚠️ Invalid appPort value, using default 5000")
                APP_PORT = 5000

        elif line.lower().startswith("searchpatterns="):
            patterns_str = line.split("=", 1)[1].strip()
            if patterns_str:
                SEARCH_PATTERNS = [s.strip() for s in patterns_str.split(";") if s.strip()]


@app.route("/scan/secrets", methods=["POST"])
def scan_secrets():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400
    
    repo_url = data["url"]
    temp_dir = tempfile.mkdtemp()

    try:
        success, error = clone_repo(repo_url, temp_dir)
        if not success:
            return jsonify({"error": f"Failed to clone repo: {error}"}), 500

        try:
            result = subprocess.run(
                ["gitleaks", "detect", "--source", temp_dir, "--report-format", "json", "--no-banner"],
                capture_output=True,
                text=True,
                check=False
            )
            findings = result.stderr.strip()
            findings = re.sub(r'\x1b\[[0-9;]*m', '', findings)
            findings = findings.encode('ascii', errors='ignore').decode()
            findings = findings.encode("ascii", errors="ignore").decode()
            findings_json = []
            if findings:
                try:
                    findings_json = json.loads(findings)
                except Exception:
                    findings_json = findings

            return jsonify({
                "repository": repo_url,
                "scan_type": "secrets",
                "status": "completed",
                "findings": findings_json
            }), 200

        except FileNotFoundError:
            return jsonify({"error": "Gitleaks not installed or not in PATH"}), 500

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.route("/scan/code", methods=["POST"])
def scan_code():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url' field"}), 400
    
    repo_url = data["url"]
    temp_dir = tempfile.mkdtemp()
    repotStatus = "Valid!"

    try:
        success, error = clone_repo(repo_url, temp_dir)
        if not success:
            return jsonify({"error": f"Failed to clone repo: {error}"}), 500

        if not SEARCH_PATTERNS:
            return jsonify({"error": "No search patterns loaded from config"}), 500

        issues = []
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for lineno, line in enumerate(f, start=1):
                            for pattern in SEARCH_PATTERNS:
                                if pattern in line:
                                    issues.append({
                                        "file": os.path.relpath(file_path, temp_dir),
                                        "line": lineno,
                                        "pattern": pattern,
                                        "content": line.strip()
                                    })
                                    repotStatus = "Invalid!!"
                except Exception:
                    continue

        return jsonify({
            "repository": repo_url,
            "scan_type": "code",
            "status": repotStatus,
            "issues": issues
        }), 200

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    load_config()
    print(f"✅ Loaded patterns: {SEARCH_PATTERNS}")
    print(f"✅ Running Flask on port {APP_PORT}")
    app.run(host="0.0.0.0", port=APP_PORT, debug=True)
