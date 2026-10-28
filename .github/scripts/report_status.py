import os
import json
import urllib.request

def main():
    gh_token = os.environ.get("GH_TOKEN")
    sha = os.environ.get("SHA")
    repo = os.environ.get("REPO")
    job_status = os.environ.get("JOB_STATUS", "failure")
    job_name = os.environ.get("JOB_NAME", "CI")

    if not gh_token or not sha or not repo:
        print("Missing required environment variables for status reporting.")
        return

    state = "success" if job_status == "success" else "failure"
    url = f"https://api.github.com/repos/{repo}/statuses/{sha}"
    payload = {
        "state": state,
        "context": job_name,
        "description": f"{job_name}: {state}",
    }
    headers = {
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CI-Status-Reporter",
    }

    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"Reported status '{state}' for '{job_name}' (HTTP {resp.status}).")
    except Exception as e:
        print(f"Warning: Failed to report commit status: {e}")

if __name__ == "__main__":
    main()
