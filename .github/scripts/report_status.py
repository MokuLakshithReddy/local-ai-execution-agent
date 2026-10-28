import os
import sys
import json
import urllib.request

def main():
    gh_token = os.environ.get("GH_TOKEN")
    sha = os.environ.get("SHA")
    repo = os.environ.get("REPO")
    job_status = os.environ.get("JOB_STATUS", "failure")
    job_name = os.environ.get("JOB_NAME", "CI")
    strict = (os.environ.get("STRICT_STATUS_REPORTING") == "1")

    if not gh_token or not sha or not repo:
        msg = f"Missing required environment variables for status reporting: token={'set' if gh_token else 'unset'}, sha={'set' if sha else 'unset'}, repo={'set' if repo else 'unset'}"
        print(f"::warning title=Commit Status Reporter Incomplete Configuration::{msg}", file=sys.stderr)
        if strict:
            sys.exit(1)
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
            summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
            if summary_file and os.path.exists(os.path.dirname(summary_file) or "."):
                with open(summary_file, "a", encoding="utf-8") as sf:
                    sf.write(f"\n### ✅ Commit Status Published\n- **Context**: `{job_name}`\n- **State**: `{state}`\n- **Target**: `{url}`\n")
    except Exception as e:
        err_msg = f"Failed to publish commit status for '{job_name}' to {url}: {e}"
        print(f"::error title=Commit Status Reporting Failed::{err_msg}", file=sys.stderr)
        summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_file and os.path.exists(os.path.dirname(summary_file) or "."):
            with open(summary_file, "a", encoding="utf-8") as sf:
                sf.write(f"\n### ⚠️ Commit Status Publication Failed\n- **Context**: `{job_name}`\n- **Error**: `{e}`\n- **Action Required**: Verify GITHUB_TOKEN permissions (statuses: write).\n")
        if strict:
            sys.exit(1)

if __name__ == "__main__":
    main()
