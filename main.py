"""
Launcher for the Local-First, Model-Agnostic AI Execution Agent.
Runs the FastAPI service & serves the interactive React frontend.
"""
import sys
import os
import webbrowser
import uvicorn

if __name__ == "__main__":
    # Ensure current directory is in sys.path
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    if curr_dir not in sys.path:
        sys.path.insert(0, curr_dir)

    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    host = "127.0.0.1"
    port = 8000
    url = f"http://{host}:{port}"

    print("=" * 70)
    print(">> Local-First, Model-Agnostic AI Execution Agent")
    print(f">> Web Dashboard & API active at: {url}")
    print(">> Permission boundaries, tool sandbox, & evidence engine initialized.")
    print("=" * 70)

    # Automatically launch browser if not headless
    if "--no-browser" not in sys.argv:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    uvicorn.run("agent.api.server:app", host=host, port=port, reload=False, log_level="info")
