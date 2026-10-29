"""
FastAPI Server & WebSocket bridge for the Local-First AI Execution Agent.
Secured with local session token authorization, strict CORS boundaries,
and an approved workspace registry.
"""
import asyncio
import os
import secrets
import sys
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Header, Request, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.core.models import Task, TaskStatus, TaskType
from agent.core.engine import ExecutionEngine
from agent.persistence.db import Database
from agent.security.permissions import PermissionManager, PermissionPolicy
from agent.tools.registry import ToolRegistry

import urllib.parse

# Auth Token setup
TOKEN_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".agent_session_token")


def _lock_down_token_file(filepath: str):
    """Enforces strict user-only ACLs on the session token file. Fails safely on error."""
    if sys.platform == "win32":
        import subprocess
        from agent.security.provenance import validate_windows_acl_allowlist
        username = os.environ.get("USERNAME")
        if not username:
            raise RuntimeError("Security Failure: Unable to determine active USERNAME for token ACL configuration.")
        try:
            reset_res = subprocess.run(
                ["icacls", filepath, "/reset"],
                capture_output=True,
                text=True,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            if reset_res.returncode != 0:
                raise RuntimeError(f"Security Failure: icacls failed to reset token file ACLs ({reset_res.stderr.strip()})")
            res = subprocess.run(
                ["icacls", filepath, "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                capture_output=True,
                text=True,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            if res.returncode != 0:
                raise RuntimeError(f"Security Failure: icacls failed to lock down token file ACLs ({res.stderr.strip()})")
            audit_res = subprocess.run(
                ["icacls", filepath],
                capture_output=True,
                text=True,
                check=False,
                stdin=subprocess.DEVNULL,
                timeout=15,
            )
            if audit_res.returncode != 0:
                raise RuntimeError(f"Security Failure: icacls failed to audit token file ACLs ({audit_res.stderr.strip()})")
            validate_windows_acl_allowlist(
                icacls_stdout=audit_res.stdout,
                filepath=filepath,
                expected_username=username,
                allowed_rights={"(R,W)", "(W,R)"},
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"Security Failure: icacls timed out locking down token file ACLs: {exc}") from exc
        except Exception as err:
            if "Security Failure" in str(err):
                raise
            raise RuntimeError(f"Security Failure: Token file retained unauthorized ACL: {err}") from err
    elif hasattr(os, "chmod"):
        try:
            os.chmod(filepath, 0o600)
        except Exception as e:
            raise RuntimeError(f"Security Failure: Failed to set 0600 permissions on token file ({str(e)})") from e


def _get_or_create_session_token() -> str:
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r", encoding="utf-8") as f:
                t = f.read().strip()
                if len(t) >= 32:
                    return t
        except Exception as e:
            if "Security Failure" in str(e):
                raise

    token = secrets.token_urlsafe(32)
    try:
        with open(TOKEN_FILE, "w", encoding="utf-8") as f:
            f.write(token)
        _lock_down_token_file(TOKEN_FILE)
    except Exception as e:
        if "Security Failure" in str(e):
            raise
        raise RuntimeError(f"Security Failure: Failed to create and secure token file: {str(e)}") from e
    return token


SESSION_TOKEN = _get_or_create_session_token()

# Strict CORS: Only allow local loopback origins
ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

# Allowed host names to block DNS Rebinding attacks
ALLOWED_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


def _extract_hostname(host_header: str) -> str:
    """Extracts canonical hostname from a Host header, correctly handling IPv4, IPv6, and ports."""
    if not host_header:
        return ""
    host_header = host_header.strip()
    # Check for bare IPv6 (e.g. '::1' without brackets or port)
    if ":" in host_header and not host_header.startswith("[") and host_header.count(":") >= 2:
        try:
            import ipaddress
            ipaddress.IPv6Address(host_header)
            return host_header.lower()
        except Exception:
            pass
    try:
        parsed = urllib.parse.urlsplit(f"//{host_header}")
        hostname = parsed.hostname
        if not hostname:
            # Fallback for simple hostnames or colons
            return host_header.split(":")[0].strip("[]").lower()
        return hostname.strip("[]").lower()
    except Exception:
        return host_header.split(":")[0].strip("[]").lower()



app = FastAPI(title="Local-First AI Execution Agent", version="1.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def dns_rebinding_protection_middleware(request: Request, call_next):
    """Blocks DNS rebinding attacks by validating the Host header across IPv4 and IPv6."""
    host_header = request.headers.get("host", "")
    hostname = _extract_hostname(host_header)
    if not hostname or hostname not in ALLOWED_HOSTS:
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=400,
            content={"detail": "Bad Request: Untrusted or invalid Host header (DNS rebinding protection)."},
        )
    return await call_next(request)

db = Database()
permission_manager = PermissionManager()
tool_registry = ToolRegistry()

# Active WebSocket connections
active_connections: List[WebSocket] = []


async def broadcast_event(event_type: str, data: Dict[str, Any]):
    message = {"type": event_type, "data": data}
    disconnected = []
    for conn in active_connections:
        try:
            await conn.send_json(message)
        except Exception:
            disconnected.append(conn)
    for conn in disconnected:
        if conn in active_connections:
            active_connections.remove(conn)


engine = ExecutionEngine(
    db=db,
    tool_registry=tool_registry,
    permission_manager=permission_manager,
    on_event=broadcast_event,
)


def verify_auth(
    x_agent_auth_token: Optional[str] = Header(None, alias="X-Agent-Auth-Token"),
    authorization: Optional[str] = Header(None),
):
    """Verifies that the request provides the local session token."""
    token = x_agent_auth_token
    if not token and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            token = parts[1]

    if not token or not secrets.compare_digest(token, SESSION_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Missing or invalid local session auth token.",
        )
    return token


@app.on_event("startup")
async def on_startup():
    await db.init()
    # Seed current project directory as default approved workspace
    curr_dir = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    existing_ws = await db.get_setting("current_workspace")
    if not existing_ws:
        await db.save_setting("current_workspace", curr_dir)

    approved = await db.get_setting("approved_workspaces", [])
    if curr_dir not in approved:
        approved.append(curr_dir)
        await db.save_setting("approved_workspaces", approved)


@app.get("/api/auth/token")
async def get_session_token(request: Request):
    """
    Returns the session token only for direct local loopback requests,
    allowing the frontend running locally to bootstrap securely.
    Guarded against browser-origin attacks, cross-site requests, and unauthorized origins.
    """
    client_host = request.client.host if request.client else ""
    if client_host not in ("127.0.0.1", "localhost", "::1", "testclient"):
        raise HTTPException(status_code=403, detail="Forbidden: Handshake only available from loopback.")

    # 1. Sec-Fetch-Site defense: Modern browsers set this to cross-site when initiated from third-party origins
    sec_fetch_site = request.headers.get("sec-fetch-site", "").lower()
    if sec_fetch_site == "cross-site":
        raise HTTPException(status_code=403, detail="Forbidden: Cross-site request blocked.")

    # 2. Origin defense: If browser Origin header is present, it must be an approved local origin
    origin = request.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail=f"Forbidden: Origin '{origin}' is not authorized to bootstrap session token.")

    return {"token": SESSION_TOKEN}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
    # Validate origin if sent by browser
    origin = websocket.headers.get("origin")
    if origin and origin not in ALLOWED_ORIGINS:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Validate authorization token before accepting WebSocket
    if not token or not secrets.compare_digest(token, SESSION_TOKEN):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("action") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        if websocket in active_connections:
            active_connections.remove(websocket)


# Request schemas
class CreateTaskRequest(BaseModel):
    goal: str
    workspace_path: Optional[str] = None
    model_provider: str = "gemini"
    model_name: str = "gemini-2.5-flash"
    max_steps: int = 30
    api_key: Optional[str] = None
    custom_base_url: Optional[str] = None


class ApproveWorkspaceRequest(BaseModel):
    workspace_path: str


class ResolveApprovalRequest(BaseModel):
    approved: bool


class SaveSettingsRequest(BaseModel):
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    gemini_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = "http://localhost:11434/v1"
    auto_approve_routine: bool = True
    auto_approve_sensitive: bool = False
    current_workspace: Optional[str] = None


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "app": "Local-First AI Execution Agent", "version": "1.1.0"}


@app.get("/api/workspaces", dependencies=[Depends(verify_auth)])
async def get_workspaces():
    current_ws = await db.get_setting("current_workspace", os.getcwd())
    approved_ws = await db.get_setting("approved_workspaces", [current_ws])
    return {
        "current": current_ws,
        "approved": approved_ws,
    }


@app.post("/api/workspaces/approve", dependencies=[Depends(verify_auth)])
async def approve_workspace(req: ApproveWorkspaceRequest):
    real_path = os.path.realpath(req.workspace_path)
    if not os.path.exists(real_path) or not os.path.isdir(real_path):
        raise HTTPException(status_code=400, detail="Invalid workspace path: directory does not exist.")

    approved = await db.get_setting("approved_workspaces", [])
    if real_path not in approved:
        approved.append(real_path)
        await db.save_setting("approved_workspaces", approved)

    return {"status": "approved", "workspace": real_path, "approved_workspaces": approved}


@app.get("/api/models", dependencies=[Depends(verify_auth)])
async def get_supported_models():
    return {
        "providers": [
            {
                "id": "gemini",
                "name": "Google Gemini",
                "models": ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-1.5-pro"],
                "requires_api_key": True,
            },
            {
                "id": "openai",
                "name": "OpenAI",
                "models": ["gpt-4o", "gpt-4o-mini", "o3-mini"],
                "requires_api_key": True,
            },
            {
                "id": "anthropic",
                "name": "Anthropic Claude",
                "models": ["claude-3-7-sonnet-20250219", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
                "requires_api_key": True,
            },
            {
                "id": "ollama",
                "name": "Ollama (Local)",
                "models": ["qwen2.5-coder:latest", "llama3.1:latest", "deepseek-coder:latest"],
                "requires_api_key": False,
            },
            {
                "id": "compatible",
                "name": "OpenAI Compatible / Custom",
                "models": ["custom-model"],
                "requires_api_key": True,
            },
        ]
    }


@app.get("/api/settings", dependencies=[Depends(verify_auth)])
async def get_settings():
    settings = await db.get_setting("app_settings", {})
    return {
        "openai_api_key_set": bool(settings.get("openai_api_key")),
        "anthropic_api_key_set": bool(settings.get("anthropic_api_key")),
        "gemini_api_key_set": bool(settings.get("gemini_api_key")),
        "ollama_base_url": settings.get("ollama_base_url", "http://localhost:11434/v1"),
        "auto_approve_routine": settings.get("auto_approve_routine", True),
        "auto_approve_sensitive": settings.get("auto_approve_sensitive", False),
        "current_workspace": await db.get_setting("current_workspace", os.getcwd()),
    }


@app.post("/api/settings", dependencies=[Depends(verify_auth)])
async def save_settings(req: SaveSettingsRequest):
    settings = await db.get_setting("app_settings", {})
    if req.openai_api_key is not None:
        settings["openai_api_key"] = req.openai_api_key
    if req.anthropic_api_key is not None:
        settings["anthropic_api_key"] = req.anthropic_api_key
    if req.gemini_api_key is not None:
        settings["gemini_api_key"] = req.gemini_api_key
    if req.ollama_base_url is not None:
        settings["ollama_base_url"] = req.ollama_base_url
    settings["auto_approve_routine"] = req.auto_approve_routine
    settings["auto_approve_sensitive"] = req.auto_approve_sensitive

    permission_manager.policy = PermissionPolicy(
        auto_approve_routine=req.auto_approve_routine,
        auto_approve_sensitive=req.auto_approve_sensitive,
    )

    try:
        await db.save_setting("app_settings", settings)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Security Error: Failed to encrypt credentials safely ({str(e)}). Plaintext persistence rejected.",
        )
    if req.current_workspace:
        real_ws = os.path.realpath(req.current_workspace)
        await db.save_setting("current_workspace", real_ws)

    return {"status": "saved"}


@app.post("/api/tasks", dependencies=[Depends(verify_auth)])
async def create_task(req: CreateTaskRequest):
    target_ws = req.workspace_path or await db.get_setting("current_workspace", os.getcwd())
    real_ws = os.path.realpath(target_ws)

    if not os.path.exists(real_ws) or not os.path.isdir(real_ws):
        raise HTTPException(status_code=400, detail=f"Workspace path does not exist: {target_ws}")

    # Validate against Approved Workspace Registry
    approved_workspaces = await db.get_setting("approved_workspaces", [])
    if real_ws not in approved_workspaces:
        raise HTTPException(
            status_code=403,
            detail=f"Forbidden: Workspace '{real_ws}' has not been approved in the workspace registry.",
        )

    # Resolve API key securely
    settings = await db.get_setting("app_settings", {})
    api_key = req.api_key
    if not api_key:
        provider = req.model_provider.lower()
        if "gemini" in provider:
            api_key = settings.get("gemini_api_key") or os.environ.get("GEMINI_API_KEY", "")
        elif "anthropic" in provider:
            api_key = settings.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY", "")
        elif "openai" in provider:
            api_key = settings.get("openai_api_key") or os.environ.get("OPENAI_API_KEY", "")
        elif "ollama" in provider:
            api_key = "ollama"

    if not api_key and req.model_provider not in ("ollama", "local"):
        raise HTTPException(
            status_code=400,
            detail=f"API key for '{req.model_provider}' is not configured. Please supply an API key in Settings.",
        )

    task_id = str(uuid.uuid4())
    task = Task(
        id=task_id,
        goal=req.goal,
        workspace_path=real_ws,
        model_provider=req.model_provider,
        model_name=req.model_name,
        max_steps=req.max_steps,
    )

    # Launch in background
    asyncio.create_task(
        engine.run_task(
            task=task,
            api_key=api_key or "",
            custom_base_url=req.custom_base_url or settings.get("ollama_base_url"),
        )
    )

    return {"task_id": task_id, "status": "started"}


@app.get("/api/tasks", dependencies=[Depends(verify_auth)])
async def list_tasks():
    tasks = await db.list_tasks(limit=30)
    return {"tasks": [t.model_dump() for t in tasks]}


@app.get("/api/tasks/{task_id}", dependencies=[Depends(verify_auth)])
async def get_task_details(task_id: str):
    task = await db.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    steps = await db.get_task_steps(task_id)
    return {"task": task.model_dump(), "steps": steps}


@app.post("/api/tasks/{task_id}/cancel", dependencies=[Depends(verify_auth)])
async def cancel_task(task_id: str):
    engine.cancel_task(task_id)
    return {"status": "cancellation_requested", "task_id": task_id}


@app.get("/api/approvals/pending", dependencies=[Depends(verify_auth)])
async def get_pending_approvals():
    return {
        "approvals": [a.model_dump() for a in permission_manager.pending_approvals.values()]
    }


@app.post("/api/approvals/{approval_id}", dependencies=[Depends(verify_auth)])
async def resolve_approval(approval_id: str, req: ResolveApprovalRequest):
    resolved = permission_manager.resolve_approval(approval_id, req.approved)
    if not resolved:
        raise HTTPException(status_code=404, detail="Pending approval not found or already resolved.")
    await broadcast_event("approval_resolved", {"approval_id": approval_id, "status": resolved.status})
    return {"status": "resolved", "approval": resolved.model_dump()}


@app.get("/api/diff", dependencies=[Depends(verify_auth)])
async def get_workspace_diff(workspace_path: Optional[str] = None):
    ws = workspace_path or await db.get_setting("current_workspace", os.getcwd())
    real_ws = os.path.realpath(ws)
    res = await tool_registry.execute_tool("git_diff", workspace_path=real_ws)
    return {"diff": res.output if res.success else "", "error": res.error}


# Mount built frontend files if they exist in `ui/dist`
ui_dist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ui", "dist")
if os.path.exists(ui_dist_path):
    app.mount("/", StaticFiles(directory=ui_dist_path, html=True), name="static")
