"""
FastAPI Server & WebSocket bridge for the Local-First AI Execution Agent.
"""
import asyncio
import os
import uuid
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agent.core.models import Task, TaskStatus, PermissionLevel
from agent.core.engine import ExecutionEngine
from agent.persistence.db import Database
from agent.security.permissions import PermissionManager, PermissionPolicy
from agent.tools.registry import ToolRegistry


app = FastAPI(title="AI Execution Agent", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


@app.on_event("startup")
async def on_startup():
    await db.init()
    # Seed default workspace if none
    curr_dir = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    existing_ws = await db.get_setting("current_workspace")
    if not existing_ws:
        await db.save_setting("current_workspace", curr_dir)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            # Handle client-initiated ping or action if needed
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
    return {"status": "ok", "app": "Local-First AI Execution Agent"}


@app.get("/api/workspaces")
async def get_workspaces():
    current_ws = await db.get_setting("current_workspace", os.getcwd())
    return {
        "current": current_ws,
        "available": [
            current_ws,
            os.path.abspath(os.getcwd()),
        ],
    }


@app.get("/api/models")
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


@app.get("/api/settings")
async def get_settings():
    settings = await db.get_setting("app_settings", {})
    # Redact keys for client display
    return {
        "openai_api_key_set": bool(settings.get("openai_api_key")),
        "anthropic_api_key_set": bool(settings.get("anthropic_api_key")),
        "gemini_api_key_set": bool(settings.get("gemini_api_key")),
        "ollama_base_url": settings.get("ollama_base_url", "http://localhost:11434/v1"),
        "auto_approve_routine": settings.get("auto_approve_routine", True),
        "auto_approve_sensitive": settings.get("auto_approve_sensitive", False),
        "current_workspace": await db.get_setting("current_workspace", os.getcwd()),
    }


@app.post("/api/settings")
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

    # Update policy on permission manager
    permission_manager.policy = PermissionPolicy(
        auto_approve_routine=req.auto_approve_routine,
        auto_approve_sensitive=req.auto_approve_sensitive,
    )

    await db.save_setting("app_settings", settings)
    if req.current_workspace:
        await db.save_setting("current_workspace", os.path.abspath(req.current_workspace))

    return {"status": "saved"}


@app.post("/api/tasks")
async def create_task(req: CreateTaskRequest):
    workspace = req.workspace_path or await db.get_setting("current_workspace", os.getcwd())
    if not os.path.exists(workspace):
        raise HTTPException(status_code=400, detail=f"Workspace path does not exist: {workspace}")

    # Resolve API key
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
        workspace_path=os.path.abspath(workspace),
        model_provider=req.model_provider,
        model_name=req.model_name,
        max_steps=req.max_steps,
    )

    # Launch asynchronously in background
    asyncio.create_task(
        engine.run_task(
            task=task,
            api_key=api_key or "",
            custom_base_url=req.custom_base_url or settings.get("ollama_base_url"),
        )
    )

    return {"task_id": task_id, "status": "started"}


@app.get("/api/tasks")
async def list_tasks():
    tasks = await db.list_tasks(limit=30)
    return {"tasks": [t.model_dump() for t in tasks]}


@app.get("/api/tasks/{task_id}")
async def get_task_details(task_id: str):
    task = await db.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    steps = await db.get_task_steps(task_id)
    return {"task": task.model_dump(), "steps": steps}


@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    engine.cancel_task(task_id)
    return {"status": "cancellation_requested", "task_id": task_id}


@app.get("/api/approvals/pending")
async def get_pending_approvals():
    return {
        "approvals": [a.model_dump() for a in permission_manager.pending_approvals.values()]
    }


@app.post("/api/approvals/{approval_id}")
async def resolve_approval(approval_id: str, req: ResolveApprovalRequest):
    resolved = permission_manager.resolve_approval(approval_id, req.approved)
    if not resolved:
        raise HTTPException(status_code=404, detail="Pending approval not found or already resolved.")
    await broadcast_event("approval_resolved", {"approval_id": approval_id, "status": resolved.status})
    return {"status": "resolved", "approval": resolved.model_dump()}


@app.get("/api/diff")
async def get_workspace_diff(workspace_path: Optional[str] = None):
    ws = workspace_path or await db.get_setting("current_workspace", os.getcwd())
    res = await tool_registry.execute_tool("git_diff", workspace_path=ws)
    return {"diff": res.output if res.success else "", "error": res.error}


# Mount built frontend files if they exist in `ui/dist`
ui_dist_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ui", "dist")
if os.path.exists(ui_dist_path):
    app.mount("/", StaticFiles(directory=ui_dist_path, html=True), name="static")
