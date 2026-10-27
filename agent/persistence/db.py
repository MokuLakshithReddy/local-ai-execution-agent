"""
SQLite database persistence for tasks, logs, approvals, and application settings.
"""
import aiosqlite
import json
import os
import time
from typing import Any, Dict, List, Optional
from agent.core.models import Task, TaskStatus, TaskReport, ApprovalRequest

DB_PATH = "agent_state.db"


class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    goal TEXT NOT NULL,
                    workspace_path TEXT NOT NULL,
                    model_provider TEXT NOT NULL,
                    model_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_step INTEGER DEFAULT 0,
                    max_steps INTEGER DEFAULT 30,
                    plan_json TEXT,
                    report_json TEXT,
                    error TEXT,
                    created_at REAL,
                    updated_at REAL
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS task_steps (
                    step_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    step_num INTEGER NOT NULL,
                    step_type TEXT NOT NULL,
                    content TEXT,
                    metadata_json TEXT,
                    timestamp REAL,
                    FOREIGN KEY(task_id) REFERENCES tasks(id)
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    task_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    arguments_json TEXT NOT NULL,
                    permission_level TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL,
                    requested_at REAL,
                    resolved_at REAL
                )
            """)
            await db.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL
                )
            """)
            await db.commit()

    async def save_task(self, task: Task):
        async with aiosqlite.connect(self.db_path) as db:
            plan_str = json.dumps(task.plan)
            report_str = task.final_report.model_dump_json() if task.final_report else None
            await db.execute("""
                INSERT INTO tasks (
                    id, goal, workspace_path, model_provider, model_name, status,
                    current_step, max_steps, plan_json, report_json, error, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status=excluded.status,
                    current_step=excluded.current_step,
                    plan_json=excluded.plan_json,
                    report_json=excluded.report_json,
                    error=excluded.error,
                    updated_at=excluded.updated_at
            """, (
                task.id, task.goal, task.workspace_path, task.model_provider, task.model_name,
                task.status.value, task.current_step, task.max_steps, plan_str, report_str,
                task.error, task.created_at, time.time()
            ))
            await db.commit()

    async def get_task(self, task_id: str) -> Optional[Task]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
            row = await cursor.fetchone()
            if not row:
                return None
            plan = json.loads(row["plan_json"]) if row["plan_json"] else []
            report = TaskReport.model_validate_json(row["report_json"]) if row["report_json"] else None
            return Task(
                id=row["id"],
                goal=row["goal"],
                workspace_path=row["workspace_path"],
                model_provider=row["model_provider"],
                model_name=row["model_name"],
                status=TaskStatus(row["status"]),
                current_step=row["current_step"],
                max_steps=row["max_steps"],
                plan=plan,
                created_at=row["created_at"],
                updated_at=row["updated_at"],
                error=row["error"],
                final_report=report,
            )

    async def list_tasks(self, limit: int = 50) -> List[Task]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?", (limit,))
            rows = await cursor.fetchall()
            tasks = []
            for row in rows:
                plan = json.loads(row["plan_json"]) if row["plan_json"] else []
                report = TaskReport.model_validate_json(row["report_json"]) if row["report_json"] else None
                tasks.append(
                    Task(
                        id=row["id"],
                        goal=row["goal"],
                        workspace_path=row["workspace_path"],
                        model_provider=row["model_provider"],
                        model_name=row["model_name"],
                        status=TaskStatus(row["status"]),
                        current_step=row["current_step"],
                        max_steps=row["max_steps"],
                        plan=plan,
                        created_at=row["created_at"],
                        updated_at=row["updated_at"],
                        error=row["error"],
                        final_report=report,
                    )
                )
            return tasks

    async def log_step(self, step_id: str, task_id: str, step_num: int, step_type: str, content: str, metadata: Dict[str, Any] = None):
        async with aiosqlite.connect(self.db_path) as db:
            meta_json = json.dumps(metadata or {})
            await db.execute("""
                INSERT INTO task_steps (step_id, task_id, step_num, step_type, content, metadata_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (step_id, task_id, step_num, step_type, content, meta_json, time.time()))
            await db.commit()

    async def get_task_steps(self, task_id: str) -> List[Dict[str, Any]]:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT * FROM task_steps WHERE task_id = ? ORDER BY step_num ASC, timestamp ASC", (task_id,))
            rows = await cursor.fetchall()
            return [
                {
                    "step_id": r["step_id"],
                    "task_id": r["task_id"],
                    "step_num": r["step_num"],
                    "step_type": r["step_type"],
                    "content": r["content"],
                    "metadata": json.loads(r["metadata_json"]) if r["metadata_json"] else {},
                    "timestamp": r["timestamp"],
                }
                for r in rows
            ]

    async def save_setting(self, key: str, value: Any):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT INTO settings (key, value_json) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json
            """, (key, json.dumps(value)))
            await db.commit()

    async def get_setting(self, key: str, default: Any = None) -> Any:
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT value_json FROM settings WHERE key = ?", (key,))
            row = await cursor.fetchone()
            if not row:
                return default
            return json.loads(row["value_json"])
