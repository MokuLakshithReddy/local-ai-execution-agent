"""
SQLite database persistence for tasks, logs, approvals, and application settings.
Includes automatic credential encryption and secret sanitization on all persisted data.
"""
import asyncio
import aiosqlite
import json
import os
import time
from typing import Any, Dict, List, Optional
from agent.core.models import Task, TaskStatus, TaskReport
from agent.persistence.credentials import vault
from agent.security.sanitizer import SecuritySanitizer

DB_PATH = "agent_state.db"
sanitizer = SecuritySanitizer()


class DatabaseWriteError(RuntimeError):
    """Raised when writing to SQLite database fails."""
    pass


class CredentialMigrationError(RuntimeError):
    """Raised when migrating a legacy credential fails."""
    pass


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
            plan_clean = [sanitizer.redact_secrets(p) for p in task.plan]
            plan_str = json.dumps(plan_clean)
            report_str = sanitizer.redact_secrets(task.final_report.model_dump_json()) if task.final_report else None
            error_clean = sanitizer.redact_secrets(task.error) if task.error else None
            
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
                error_clean, task.created_at, time.time()
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
            clean_content = sanitizer.redact_secrets(content or "")
            clean_metadata = {}
            if metadata:
                for k, v in metadata.items():
                    if isinstance(v, str):
                        clean_metadata[k] = sanitizer.redact_secrets(v)
                    else:
                        clean_metadata[k] = v
            meta_json = json.dumps(clean_metadata)
            await db.execute("""
                INSERT INTO task_steps (step_id, task_id, step_num, step_type, content, metadata_json, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (step_id, task_id, step_num, step_type, clean_content, meta_json, time.time()))
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
        """Save settings with OS-native encryption for sensitive API keys. Propagates write failures."""
        to_store = value
        if key == "app_settings" and isinstance(value, dict):
            to_store = dict(value)
            for k in ("openai_api_key", "anthropic_api_key", "gemini_api_key"):
                if k in to_store and to_store[k]:
                    to_store[k] = vault.encrypt(to_store[k])

        try:
            async with aiosqlite.connect(self.db_path) as db:
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL)
                """)
                await db.execute("""
                    INSERT INTO settings (key, value_json) VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json
                """, (key, json.dumps(to_store)))
                await db.commit()
        except Exception as e:
            raise DatabaseWriteError(f"Database write failure in save_setting('{key}'): {str(e)}") from e

    async def get_setting(self, key: str, default: Any = None) -> Any:
        """Get settings, decrypting OS-native encrypted credentials and migrating legacy formats."""
        try:
            async with aiosqlite.connect(self.db_path) as db:
                db.row_factory = aiosqlite.Row
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL)
                """)
                cursor = await db.execute("SELECT value_json FROM settings WHERE key = ?", (key,))
                row = await cursor.fetchone()
                if not row:
                    return default
                val = json.loads(row["value_json"])

                if key == "app_settings" and isinstance(val, dict):
                    decrypted_val = dict(val)
                    needs_migration = False
                    for k in ("openai_api_key", "anthropic_api_key", "gemini_api_key"):
                        raw = decrypted_val.get(k)
                        if raw and isinstance(raw, str):
                            decrypted = vault.decrypt(raw)
                            if decrypted is not None:
                                decrypted_val[k] = decrypted
                                # If stored in legacy scheme (enc: or b64:) or unencrypted, migrate to native vault immediately
                                if raw.startswith("enc:") or raw.startswith("b64:") or not (raw.startswith("dpapi:") or raw.startswith("fernet:")):
                                    needs_migration = True
                            else:
                                # Corrupted or non-decryptable vault key: do not return ciphertext as usable secret
                                decrypted_val[k] = None
                    if needs_migration:
                        try:
                            # Immediately re-encrypt with DPAPI and persist securely
                            await self.save_setting(key, decrypted_val)
                        except Exception as e:
                            # If migration fails, do NOT return unmigrated secret to caller
                            for k in ("openai_api_key", "anthropic_api_key", "gemini_api_key"):
                                raw_item = val.get(k)
                                if raw_item and (raw_item.startswith("enc:") or raw_item.startswith("b64:") or not (raw_item.startswith("dpapi:") or raw_item.startswith("fernet:"))):
                                    decrypted_val[k] = None
                            raise CredentialMigrationError(
                                f"Failed to securely migrate and persist legacy credential: {str(e)}"
                            ) from e
                    return decrypted_val

                return val
        except CredentialMigrationError:
            raise
        except Exception:
            await self.init()
            return default
