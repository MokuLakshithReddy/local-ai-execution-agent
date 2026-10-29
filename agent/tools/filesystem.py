"""
Filesystem tools: List, Read, Write, Patch, and Search files within workspace.
"""
import os
import re
import time
from typing import Any, Dict, List
from agent.tools.base import BaseTool
from agent.core.models import PermissionLevel, ActionResult

IGNORED_DIRS = {".git", "node_modules", "venv", "__pycache__", ".venv", ".idea", ".vscode", "dist", "build"}
MAX_READ_BYTES = 100_000  # 100 KB safety limit per read
MAX_LINE_CHARS = 10_000  # Max characters per line to guard against giant un-newline minified blobs
MAX_SCAN_BYTES = 5 * 1024 * 1024  # 5 MB maximum bytes scanned during slicing


def resolve_safe_path(workspace_path: str, sub_path: str) -> str:
    """Safely resolves and validates that a relative/absolute path and any symbolic links stay within the workspace."""
    if not sub_path:
        return os.path.realpath(workspace_path)
    
    workspace_real = os.path.realpath(workspace_path)
    
    # If path is absolute, check its canonical path; otherwise join to workspace
    if os.path.isabs(sub_path):
        candidate = os.path.abspath(sub_path)
    else:
        candidate = os.path.abspath(os.path.join(workspace_real, sub_path))

    # Resolve all symbolic links and junctions to their real canonical target
    if os.path.exists(candidate) or os.path.islink(candidate):
        resolved_real = os.path.realpath(candidate)
    else:
        # If candidate does not exist yet (e.g. creating new file), resolve nearest existing parent
        parent = os.path.dirname(candidate)
        while parent and not os.path.exists(parent) and parent != os.path.dirname(parent):
            parent = os.path.dirname(parent)
        real_parent = os.path.realpath(parent) if os.path.exists(parent) else parent
        rel_from_parent = os.path.relpath(candidate, parent)
        resolved_real = os.path.abspath(os.path.join(real_parent, rel_from_parent))

    # Check that canonical path is strictly contained within real workspace
    try:
        common = os.path.commonpath([resolved_real, workspace_real])
        if common != workspace_real:
            raise ValueError(f"Path traversal or symlink escape detected: '{sub_path}' resolves to '{resolved_real}', which is outside authorized workspace '{workspace_real}'")
    except Exception as e:
        raise ValueError(f"Security validation error: {str(e)}")
        
    return resolved_real


class ListDirTool(BaseTool):
    name = "list_dir"
    description = "List files and directories within a target path in the workspace."
    permission_level = PermissionLevel.READ_ONLY

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "relative_path": {
                    "type": "string",
                    "description": "Path relative to workspace root (defaults to root if empty).",
                    "default": "",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Whether to list subdirectories recursively (max depth 3).",
                    "default": False,
                },
            },
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "list_dir")
        rel_path = kwargs.get("relative_path", "")
        recursive = kwargs.get("recursive", False)

        try:
            target_dir = resolve_safe_path(workspace_path, rel_path)
            if not os.path.exists(target_dir):
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"Directory does not exist: {rel_path or '.'}",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            items = []
            if not recursive:
                for entry in sorted(os.listdir(target_dir)):
                    full_p = os.path.join(target_dir, entry)
                    is_d = os.path.isdir(full_p)
                    size = os.path.getsize(full_p) if not is_d else 0
                    items.append(f"{'[DIR] ' if is_d else '[FILE]'} {entry} ({size} bytes)" if not is_d else f"[DIR]  {entry}")
            else:
                for root, dirs, files in os.walk(target_dir):
                    dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
                    # Compute relative depth
                    rel = os.path.relpath(root, target_dir)
                    depth = 0 if rel == "." else rel.count(os.sep) + 1
                    if depth > 3:
                        dirs.clear()
                        continue
                    indent = "  " * depth
                    if rel != ".":
                        items.append(f"{indent}[DIR]  {os.path.basename(root)}/")
                    for f in files:
                        p = os.path.join(root, f)
                        items.append(f"{indent}  [FILE] {f} ({os.path.getsize(p)} bytes)")

            output_str = "\n".join(items) if items else "(empty directory)"
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=True,
                output=output_str,
                execution_time_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=str(e),
                execution_time_ms=(time.time() - t0) * 1000,
            )


class ReadFileTool(BaseTool):
    name = "read_file"
    description = "Read the text contents of a file within the workspace. Supports start_line and end_line slicing."
    permission_level = PermissionLevel.READ_ONLY

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to the workspace.",
                },
                "start_line": {
                    "type": "integer",
                    "description": "Optional 1-indexed starting line number.",
                    "default": 1,
                },
                "end_line": {
                    "type": "integer",
                    "description": "Optional 1-indexed ending line number.",
                    "default": 500,
                },
            },
            "required": ["file_path"],
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "read_file")
        file_path = kwargs.get("file_path", "")
        start_line = max(1, kwargs.get("start_line", 1))
        end_line = kwargs.get("end_line", 500)

        try:
            target_file = resolve_safe_path(workspace_path, file_path)
            if not os.path.isfile(target_file):
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"File not found: {file_path}",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            size = os.path.getsize(target_file)
            if size > 10 * 1024 * 1024 and (end_line - start_line) > 500:
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"File exceeds maximum read limit ({size} bytes > 10 MB). Specify a narrower start_line and end_line slice.",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            selected = []
            returned_bytes = 0
            scanned_bytes = 0
            truncated = False
            line_idx = 0

            # Bounded streaming reader: bounds lines, individual line lengths, and scanned bytes
            with open(target_file, "r", encoding="utf-8", errors="replace") as f:
                while True:
                    line_idx += 1
                    # Stop immediately once the requested range is complete
                    if line_idx > end_line:
                        line_idx -= 1
                        break

                    # Bound individual line memory using chunked readline
                    raw_chunk = f.readline(MAX_LINE_CHARS + 1)
                    if not raw_chunk:
                        # End of file reached
                        line_idx -= 1
                        break

                    scanned_bytes += len(raw_chunk.encode("utf-8", errors="replace"))

                    # If line exceeds MAX_LINE_CHARS, truncate line and drain remaining chars up to newline
                    if len(raw_chunk) > MAX_LINE_CHARS:
                        line = raw_chunk[:MAX_LINE_CHARS] + " ... [LINE TRUNCATED AT 10,000 CHARACTERS]\n"
                        # Drain until newline to keep line numbers accurate without storing
                        while True:
                            drain = f.readline(65536)
                            if not drain:
                                break
                            scanned_bytes += len(drain.encode("utf-8", errors="replace"))
                            if drain.endswith("\n"):
                                break
                    else:
                        line = raw_chunk

                    # Check overall scan budget
                    if scanned_bytes > MAX_SCAN_BYTES:
                        truncated = True
                        break

                    if line_idx < start_line:
                        continue

                    # Ensure line ends with newline for consistent formatting
                    if not line.endswith("\n"):
                        line = line + "\n"

                    formatted = f"{line_idx}: {line}"
                    f_bytes = len(formatted.encode("utf-8", errors="replace"))
                    if returned_bytes + f_bytes > MAX_READ_BYTES:
                        truncated = True
                        break

                    selected.append(formatted)
                    returned_bytes += f_bytes

            output_content = "".join(selected)
            if truncated:
                output_content += f"\n[OUTPUT TRUNCATED: Reached safety limit ({MAX_READ_BYTES} output bytes or {MAX_SCAN_BYTES} scan bytes). Specify narrower start_line and end_line]."

            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=True,
                output=output_content,
                artifacts={"scanned_lines": line_idx, "returned_lines": len(selected), "truncated": truncated},
                execution_time_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=str(e),
                execution_time_ms=(time.time() - t0) * 1000,
            )


class WriteFileTool(BaseTool):
    name = "write_file"
    description = "Create or overwrite a file in the workspace with new content."
    permission_level = PermissionLevel.ROUTINE_MODIFICATION

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to the workspace.",
                },
                "content": {
                    "type": "string",
                    "description": "Complete text content to write.",
                },
            },
            "required": ["file_path", "content"],
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "write_file")
        file_path = kwargs.get("file_path", "")
        content = kwargs.get("content", "")

        try:
            target_file = resolve_safe_path(workspace_path, file_path)
            os.makedirs(os.path.dirname(target_file), exist_ok=True)

            is_new = not os.path.exists(target_file)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(content)

            msg = f"Successfully {'created' if is_new else 'updated'} {file_path} ({len(content)} characters)."
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=True,
                output=msg,
                artifacts={"file_path": file_path, "is_new": is_new, "bytes_written": len(content.encode("utf-8"))},
                execution_time_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=str(e),
                execution_time_ms=(time.time() - t0) * 1000,
            )


class PatchFileTool(BaseTool):
    name = "patch_file"
    description = "Replace a specific unique target text block in an existing file with replacement text."
    permission_level = PermissionLevel.ROUTINE_MODIFICATION

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the file relative to the workspace.",
                },
                "target_content": {
                    "type": "string",
                    "description": "Exact text block to find and replace. Must match existing text character-for-character.",
                },
                "replacement_content": {
                    "type": "string",
                    "description": "New text to insert in place of target_content.",
                },
            },
            "required": ["file_path", "target_content", "replacement_content"],
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "patch_file")
        file_path = kwargs.get("file_path", "")
        target = kwargs.get("target_content", "")
        replacement = kwargs.get("replacement_content", "")

        try:
            target_file = resolve_safe_path(workspace_path, file_path)
            if not os.path.isfile(target_file):
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"File not found: {file_path}",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            with open(target_file, "r", encoding="utf-8") as f:
                content = f.read()

            count = content.count(target)
            if count == 0:
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error="Target content was not found in the file. Ensure whitespace and indentation match exactly.",
                    execution_time_ms=(time.time() - t0) * 1000,
                )
            if count > 1:
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"Target content matches {count} locations. Please include more surrounding context lines to make the match unique.",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            new_content = content.replace(target, replacement, 1)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(new_content)

            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=True,
                output=f"Successfully patched {file_path}.",
                artifacts={"file_path": file_path},
                execution_time_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=str(e),
                execution_time_ms=(time.time() - t0) * 1000,
            )


class SearchFilesTool(BaseTool):
    name = "search_files"
    description = "Search for a regex or text query across files in the workspace."
    permission_level = PermissionLevel.READ_ONLY

    def get_parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Regex or string query to search for.",
                },
                "file_extension": {
                    "type": "string",
                    "description": "Optional file extension filter, e.g. '.py' or '.ts'.",
                    "default": "",
                },
            },
            "required": ["query"],
        }

    async def execute(self, workspace_path: str, **kwargs) -> ActionResult:
        t0 = time.time()
        call_id = kwargs.get("call_id", "search_files")
        query = kwargs.get("query", "")
        ext = kwargs.get("file_extension", "")

        try:
            workspace_real = os.path.realpath(workspace_path)
            if not os.path.isdir(workspace_real):
                return ActionResult(
                    call_id=call_id,
                    tool_name=self.name,
                    success=False,
                    output="",
                    error=f"Workspace path does not exist: {workspace_path}",
                    execution_time_ms=(time.time() - t0) * 1000,
                )

            pattern = re.compile(query, re.IGNORECASE)
            matches = []
            max_matches = 50

            for root, dirs, files in os.walk(workspace_real, followlinks=False):
                # Filter directories: remove ignored dirs and any symlinks/out-of-workspace dirs
                safe_dirs = []
                for d in dirs:
                    if d in IGNORED_DIRS:
                        continue
                    d_path = os.path.join(root, d)
                    try:
                        # Reject symlink directories or directory escaping outside workspace
                        if os.path.islink(d_path):
                            continue
                        resolve_safe_path(workspace_real, d_path)
                        safe_dirs.append(d)
                    except Exception:
                        continue
                dirs[:] = safe_dirs

                for file in files:
                    if ext and not file.endswith(ext):
                        continue
                    full_p = os.path.join(root, file)
                    try:
                        # Validate that file resolves strictly within workspace and reject out-of-workspace symlinks
                        safe_file = resolve_safe_path(workspace_real, full_p)
                        if not os.path.isfile(safe_file):
                            continue
                    except Exception:
                        continue

                    rel_p = os.path.relpath(safe_file, workspace_real)
                    try:
                        with open(safe_file, "r", encoding="utf-8", errors="ignore") as f:
                            for idx, line in enumerate(f, start=1):
                                if pattern.search(line):
                                    matches.append(f"{rel_p}:{idx}: {line.strip()[:160]}")
                                    if len(matches) >= max_matches:
                                        break
                    except Exception:
                        continue
                if len(matches) >= max_matches:
                    break

            output = "\n".join(matches) if matches else "No matching files found."
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=True,
                output=output,
                artifacts={"match_count": len(matches)},
                execution_time_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ActionResult(
                call_id=call_id,
                tool_name=self.name,
                success=False,
                output="",
                error=str(e),
                execution_time_ms=(time.time() - t0) * 1000,
            )
