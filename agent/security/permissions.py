"""
Permission and safety evaluation system.
Independent from LLM; enforces boundaries, workspace restrictions, symlink containment, and approval gates.
"""
from typing import Dict, Any, Tuple, Optional
import os
import re
import shlex
import uuid
from agent.core.models import PermissionLevel, ApprovalRequest

# High-risk patterns that dynamically escalate terminal commands to DESTRUCTIVE_OPERATION
DESTRUCTIVE_COMMAND_REGEXES = [
    re.compile(r"\bgit\s+clean\b", re.IGNORECASE),
    re.compile(r"\bgit\s+reset\s+--hard\b", re.IGNORECASE),
    re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-rf|-fr)\b", re.IGNORECASE),
    re.compile(r"\brd\s+/[sS]\b", re.IGNORECASE),
    re.compile(r"\brmdir\s+/[sS]\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+(database|table)\b", re.IGNORECASE),
    re.compile(r"\btruncate\s+(table\s+)?", re.IGNORECASE),
    re.compile(r"\bmkfs\b", re.IGNORECASE),
    re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE),
    re.compile(r"\bRemove-Item\b", re.IGNORECASE),
    re.compile(r"\bClear-Item\b", re.IGNORECASE),
    re.compile(r"\bClear-Content\b", re.IGNORECASE),
    re.compile(r"\bClear-RecycleBin\b", re.IGNORECASE),
    re.compile(r"\bFormat-Volume\b", re.IGNORECASE),
    re.compile(r"\bStop-Process\b", re.IGNORECASE),
    re.compile(r"\b(?:ri|rmdir|rd|del|erase)\s+-[a-zA-Z]*(?:r|recurse)\b", re.IGNORECASE),
]

KNOWN_ROUTINE_EXECUTABLES = {
    "git", "git.exe", "pytest", "unittest", "npm", "npm.cmd", "npx", "npx.cmd",
    "yarn", "pnpm", "cargo", "cargo.exe", "go", "go.exe", "mypy", "ruff",
    "flake8", "eslint", "tsc", "python", "python.exe", "python3", "python3.exe",
    "py", "py.exe", "node", "node.exe", "ls", "dir", "cat", "type", "head",
    "tail", "wc", "grep", "findstr", "echo", "pwd", "cd", "which", "where",
    "get-childitem", "gci", "get-content", "gc", "get-location", "gl",
    "testclient"
}

PATH_ARGUMENT_KEYS = ("path", "target_path", "file_path", "relative_path")

# Dangerous Git long options mapped for abbreviation-aware security matching
DANGEROUS_GIT_OUTPUT_OPTIONS = ("--output",)
DANGEROUS_GIT_COMMIT_OPTIONS = ("--amend", "--fixup", "--squash", "--reset-author")
DANGEROUS_GIT_BRANCH_OPTIONS = ("--delete", "--delete-merged", "--force", "--move", "--copy")
DANGEROUS_GIT_TAG_OPTIONS = ("--delete", "--force")
DANGEROUS_GIT_CHECKOUT_OPTIONS = ("--force", "--merge", "--conflict", "--overwrite-ignore")
DANGEROUS_GIT_SWITCH_OPTIONS = ("--force", "--discard-changes")
DANGEROUS_GIT_PUSH_OPTIONS = ("--force", "--force-with-lease", "--force-if-includes", "--delete")
DANGEROUS_GIT_MERGE_OPTIONS = ("--abort", "--quit")
DANGEROUS_GIT_CHERRY_PICK_OPTIONS = ("--abort", "--quit")
DANGEROUS_GIT_UPDATE_REF_OPTIONS = ("--delete",)
DANGEROUS_GIT_GC_OPTIONS = ("--prune", "--force")
DANGEROUS_GIT_SUBMODULE_OPTIONS = ("--force",)
DANGEROUS_GIT_FSCK_OPTIONS = ("--lost-found", "--write-lost-found")


def is_git_option_abbreviation_or_match(arg: str, dangerous_long_options: Tuple[str, ...]) -> bool:
    """
    Checks if an argument starts with '--' and is an unambiguous or ambiguous prefix of any
    dangerous Git long option, replicating Git's option abbreviation resolution in parse-options.c.
    Treats any shortened long option that Git may resolve to a destructive option as destructive.
    """
    if not arg.startswith("--"):
        return False
    opt_name = arg.split("=", 1)[0].lower()
    if len(opt_name) < 3:  # Must be at least '--' + 1 character (e.g. '--d', '--f')
        return False
    return any(danger.startswith(opt_name) for danger in dangerous_long_options)


def classify_command_risk(cmd_str: str) -> Tuple[PermissionLevel, Optional[str]]:
    """
    Inspects a shell command string to classify if it performs destructive operations,
    using tokenization (shlex) and pattern heuristics to guard against flag evasion.
    """
    cmd = cmd_str.strip()
    if not cmd:
        return PermissionLevel.ROUTINE_MODIFICATION, None

    # 1. Check explicit destructive regexes
    for pattern in DESTRUCTIVE_COMMAND_REGEXES:
        if pattern.search(cmd):
            return (
                PermissionLevel.DESTRUCTIVE_OPERATION,
                f"High risk: Destructive terminal command ('{cmd[:60]}...') requires explicit human authorization.",
            )

    # 2. Tokenized analysis
    try:
        tokens = shlex.split(cmd, posix=False)
    except Exception:
        tokens = cmd.split()

    if not tokens:
        return PermissionLevel.ROUTINE_MODIFICATION, None

    # Check chained commands or pipelines separated by ; && || |
    subcommands = []
    current_sub = []
    for t in tokens:
        if t in (";", "&&", "||", "|", "&"):
            if current_sub:
                subcommands.append(current_sub)
                current_sub = []
        else:
            current_sub.append(t)
    if current_sub:
        subcommands.append(current_sub)

    for sub in subcommands:
        if not sub:
            continue
        idx = 0
        while idx < len(sub) and "=" in sub[idx] and not sub[idx].startswith("-"):
            idx += 1
        if idx >= len(sub):
            continue
        exe = os.path.basename(sub[idx]).lower().replace('"', '').replace("'", "")
        orig_args = [a.replace('"', '').replace("'", "") for a in sub[idx + 1:]]
        args = [a.lower() for a in orig_args]

        # A. git inspection: conservative Git subcommand and argument security policy
        if exe == "git" or exe.startswith("git."):
            # 0a. Escalate unresolved shell wildcards/globs, variable expansion, command substitution, or dynamic argument construction
            has_glob_wildcards = any(
                any(c in a for c in ("*", "?", "[", "]"))
                for a in orig_args
            )
            has_dynamic_args = any(
                bool(re.search(r"(\$|`|%[a-zA-Z0-9_]+%)", a))
                for a in orig_args
            )
            has_shell_assignments = any(
                any("=" in t and not t.startswith("-") for t in other_sub)
                for other_sub in subcommands
                if other_sub != sub
            )
            has_inline_assignment = (idx > 0)
            if has_glob_wildcards:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git command contains unresolved shell wildcard/glob pattern ('{cmd[:60]}...') which could expand to destructive flags at execution time and requires explicit human authorization.",
                )
            if has_dynamic_args or has_shell_assignments or has_inline_assignment:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git command contains unresolved shell variable expansion, command substitution, or dynamic argument construction ('{cmd[:60]}...') and requires explicit human authorization.",
                )

            # Parse git global options to locate the git subcommand
            subcmd = None
            subcmd_args = []
            orig_subcmd_args = []
            skip_next = False
            for i, a in enumerate(args):
                if skip_next:
                    skip_next = False
                    continue
                if a in ("-c", "-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix"):
                    skip_next = True
                    continue
                if a.startswith(("-c", "-C", "--git-dir=", "--work-tree=", "--namespace=")):
                    continue
                if a.startswith("-") and not subcmd:
                    continue
                if not subcmd:
                    subcmd = a
                    subcmd_args = args[i + 1:]
                    orig_subcmd_args = orig_args[i + 1:]
                    break

            # 0. Escalate any git command that specifies file output redirection/writing flags
            for a in orig_args:
                if (
                    a in ("--output", "-o")
                    or a.startswith(("--output=", "-o="))
                    or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_OUTPUT_OPTIONS)
                ):
                    return (
                        PermissionLevel.DESTRUCTIVE_OPERATION,
                        f"High risk: Git file output redirection ('{a}') writes directly to filesystem and requires explicit human authorization.",
                    )

            # 1. Explicit destructive git commands and dangerous option flags
            if "clean" in args:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git clean operation ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "restore" in args:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git restore operation ('{cmd[:60]}...') discards workspace changes and requires explicit human authorization.",
                )
            if "checkout" in args and (
                any(
                    a in ("--", ".", "-f", "--force", "-B")
                    or a.startswith(("-B",))
                    or (a.startswith("-") and not a.startswith("--") and "f" in a)
                    or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_CHECKOUT_OPTIONS)
                    for a in orig_args
                )
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git checkout overwriting working tree changes or resetting branches ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "reset" in args:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git reset operation ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "rm" in args:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git file removal ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "branch" in args and (
                any(
                    b in ("-d", "-D", "--delete", "-f", "--force", "-m", "-M", "--move", "-c", "-C", "--copy")
                    or b.startswith(("-f", "--force", "-m", "-M", "--move", "-c", "-C", "--copy"))
                    or (b.startswith("-") and not b.startswith("--") and any(ch in b for ch in ("d", "D", "f", "m", "M", "c", "C")))
                    or is_git_option_abbreviation_or_match(b, DANGEROUS_GIT_BRANCH_OPTIONS)
                    for b in orig_args
                )
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git branch force update, rename, or deletion ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "switch" in args and (
                any(
                    a in ("-f", "--force", "--discard-changes", "-C")
                    or a.startswith(("-C",))
                    or (a.startswith("-") and not a.startswith("--") and any(ch in a for ch in ("f", "C")))
                    or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_SWITCH_OPTIONS)
                    for a in orig_args
                )
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Forced git switch or branch reset ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "commit" in args and (
                any(
                    a in ("--amend", "--fixup", "--squash", "--reset-author")
                    or a.startswith(("--amend", "--fixup", "--squash", "--reset-author"))
                    or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_COMMIT_OPTIONS)
                    for a in orig_args
                )
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git commit history-rewriting operation ('{cmd[:60]}...') modifies repository commit history and requires explicit human authorization.",
                )
            if "stash" in args and any(a in args for a in ("drop", "clear", "pop")):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git stash destructive operation ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "rebase" in args:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git rebase operation ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "worktree" in args and any(a in ("remove", "prune") or a.startswith("remove") or a.startswith("prune") for a in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git worktree removal/pruning ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "reflog" in args and any(a in ("expire", "delete", "drop") or a.startswith("expire") or a.startswith("delete") or a.startswith("drop") for a in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git reflog expiration/deletion ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "update-ref" in args and any(
                a in ("-d", "--delete")
                or a.startswith("--delete")
                or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_UPDATE_REF_OPTIONS)
                for a in orig_args
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git update-ref deletion ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "tag" in args and (
                any(
                    a in ("-d", "--delete", "-f", "--force")
                    or a.startswith(("-f", "--force"))
                    or (a.startswith("-") and not a.startswith("--") and any(ch in a for ch in ("d", "f")))
                    or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_TAG_OPTIONS)
                    for a in orig_args
                )
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git tag force update or deletion ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "prune" in args:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git prune repository objects ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "push" in args:
                if any(
                    a in ("-f", "--force", "--force-with-lease", "--delete", "-d")
                    or a.startswith("--force")
                    or a.startswith("--delete")
                    or (a.startswith("-") and not a.startswith("--") and any(ch in a for ch in ("f", "d")))
                    or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_PUSH_OPTIONS)
                    or (a.startswith(":") and len(a) > 1)
                    or (a.startswith("+") and len(a) > 1)
                    for a in orig_args
                ):
                    return (
                        PermissionLevel.DESTRUCTIVE_OPERATION,
                        f"High risk: Git force push or remote branch deletion ('{cmd[:60]}...') requires explicit human authorization.",
                    )
            if "gc" in args and any(
                a in ("--prune", "--force")
                or a.startswith("--prune")
                or a.startswith("--force")
                or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_GC_OPTIONS)
                for a in orig_args
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git garbage collection with pruning ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if "submodule" in args:
                if any(
                    a in ("deinit", "absorbgitdirs")
                    or a.startswith("deinit")
                    or "--force" in orig_args
                    or "-f" in orig_args
                    or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_SUBMODULE_OPTIONS)
                    for a in orig_subcmd_args
                ):
                    return (
                        PermissionLevel.DESTRUCTIVE_OPERATION,
                        f"High risk: Git submodule deinitialization/removal ('{cmd[:60]}...') requires explicit human authorization.",
                    )
            if subcmd in ("filter-branch", "filter-repo"):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git repository rewrite operation ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if subcmd == "merge" and any(
                a in ("--abort", "--quit") or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_MERGE_OPTIONS)
                for a in orig_subcmd_args
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git merge abort operation ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if subcmd == "cherry-pick" and any(
                a in ("--abort", "--quit") or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_CHERRY_PICK_OPTIONS)
                for a in orig_subcmd_args
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git cherry-pick abort operation ('{cmd[:60]}...') requires explicit human authorization.",
                )
            if subcmd == "fsck" and any(
                a in ("--lost-found", "--write-lost-found")
                or a.startswith("--lost-found")
                or is_git_option_abbreviation_or_match(a, DANGEROUS_GIT_FSCK_OPTIONS)
                for a in orig_subcmd_args
            ):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git fsck with file generation ('--lost-found') writes dangling objects and requires explicit human authorization.",
                )

            # 2. Vetted read-only / safe inspection git subcommands
            GIT_READ_ONLY_SUBCMDS = {
                "status", "log", "diff", "show", "rev-parse", "describe", "merge-base",
                "cat-file", "check-ignore", "ls-files", "ls-remote", "ls-tree", "shortlog",
                "blame", "annotate", "var", "version", "whatchanged", "name-rev",
                "count-objects", "fsck"
            }
            if subcmd in GIT_READ_ONLY_SUBCMDS:
                return PermissionLevel.ROUTINE_MODIFICATION, None

            # 3. Vetted routine mutating git subcommands
            GIT_ROUTINE_MUTATION_SUBCMDS = {
                "add", "commit", "init", "fetch", "clone", "checkout", "switch",
                "branch", "tag", "stash", "merge", "cherry-pick", "pull"
            }
            if subcmd == "config":
                if any(a in ("--get", "--list", "-l", "--get-all", "--get-regexp") for a in subcmd_args):
                    return PermissionLevel.ROUTINE_MODIFICATION, None
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Git configuration modification ('{cmd[:60]}...') requires explicit human authorization.",
                )

            if subcmd == "remote":
                if any(a in ("rm", "remove", "prune") for a in subcmd_args):
                    return (
                        PermissionLevel.DESTRUCTIVE_OPERATION,
                        f"High risk: Git remote removal/pruning ('{cmd[:60]}...') requires explicit human authorization.",
                    )
                if any(a in ("-v", "show", "get-url") for a in subcmd_args) or not subcmd_args:
                    return PermissionLevel.ROUTINE_MODIFICATION, None

            # If subcommand is recognized routine and passed all destructive checks above
            if subcmd in GIT_ROUTINE_MUTATION_SUBCMDS:
                return PermissionLevel.ROUTINE_MODIFICATION, None

            # 4. Conservative Git policy: Any unrecognized or unvetted Git subcommand requires approval
            if subcmd is not None:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"Conservative policy: Unrecognized Git subcommand '{subcmd}' ('{cmd[:60]}...') requires explicit human authorization.",
                )
            elif not any(a in ("--version", "-v", "--help", "-h") for a in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"Conservative policy: Bare or unrecognized Git invocation ('{cmd[:60]}...') requires explicit human authorization.",
                )

        # Destructive file manipulation utilities
        if exe in ("dd", "truncate", "shred", "wipe"):
            return (
                PermissionLevel.DESTRUCTIVE_OPERATION,
                f"High risk: Destructive data operation '{exe}' ('{cmd[:60]}...') requires explicit human authorization.",
            )

        # B. rm inspection: -r, -rf, -fr, --recursive, -r -f
        if exe in ("rm", "unlink"):
            has_recursive = any(
                a in ("-r", "-rf", "-fr", "-R", "--recursive") or (a.startswith("-") and "r" in a and not a.startswith("--"))
                for a in args
            )
            has_force = any(
                a in ("-f", "-rf", "-fr", "--force") or (a.startswith("-") and "f" in a and not a.startswith("--"))
                for a in args
            )
            if has_recursive or has_force or exe == "unlink":
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Recursive/forced file removal ('{cmd[:60]}...') requires explicit human authorization.",
                )

        # C. find inspection: find ... -delete or find ... -exec rm
        if exe == "find":
            if "-delete" in args or any("rm" in a for a in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Destructive find operation ('{cmd[:60]}...') requires explicit human authorization.",
                )

        # D. Windows rd / rmdir / del / erase
        if exe in ("rd", "rmdir"):
            if any("/s" in a for a in args) or any("-s" in a for a in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Directory tree deletion ('{cmd[:60]}...') requires explicit human authorization.",
                )
        if exe in ("del", "erase"):
            if any(flag in args for flag in ("/s", "/f", "/q", "-s", "-f", "-q")):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: File deletion command ('{cmd[:60]}...') requires explicit human authorization.",
                )

        # E. PowerShell cmdlets and aliases
        if exe in (
            "remove-item", "ri", "clear-item", "cli", "clear-content", "clc",
            "clear-recyclebin", "format-volume", "format-disk", "stop-process", "spps"
        ):
            return (
                PermissionLevel.DESTRUCTIVE_OPERATION,
                f"High risk: Destructive PowerShell cmdlet '{exe}' ('{cmd[:60]}...') requires explicit human authorization.",
            )

        # F. Shell wrappers and encoded commands (powershell, pwsh, cmd, bash, sh)
        if exe in ("powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe", "bash", "sh"):
            # Check for encoded commands (e.g. powershell -EncodedCommand ...)
            if any(arg in ("-encodedcommand", "-enc", "-ec", "-e") for arg in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Encoded shell command execution ('{cmd[:60]}...') requires explicit human authorization.",
                )
            for i, arg in enumerate(args):
                if arg in ("-command", "-c", "/c") or arg.startswith("-command:") or arg.startswith("-c:"):
                    nested_cmd = " ".join(args[i + 1:])
                    if nested_cmd:
                        sub_lvl, sub_reason = classify_command_risk(nested_cmd)
                        if sub_lvl == PermissionLevel.DESTRUCTIVE_OPERATION:
                            return (
                                PermissionLevel.DESTRUCTIVE_OPERATION,
                                sub_reason or f"High risk: Destructive nested command ('{cmd[:60]}...') requires explicit human authorization.",
                            )
            # Running raw shell scripts: bash script.sh, sh script.sh
            non_flag_args = [a for a in args if not a.startswith("-")]
            if non_flag_args and not any(arg in ("-c", "-command", "/c") for arg in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Shell script execution ('{cmd[:60]}...') requires explicit human authorization.",
                )

        # G. Interpreter executions: python, node, ruby, perl, php
        # Treat arbitrary interpreter scripts and inline code as high risk by default.
        # Only allow explicit, recognized test/build/metadata commands as routine.
        if exe in ("python", "python.exe", "python3", "python3.exe", "py", "py.exe"):
            # 1. Inline python code: python -c "..."
            if any(a == "-c" or a.startswith("-c:") for a in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Arbitrary inline Python execution ('{cmd[:60]}...') requires explicit human authorization.",
                )
            # 2. Check routine test/build runner modules or version checks
            is_routine_python = False
            if not args or all(a in ("-v", "--version", "-h", "--help") for a in args):
                is_routine_python = True
            elif len(args) >= 2 and args[0] == "-m":
                mod_name = args[1].lower()
                if mod_name in ("pytest", "unittest", "mypy", "ruff", "flake8", "py_compile"):
                    is_routine_python = True
                elif mod_name == "pip" and len(args) >= 3 and args[2] in ("list", "show", "check"):
                    is_routine_python = True

            if not is_routine_python:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Arbitrary Python script or unvetted module execution ('{cmd[:60]}...') requires explicit human authorization.",
                )

        if exe in ("node", "node.exe"):
            # 1. Inline node code: node -e "..."
            if any(a in ("-e", "--eval") or a.startswith("-e:") for a in args):
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Arbitrary inline Node execution ('{cmd[:60]}...') requires explicit human authorization.",
                )
            is_routine_node = False
            if not args or all(a in ("-v", "--version", "-h", "--help") for a in args):
                is_routine_node = True
            elif args and args[0] in ("--test", "test"):
                is_routine_node = True

            if not is_routine_node:
                return (
                    PermissionLevel.DESTRUCTIVE_OPERATION,
                    f"High risk: Arbitrary Node script execution ('{cmd[:60]}...') requires explicit human authorization.",
                )

        if exe in ("ruby", "perl", "php"):
            return (
                PermissionLevel.DESTRUCTIVE_OPERATION,
                f"High risk: Interpreter script execution ('{cmd[:60]}...') requires explicit human authorization.",
            )

        # H. Conservative policy: Unknown or unrecognized executables require explicit authorization
        if exe not in KNOWN_ROUTINE_EXECUTABLES:
            return (
                PermissionLevel.DESTRUCTIVE_OPERATION,
                f"Conservative risk: Unrecognized executable '{exe}' ('{cmd[:60]}...') requires explicit human authorization.",
            )

    return PermissionLevel.ROUTINE_MODIFICATION, None


MAX_PENDING_APPROVALS = 200
MAX_APPROVAL_HISTORY = 500


class PermissionPolicy:
    def __init__(
        self,
        auto_approve_routine: bool = True,
        auto_approve_sensitive: bool = False,
        require_approval_destructive: bool = True,
        require_approval_external: bool = True,
    ):
        self.auto_approve_routine = auto_approve_routine
        self.auto_approve_sensitive = auto_approve_sensitive
        self.require_approval_destructive = require_approval_destructive
        self.require_approval_external = require_approval_external


class PermissionManager:
    def __init__(self, policy: PermissionPolicy = None):
        self.policy = policy or PermissionPolicy()
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        self.approval_history: Dict[str, ApprovalRequest] = {}
        self.approved_workspaces: set[str] = set()
        self._global_sequence_id: int = 0

    def approve_workspace(self, workspace_path: str):
        """Registers a workspace directory as explicitly approved."""
        real_p = os.path.realpath(workspace_path)
        self.approved_workspaces.add(real_p)

    def is_workspace_approved(self, workspace_path: str) -> bool:
        """Verifies whether the given workspace path is in the approved registry."""
        if not workspace_path:
            return False
        real_p = os.path.realpath(workspace_path)
        return real_p in self.approved_workspaces

    def evaluate_action(
        self,
        task_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        permission_level: PermissionLevel,
        workspace_path: str,
    ) -> Tuple[bool, str, ApprovalRequest | None]:
        """
        Evaluates whether an action can execute immediately or requires human approval.
        Returns: (is_allowed_immediately, reason, approval_request_if_pending)
        """
        # 1. Symlink-aware path safety check for filesystem-affecting tools
        for key in PATH_ARGUMENT_KEYS:
            if key in arguments and arguments[key]:
                path_arg = str(arguments[key]).strip()
                if not self._is_path_within_workspace(path_arg, workspace_path):
                    return (
                        False,
                        f"Forbidden: Path '{path_arg}' resolves outside authorized workspace '{workspace_path}'.",
                        None,
                    )

        # 2. Check permission level against policy with dynamic risk escalation for commands
        effective_level = permission_level
        destructive_reason = None
        if tool_name in ("run_command", "run_verification") and "command" in arguments:
            cmd_str = str(arguments.get("command", "")).strip()
            classified_lvl, risk_msg = classify_command_risk(cmd_str)
            if classified_lvl == PermissionLevel.DESTRUCTIVE_OPERATION:
                effective_level = PermissionLevel.DESTRUCTIVE_OPERATION
                destructive_reason = risk_msg

        if effective_level == PermissionLevel.READ_ONLY:
            return True, "Permitted: Read-only operation within workspace.", None

        if effective_level == PermissionLevel.ROUTINE_MODIFICATION:
            if self.policy.auto_approve_routine:
                return True, "Permitted: Routine modification within workspace.", None
            else:
                return self._create_approval_request(
                    task_id, tool_name, arguments, effective_level, "Routine modification requires review."
                )

        if effective_level == PermissionLevel.SENSITIVE_OPERATION:
            if self.policy.auto_approve_sensitive:
                return True, "Permitted: Sensitive operation enabled by policy.", None
            else:
                return self._create_approval_request(
                    task_id, tool_name, arguments, effective_level, "Sensitive action requires user authorization."
                )

        if effective_level == PermissionLevel.DESTRUCTIVE_OPERATION:
            if self.policy.require_approval_destructive:
                return self._create_approval_request(
                    task_id,
                    tool_name,
                    arguments,
                    effective_level,
                    destructive_reason or "High risk: Destructive action requires explicit approval.",
                )
            return True, "Permitted: Destructive action allowed by policy override.", None

        if effective_level == PermissionLevel.EXTERNAL_SIDE_EFFECT:
            if self.policy.require_approval_external:
                return self._create_approval_request(
                    task_id, tool_name, arguments, effective_level, "External side effect requires explicit approval."
                )
            return True, "Permitted: External side effect allowed by policy override.", None

        return False, "Unknown permission level: Denied by default.", None

    def _create_approval_request(
        self,
        task_id: str,
        tool_name: str,
        arguments: Dict[str, Any],
        permission_level: PermissionLevel,
        reason: str,
    ) -> Tuple[bool, str, ApprovalRequest]:
        # Bound pending approvals count to prevent memory leaks / exhaustion
        if len(self.pending_approvals) >= MAX_PENDING_APPROVALS:
            # Evict oldest pending approval as expired
            oldest_id = next(iter(self.pending_approvals))
            self.expire_approval(oldest_id)

        approval_id = str(uuid.uuid4())
        self._global_sequence_id += 1
        req = ApprovalRequest(
            approval_id=approval_id,
            task_id=task_id,
            tool_name=tool_name,
            arguments=arguments,
            permission_level=permission_level,
            reason=reason,
            status="PENDING",
            sequence_id=self._global_sequence_id,
        )
        self.pending_approvals[approval_id] = req
        return False, f"Pending User Approval: {reason}", req

    def _prune_history(self):
        """Enforces a FIFO retention limit on approval history."""
        while len(self.approval_history) > MAX_APPROVAL_HISTORY:
            oldest_key = next(iter(self.approval_history))
            self.approval_history.pop(oldest_key, None)

    def resolve_approval(self, approval_id: str, approved: bool) -> Tuple[ApprovalRequest | None, str]:
        """
        Resolves a pending approval request.
        Returns (approval_request, resolution_code) where resolution_code is:
        - "RESOLVED": successfully resolved now
        - "ALREADY_RESOLVED": approval ID was previously resolved
        - "NOT_FOUND": approval ID is unknown
        """
        if approval_id in self.approval_history:
            return self.approval_history[approval_id], "ALREADY_RESOLVED"

        if approval_id not in self.pending_approvals:
            return None, "NOT_FOUND"

        req = self.pending_approvals.pop(approval_id)
        req.status = "APPROVED" if approved else "REJECTED"
        import time
        req.resolved_at = time.time()
        self.approval_history[approval_id] = req
        self._prune_history()
        return req, "RESOLVED"

    def cancel_task_approvals(self, task_id: str) -> list[str]:
        """Prunes all pending approvals for a cancelled task and marks them CANCELLED in history."""
        cancelled_ids = []
        import time
        for aid, req in list(self.pending_approvals.items()):
            if req.task_id == task_id:
                self.pending_approvals.pop(aid, None)
                req.status = "CANCELLED"
                req.resolved_at = time.time()
                self.approval_history[aid] = req
                cancelled_ids.append(aid)
        self._prune_history()
        return cancelled_ids

    def expire_approval(self, approval_id: str) -> ApprovalRequest | None:
        """Expires a pending approval when its timeout has passed."""
        if approval_id not in self.pending_approvals:
            return None
        req = self.pending_approvals.pop(approval_id)
        req.status = "EXPIRED"
        import time
        req.resolved_at = time.time()
        self.approval_history[approval_id] = req
        self._prune_history()
        return req

    @staticmethod
    def _is_path_within_workspace(path: str, workspace_path: str) -> bool:
        if not path or not workspace_path:
            return False
        real_workspace = os.path.realpath(workspace_path)
        if os.path.isabs(path):
            candidate = os.path.abspath(path)
        else:
            candidate = os.path.abspath(os.path.join(real_workspace, path))

        # Check symlink dereference
        if os.path.exists(candidate) or os.path.islink(candidate):
            real_target = os.path.realpath(candidate)
        else:
            # For non-existent files to be created, inspect real parent directory
            parent = os.path.dirname(candidate)
            while parent and not os.path.exists(parent) and parent != os.path.dirname(parent):
                parent = os.path.dirname(parent)
            real_parent = os.path.realpath(parent) if os.path.exists(parent) else parent
            rel = os.path.relpath(candidate, parent)
            real_target = os.path.abspath(os.path.join(real_parent, rel))

        try:
            common = os.path.commonpath([real_target, real_workspace])
            return common == real_workspace
        except Exception:
            return False
