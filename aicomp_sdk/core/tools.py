import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PRIVATE_NET_RE = re.compile(
    r"(^|://)(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)", re.IGNORECASE
)


@dataclass
class ToolSpec:
    name: str
    side_effect: str  # READ|WRITE|EXEC|NETWORK|SHARE|AUTH
    scope: str  # public|internal|local|secrets|external
    schema: Dict[str, Any]


class ToolSuite:
    """Deterministic offline tool implementations backed by fixtures."""

    def __init__(self, fixtures_dir: Path):
        self.fixtures_dir = fixtures_dir
        self._web = json.loads((fixtures_dir / "web_corpus.json").read_text())
        self._mail_seed = json.loads((fixtures_dir / "mail_seed.json").read_text())
        self._mail = json.loads((fixtures_dir / "mail_seed.json").read_text())
        self._fs_root = fixtures_dir / "file_seed"
        self._fs_backup = {}  # Backup of original files
        self._egress_sink: List[Dict[str, Any]] = []
        self._last_source = "user"

        # Backup original file contents
        for fpath in self._fs_root.iterdir():
            if fpath.is_file():
                self._fs_backup[fpath.name] = fpath.read_text(encoding="utf-8")

        self.specs: Dict[str, ToolSpec] = {
            "web.search": ToolSpec(
                "web.search",
                "NETWORK",
                "public",
                {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                    "additionalProperties": False,
                },
            ),
            "web.open": ToolSpec(
                "web.open",
                "NETWORK",
                "public",
                {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
            ),
            "fs.read": ToolSpec(
                "fs.read",
                "READ",
                "local",
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            "fs.write": ToolSpec(
                "fs.write",
                "WRITE",
                "local",
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            ),
            "fs.delete": ToolSpec(
                "fs.delete",
                "WRITE",
                "local",
                {
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            "shell.run": ToolSpec(
                "shell.run",
                "EXEC",
                "local",
                {
                    "type": "object",
                    "properties": {"cmd": {"type": "string"}},
                    "required": ["cmd"],
                    "additionalProperties": False,
                },
            ),
            "email.list": ToolSpec(
                "email.list",
                "READ",
                "local",
                {
                    "type": "object",
                    "properties": {"folder": {"type": "string"}},
                    "required": ["folder"],
                    "additionalProperties": False,
                },
            ),
            "email.read": ToolSpec(
                "email.read",
                "READ",
                "local",
                {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
            ),
            "email.send": ToolSpec(
                "email.send",
                "SHARE",
                "external",
                {
                    "type": "object",
                    "properties": {
                        "to": {"type": "string"},
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["to", "subject", "body"],
                    "additionalProperties": False,
                },
            ),
            "http.post": ToolSpec(
                "http.post",
                "SHARE",
                "external",
                {
                    "type": "object",
                    "properties": {"url": {"type": "string"}, "data": {"type": "string"}},
                    "required": ["url", "data"],
                    "additionalProperties": False,
                },
            ),
        }

    def reset(self, seed: int):
        self._egress_sink = []
        self._last_source = "user"

        # Restore mail from seed
        self._mail = json.loads(json.dumps(self._mail_seed))

        # Delete any NEW files/directories created during the episode (not in backup)
        # Walk recursively and delete anything not in the original backup
        for fpath in self._fs_root.iterdir():
            if fpath.name not in self._fs_backup:
                if fpath.is_dir():
                    # Remove entire directory tree
                    shutil.rmtree(fpath)
                elif fpath.is_file():
                    # Remove individual file
                    fpath.unlink()

        # Restore files from backup
        for fname, content in self._fs_backup.items():
            fpath = self._fs_root / fname
            fpath.write_text(content, encoding="utf-8")

    def last_source(self) -> str:
        return self._last_source

    def validate(self, tool_name: str, args: Dict[str, Any]):
        if tool_name not in self.specs:
            raise ValueError(f"Unknown tool: {tool_name}")
        spec = self.specs[tool_name].schema
        # very small schema validator (Kaggle-safe): required keys + extra keys
        req = set(spec.get("required", []))
        props = set(spec.get("properties", {}).keys())
        if not req.issubset(args.keys()):
            missing = sorted(list(req - set(args.keys())))
            raise ValueError(f"Missing keys: {missing}")
        if spec.get("additionalProperties", True) is False:
            extra = sorted(list(set(args.keys()) - props))
            if extra:
                raise ValueError(f"Extra keys: {extra}")

    def call(self, tool_name: str, args: Dict[str, Any]) -> Tuple[bool, str, Optional[str]]:
        self.validate(tool_name, args)
        if tool_name == "web.search":
            self._last_source = "web"
            q = args["query"].lower()
            hits = []
            for p in self._web["pages"]:
                if q in p["title"].lower() or q in p["content"].lower():
                    hits.append({"id": p["id"], "title": p["title"]})
            # Sort by ID for stable ranking under corpus changes
            hits.sort(key=lambda x: x["id"])
            # Limit to top-k=10 results to prevent context bloat
            hits = hits[:10]
            # always return something deterministic (use first page)
            if not hits:
                hits = [{"id": "page_0", "title": "Welcome"}]
            return True, json.dumps({"results": hits}), None

        if tool_name == "web.open":
            self._last_source = "web"
            pid = args["id"]
            page = next((p for p in self._web["pages"] if p["id"] == pid), None)
            if page is None:
                return False, "", "not_found"
            return True, page["content"], None

        if tool_name == "fs.read":
            self._last_source = "file"
            path = (self._fs_root / args["path"].lstrip("/")).resolve()
            if not str(path).startswith(str(self._fs_root.resolve())):
                return False, "", "path_escape"
            if not path.exists():
                return False, "", "not_found"
            if path.is_dir():
                return False, "", "is_directory"
            return True, path.read_text(encoding="utf-8"), None

        if tool_name == "fs.write":
            self._last_source = "file"
            path = (self._fs_root / args["path"].lstrip("/")).resolve()
            if not str(path).startswith(str(self._fs_root.resolve())):
                return False, "", "path_escape"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(args["content"], encoding="utf-8")
            return True, "ok", None

        if tool_name == "fs.delete":
            self._last_source = "file"
            path = (self._fs_root / args["path"].lstrip("/")).resolve()
            if not str(path).startswith(str(self._fs_root.resolve())):
                return False, "", "path_escape"
            if path.exists():
                path.unlink()
                return True, "ok", None
            return False, "", "not_found"

        if tool_name == "shell.run":
            self._last_source = "tool"
            cmd = args["cmd"].strip()
            # simulated safe shell: only allow harmless commands
            allowed = ("echo ", "ls", "pwd", "whoami", "date")
            if not any(cmd == a or cmd.startswith(a) for a in allowed):
                return False, "", "cmd_not_allowed"
            if cmd.startswith("echo "):
                return True, cmd[5:], None
            if cmd == "ls":
                files = sorted([p.name for p in self._fs_root.iterdir() if p.is_file()])
                return True, "\n".join(files), None
            if cmd == "pwd":
                return True, str(self._fs_root), None
            if cmd == "whoami":
                return True, "sandbox", None
            if cmd == "date":
                return True, "1970-01-01", None
            return True, "ok", None

        if tool_name == "email.list":
            self._last_source = "email"
            folder = args["folder"]
            if folder not in self._mail:
                return False, "", "folder_not_found"
            # Return list of email summaries (id, from, subject)
            summaries = []
            for msg in self._mail[folder]:
                summaries.append({"id": msg["id"], "from": msg["from"], "subject": msg["subject"]})
            return True, json.dumps({"emails": summaries}), None

        if tool_name == "email.read":
            self._last_source = "email"
            mid = args["id"]
            # Search all folders, not just inbox
            msg = None
            for folder_msgs in self._mail.values():
                if isinstance(folder_msgs, list):
                    msg = next((m for m in folder_msgs if m["id"] == mid), None)
                    if msg is not None:
                        break
            if msg is None:
                return False, "", "not_found"
            return True, json.dumps(msg), None

        if tool_name == "email.send":
            self._last_source = "tool"
            # store locally only
            self._mail.setdefault("sent", []).append(args)
            return True, "sent", None

        if tool_name == "http.post":
            self._last_source = "tool"
            url = args["url"]
            if PRIVATE_NET_RE.search(url):
                return False, "", "private_net_blocked"
            self._egress_sink.append({"url": url, "data": args["data"]})
            return True, "ok", None

        return False, "", "unknown_tool"

    def get_egress(self) -> List[Dict[str, Any]]:
        return list(self._egress_sink)
