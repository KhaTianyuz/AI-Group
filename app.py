#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# AI Group Chat Studio (AI 协作群聊工作台)
# Copyright (C) 2025-2026 AI Group Chat Studio Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program (see LICENSE / LICENSE_AGPL-3.0.txt).
# If not, see <https://www.gnu.org/licenses/>.
"""
AI 协作群聊工作台 — Windows Python 本地服务端 (基于 Python 标准库启动核心服务，可选 pypdf/PyMuPDF 增强 PDF 解析)
========================================================================================
核心特性：
1. 零第三方强依赖：仅使用 Python 3 标准库（sqlite3, http.server, urllib.request, subprocess, tkinter, threading, zipfile, xml, secrets, hashlib），开箱即用。
2. 全量数据单一 SQLite 数据库持久化 (`ai_group_chat.sqlite`)：
   - 所有用户数据（包括免责协议签署状态 `disclaimer_accepted_v1`、AI 成员配置与密钥、群聊消息、私密思考日志、工具调用审计与全局设置）统一保存在单一 SQLite 数据库中，彻底摒弃浏览器 `localStorage` 缓存。
3. 多层本地安全防护机制（缓解 DNS Rebinding、CSRF、未授权工具调用与前端密钥暴露风险）：
   - 严格校验 `Host`、`Origin`、`Referer` 与 `Sec-Fetch-Site` 请求头，拦截一切非本机 (`127.0.0.1` / `localhost`) 或跨站请求，缓解 DNS Rebinding 攻击风险。
   - 每次启动自动生成 256-bit 高熵随机鉴权令牌 (`SERVER_SESSION_TOKEN`)，仅注入本机首屏 HTML，所有 `/api/*` 接口强制校验 `X-Session-Token` 请求头。
   - `GET /api/state` 接口对所有 API Key 执行脱敏保护（仅返回 `__STORED_IN_SQLITE__` 占位符与末尾掩码，不向前端明文暴露已保存的密钥；流式调用时由后端在内存内自动解析真实密钥）。
   - 后端强制执行免责协议签署校验与工具权限审批校验：未签署免责协议禁止调用模型或工具；当处于 `ask`（每次询问批准）模式时，`/api/tool/execute` 强制验证与当前工具名及参数哈希绑定的一次性批准票据 (`approval_ticket`)，绕过前端直接发包将被后端直接拒绝。
   - 移除 PowerShell `策略绕过` 参数，并内置高危系统敏感路径黑名单保护（拦截对 `.ssh`、`.gnupg`、`.aws`、系统启动目录、`System32` 等敏感路径的读写）。
4. 一口气全量读取与批量读取文件 (`read_local_file`)：
   - 原生内置 `.pdf` 论文与 `.docx` Word 文档全文提取，单次最高支持读取 500,000 字符完整全文，并支持 `file_paths` 数组一次性批量读取多个文件，彻底杜绝分段重复调用导致的 Token 爆炸。
5. AI 自主私密上下文隔离标志 (`share_with_other_ai` / `only_self_and_owner`)：
   - 工具调用结果与中间过程默认仅对该 AI 自己和群主可见，不污染其他 AI 的上下文窗口。
"""

import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import http.client
import urllib.request
import webbrowser
import xml.etree.ElementTree as ET
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ai_group_chat.sqlite"
HTML_PATH = BASE_DIR / "static" / "index.html"
DEFAULT_WORKSPACE = BASE_DIR / "workspace"

# 每次服务端启动生成的 256-bit 会话令牌，用于所有 /api/* 请求鉴权
SERVER_SESSION_TOKEN = secrets.token_urlsafe(32)
SERVER_BOUND_PORT = 18765

# 一次性工具审批票据池: ticket_id -> {"sig": str, "expires_at": float}
APPROVAL_TICKETS: dict[str, dict] = {}
TICKET_LOCK = threading.Lock()

# 活跃的流式请求中断标志表: task_id -> threading.Event
ACTIVE_STREAM_ABORTS: dict[str, threading.Event] = {}
ABORT_LOCK = threading.Lock()

STORED_KEY_PLACEHOLDER = "__STORED_IN_SQLITE__"


def mask_api_key_preview(raw_key: str) -> str:
    if not raw_key or not raw_key.strip():
        return ""
    k = raw_key.strip()
    if len(k) <= 8:
        return "••••"
    return f"{k[:3]}••••{k[-4:]}"


def compute_tool_args_signature(tool_name: str, args: dict) -> str:
    canonical = json.dumps({"tool": tool_name, "args": args or {}}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def issue_one_time_approval_ticket(tool_name: str, args: dict) -> str:
    sig = compute_tool_args_signature(tool_name, args)
    ticket_id = secrets.token_urlsafe(24)
    now = time.time()
    with TICKET_LOCK:
        expired = [k for k, v in APPROVAL_TICKETS.items() if v["expires_at"] < now]
        for k in expired:
            APPROVAL_TICKETS.pop(k, None)
        APPROVAL_TICKETS[ticket_id] = {
            "sig": sig,
            "expires_at": now + 300.0,
        }
    return ticket_id


def consume_one_time_approval_ticket(ticket_id: str, tool_name: str, args: dict) -> bool:
    if not ticket_id:
        return False
    sig = compute_tool_args_signature(tool_name, args)
    now = time.time()
    with TICKET_LOCK:
        info = APPROVAL_TICKETS.pop(ticket_id, None)
        if not info:
            return False
        if info["expires_at"] < now:
            return False
        return secrets.compare_digest(info["sig"], sig)


def is_high_risk_system_path(target_path: Path) -> tuple[bool, str]:
    """检查目标路径是否命中系统高危敏感目录黑名单（如 .ssh、启动文件夹、System32 等）"""
    norm = str(target_path).replace("/", "\\").lower()
    sensitive_markers = [
        ("\\.ssh\\", "SSH 密钥目录 (.ssh)"),
        ("\\.gnupg\\", "GPG 密钥目录 (.gnupg)"),
        ("\\.aws\\", "AWS 凭证目录 (.aws)"),
        ("\\.kube\\", "Kubernetes 凭证目录 (.kube)"),
        ("\\microsoft\\windows\\start menu\\programs\\startup", "Windows 开机自启动目录 (Startup)"),
        ("\\windows\\system32", "Windows 系统核心目录 (System32)"),
        ("\\windows\\syswow64", "Windows 系统目录 (SysWOW64)"),
        ("\\etc\\shadow", "系统密码文件 (/etc/shadow)"),
        ("\\etc\\passwd", "系统账户文件 (/etc/passwd)"),
    ]
    for marker, desc in sensitive_markers:
        if marker in norm or norm.endswith(marker.rstrip("\\")):
            return True, desc
    if target_path.name.lower() in ("id_rsa", "id_ed25519", "authorized_keys", "known_hosts"):
        return True, f"SSH 敏感密钥文件 ({target_path.name})"
    return False, ""


def build_default_system_prompt(name: str, role_desc: str) -> str:
    return (
        f"你是群里的 {name}（{role_desc}）。\n\n"
        "【群聊协作与严格 @ 规则】：\n"
        f"1. 你当前在一个多 AI 协作群中，你的群昵称是 @{name}。群里的历史消息均带有发言人前缀（包括群主和其他 AI 的公开回复），请结合完整上下文回答。\n"
        "2. 当你只是向群主汇报结果、回答问题，或者你的多步工具操作尚未全部完成时，**严禁在回复中写出 @其他AI昵称**（普通提及对方名字时不要加 @ 符号），以免误唤醒其他 AI。\n"
        "3. 只有当你自己的全部文件读写/代码生成工作已彻底完成，且明确需要某个 AI 修改东西、审查代码或接手下一步工作时，才在最终回复中明确写出 @对方昵称（若属阻塞性紧急问题可写 @对方昵称 [紧急]）。\n\n"
        "【AI 自主上下文可见性控制（避免无用上下文污染其他 AI）】：\n"
        "- 你调用本地工具读取的文件原文、目录列表和终端输出，系统默认设为 `share_with_other_ai=false`（**仅你自己和群主可见**，不会塞入其他 AI 的上下文）。如果你确需把某次工具结果共享给全群 AI，可在工具参数中传 `share_with_other_ai=true`。\n"
        "- 在普通文字回复中，如果某段内容仅需群主和你自己知晓（无需传递给其他 AI），你可以在消息开头加上 `[仅自己和群主可见]`（整条隔离，且不会触发对其他 AI 的 @ 唤醒），或使用 `<private>仅自己和群主可见的细节</private>` 包裹对应段落，系统在组装其他 AI 的上下文及解析 @ 唤醒时会自动剔除这些私密内容。\n\n"
        "【本地文件与 PowerShell / CMD 终端工具使用说明（一口气全量读取 + 多步 ReAct 闭环）】：\n"
        "- `read_local_file(file_path, file_paths, share_with_other_ai)`：**一次性全量读取本地文件完整内容**（单次最高支持 50 万字符，已原生内置 `.pdf` 论文全文提取与 `.docx` Word 文档提取，并支持通过 `file_paths` 数组一次批量读完多个文件）。**严禁使用脚本或分段参数多次切片读取同一个文件**，请直接调用一次 `read_local_file` 即可一口气读完全文，节省 Token！\n"
        "- `write_local_file(file_path, content, share_with_other_ai)`：创建或覆盖写入本地代码/文档文件（自动创建父文件夹）。\n"
        "- `list_local_directory(dir_path, share_with_other_ai)`：列出指定目录中的文件与子文件夹。\n"
        "- `run_powershell_command(command, cwd, share_with_other_ai)`：使用 Windows PowerShell 执行命令并读取标准输出/错误输出。\n"
        "- `run_cmd_command(command, cwd, share_with_other_ai)`：使用 Windows `cmd.exe /c` 执行命令并读取输出。\n"
        "- `ask_other_ai(target_ai, message, is_urgent)`：当你完成自身任务后，调用工具向群内其他 AI 发起协作请求。\n"
        "（提示：每次你调用本地工具后，系统会自动执行并将结果立即回传给你，你可以连续多步调用工具把任务彻底做完，不要只查完目录就停下！若你所处的 API 网关不支持原生工具字段，也可直接在正文中输出 `<tool_call>{\"name\": \"read_local_file\", \"args\": {\"file_path\": \"...\"}}</tool_call>`。）"
    )


def normalize_alternating_messages(raw_messages: list, user_role: str = "user", assistant_role: str = "assistant") -> list:
    """
    针对 Anthropic (/v1/messages) 与 Google Gemini (streamGenerateContent) 等对连续相同角色敏感的协议，
    自动合并连续同角色的非 system 消息，并确保首条消息为 user 角色。
    """
    normalized = []
    for m in raw_messages:
        if m.get("role") == "system":
            continue
        role = assistant_role if m.get("role") in ("assistant", "model") else user_role
        content = str(m.get("content") or "").strip()
        if not content:
            continue
        if normalized and normalized[-1]["role"] == role:
            normalized[-1]["content"] += f"\n\n{content}"
        else:
            normalized.append({"role": role, "content": content})

    if normalized and normalized[0]["role"] != user_role:
        normalized.insert(0, {"role": user_role, "content": "[群聊历史上下文开始]"})
    elif not normalized:
        normalized.append({"role": user_role, "content": "请继续。"})
    return normalized


# ============================================================================
# 1. SQLite 本地数据库层 (Python 标准库 sqlite3，全量状态唯一持久化源)
# ============================================================================
class LocalSQLiteDB:
    def __init__(self, db_path: Path):
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        DEFAULT_WORKSPACE.mkdir(parents=True, exist_ok=True)
        self._init_starter_workspace_files()
        try:
            self._init_schema()
        except sqlite3.OperationalError:
            import tempfile
            fallback_dir = Path(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()) / "AIGroupChatStudio"
            fallback_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = str(fallback_dir / "ai_group_chat.sqlite")
            self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=5000;")
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        except sqlite3.OperationalError:
            try:
                conn.execute("PRAGMA journal_mode=MEMORY;")
            except sqlite3.OperationalError:
                pass
        return conn

    def _init_starter_workspace_files(self):
        schema_file = DEFAULT_WORKSPACE / "src" / "schema.sql"
        if not schema_file.exists():
            schema_file.parent.mkdir(parents=True, exist_ok=True)
            schema_file.write_text(
                "-- 核心任务表结构\nCREATE TABLE tasks (\n  id TEXT PRIMARY KEY,\n  title TEXT NOT NULL,\n  status TEXT DEFAULT 'pending'\n);\n",
                encoding="utf-8",
            )
        sync_file = DEFAULT_WORKSPACE / "src" / "sync_service.ts"
        if not sync_file.exists():
            sync_file.write_text(
                "export async function syncTasksToLocalDB(tasks: any[]) {\n  // 等待各 AI 节点对齐字段规范\n  return { synced: tasks.length, timestamp: Date.now() };\n}\n",
                encoding="utf-8",
            )

    def _init_schema(self):
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS agents (
                  id TEXT PRIMARY KEY,
                  name TEXT NOT NULL,
                  handle TEXT NOT NULL,
                  provider TEXT NOT NULL,
                  base_url TEXT NOT NULL,
                  api_key TEXT DEFAULT '',
                  model TEXT NOT NULL,
                  system_prompt TEXT DEFAULT '',
                  supports_reasoning INTEGER DEFAULT 1,
                  reasoning_effort TEXT DEFAULT 'high',
                  avatar_color TEXT DEFAULT '#3b82f6',
                  role_badge TEXT DEFAULT '通用助手',
                  enabled INTEGER DEFAULT 1,
                  sort_order INTEGER DEFAULT 0,
                  created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS messages (
                  id TEXT PRIMARY KEY,
                  sender_type TEXT NOT NULL,
                  sender_id TEXT NOT NULL,
                  sender_name TEXT NOT NULL,
                  content TEXT NOT NULL,
                  mentions_json TEXT DEFAULT '[]',
                  reply_to_id TEXT DEFAULT NULL,
                  task_id TEXT DEFAULT NULL,
                  audit_id TEXT DEFAULT NULL,
                  turn_depth INTEGER DEFAULT 0,
                  is_urgent INTEGER DEFAULT 0,
                  only_self_and_owner INTEGER DEFAULT 0,
                  is_tool_step_log INTEGER DEFAULT 0,
                  tool_summary TEXT DEFAULT NULL,
                  protocol_badge TEXT DEFAULT NULL,
                  created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reasoning_logs (
                  id TEXT PRIMARY KEY,
                  task_id TEXT NOT NULL,
                  agent_id TEXT NOT NULL,
                  agent_name TEXT NOT NULL,
                  task_prompt TEXT NOT NULL,
                  reasoning_text TEXT DEFAULT '',
                  status TEXT NOT NULL,
                  started_at INTEGER NOT NULL,
                  updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS task_queue (
                  id TEXT PRIMARY KEY,
                  agent_id TEXT NOT NULL,
                  source_type TEXT NOT NULL,
                  source_name TEXT NOT NULL,
                  prompt TEXT NOT NULL,
                  context_json TEXT DEFAULT '{}',
                  turn_depth INTEGER DEFAULT 0,
                  is_urgent INTEGER DEFAULT 0,
                  status TEXT NOT NULL,
                  partial_reasoning TEXT DEFAULT '',
                  partial_output TEXT DEFAULT '',
                  created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tool_audit_logs (
                  id TEXT PRIMARY KEY,
                  task_id TEXT NOT NULL,
                  agent_id TEXT NOT NULL,
                  agent_name TEXT NOT NULL,
                  tool_name TEXT NOT NULL,
                  args_json TEXT NOT NULL,
                  permission_mode TEXT NOT NULL,
                  approved_by_user INTEGER DEFAULT 1,
                  status TEXT DEFAULT 'completed',
                  step_num INTEGER DEFAULT 1,
                  duration_ms INTEGER DEFAULT 0,
                  exit_code INTEGER DEFAULT 0,
                  resolved_path TEXT DEFAULT '',
                  result_text TEXT DEFAULT '',
                  created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS settings (
                  key TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                """
            )
            for col_sql in (
                "ALTER TABLE agents ADD COLUMN wire_api TEXT DEFAULT 'chat_completions'",
                "ALTER TABLE agents ADD COLUMN disable_response_storage INTEGER DEFAULT 0",
                "ALTER TABLE agents ADD COLUMN enable_tools INTEGER DEFAULT 1",
                "ALTER TABLE agents ADD COLUMN custom_provider_name TEXT DEFAULT ''",
                "ALTER TABLE agents ADD COLUMN sort_order INTEGER DEFAULT 0",
                "ALTER TABLE messages ADD COLUMN only_self_and_owner INTEGER DEFAULT 0",
                "ALTER TABLE messages ADD COLUMN audit_id TEXT DEFAULT NULL",
                "ALTER TABLE messages ADD COLUMN is_tool_step_log INTEGER DEFAULT 0",
                "ALTER TABLE tool_audit_logs ADD COLUMN status TEXT DEFAULT 'completed'",
                "ALTER TABLE tool_audit_logs ADD COLUMN step_num INTEGER DEFAULT 1",
                "ALTER TABLE tool_audit_logs ADD COLUMN duration_ms INTEGER DEFAULT 0",
                "ALTER TABLE tool_audit_logs ADD COLUMN exit_code INTEGER DEFAULT 0",
                "ALTER TABLE tool_audit_logs ADD COLUMN resolved_path TEXT DEFAULT ''",
            ):
                try:
                    conn.execute(col_sql)
                except sqlite3.OperationalError:
                    pass
            # 清理可能意外残留的流式占位消息
            conn.execute("DELETE FROM messages WHERE id LIKE 'msg_live_%'")
            seeded_row = conn.execute("SELECT value FROM settings WHERE key = 'db_seeded'").fetchone()
            if not seeded_row:
                cur = conn.execute("SELECT COUNT(*) AS cnt FROM agents")
                if cur.fetchone()["cnt"] == 0:
                    self._seed_defaults(conn)
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('db_seeded', 'true')")

    def _seed_defaults(self, conn: sqlite3.Connection):
        now = int(time.time() * 1000)
        default_agents = [
            (
                "agent_gemini",
                "Gemini",
                "@Gemini",
                "gemini",
                "https://generativelanguage.googleapis.com/v1beta",
                "",
                "gemini-2.5-pro",
                build_default_system_prompt("Gemini", "架构师与多模态检索专家，擅长系统架构设计、目录规划与全局分析"),
                1,
                "high",
                "#2563eb",
                "架构与检索专家",
                1,
                0,
                now,
                "chat_completions",
                0,
                1,
                "Gemini",
            ),
            (
                "agent_codex",
                "Codex",
                "@Codex",
                "responses",
                "https://api.openai.com/v1",
                "",
                "gpt-4.1",
                build_default_system_prompt("Codex", "核心代码工程与终端自动化专家，擅长直接读写本地文件、执行 PowerShell/CMD 命令与编写高质量代码"),
                1,
                "high",
                "#10b981",
                "代码与终端工程",
                1,
                1,
                now + 1,
                "responses",
                1,
                1,
                "OpenAI-Responses",
            ),
            (
                "agent_claude",
                "Claude",
                "@Claude",
                "anthropic",
                "https://api.anthropic.com/v1",
                "",
                "claude-3-7-sonnet-20250219",
                build_default_system_prompt("Claude", "代码审查、前端交互与文档精修专家，擅长发现边界 Bug、验证本地文件与重构代码"),
                1,
                "high",
                "#d97706",
                "代码审查与重构",
                1,
                2,
                now + 2,
                "chat_completions",
                0,
                1,
                "Anthropic",
            ),
            (
                "agent_gpt4o",
                "GPT-4o",
                "@GPT-4o",
                "custom_openai",
                "https://api.openai.com/v1",
                "",
                "gpt-4o",
                build_default_system_prompt("GPT-4o", "快速响应通用模型（不支持原生思考链的普通模型示例，严格不返回思考过程）"),
                0,
                "none",
                "#8b5cf6",
                "普通非推理模型",
                1,
                3,
                now + 3,
                "chat_completions",
                0,
                1,
                "OpenAI",
            ),
        ]
        conn.executemany(
            """
            INSERT INTO agents (
              id, name, handle, provider, base_url, api_key, model,
              system_prompt, supports_reasoning, reasoning_effort, avatar_color, role_badge, enabled, sort_order, created_at,
              wire_api, disable_response_storage, enable_tools, custom_provider_name
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            default_agents,
        )
        default_settings = {
            "max_ai_turns": "4",
            "max_tool_steps": "15",
            "workspace_dir": str(DEFAULT_WORKSPACE),
            "fs_permission_mode": "ask",
            "cmd_permission_mode": "ask",
            "auto_resume_suspended": "true",
            "sequential_mode": "true",
            "disclaimer_accepted_v1": "false",
        }
        for k, v in default_settings.items():
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (k, v))

    def get_raw_api_key(self, agent_id: str) -> str:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT api_key FROM agents WHERE id = ?", (str(agent_id),)).fetchone()
            return (row["api_key"] or "").strip() if row else ""

    def get_setting(self, key: str, default: str = "") -> str:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (str(key),)).fetchone()
            return str(row["value"]) if row else default

    def get_all_state(self, mask_keys: bool = True) -> dict:
        with self._lock, self._connect() as conn:
            agents = [
                dict(r)
                for r in conn.execute("SELECT * FROM agents ORDER BY sort_order ASC, created_at ASC").fetchall()
            ]
            for a in agents:
                raw_k = (a.get("api_key") or "").strip()
                a["has_api_key"] = bool(raw_k)
                a["api_key_masked"] = mask_api_key_preview(raw_k)
                if mask_keys and raw_k:
                    a["api_key"] = STORED_KEY_PLACEHOLDER

            messages = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM (SELECT * FROM messages WHERE id NOT LIKE 'msg_live_%' ORDER BY created_at DESC LIMIT 1000) ORDER BY created_at ASC"
                ).fetchall()
            ]
            for m in messages:
                try:
                    m["mentions"] = json.loads(m.get("mentions_json") or "[]")
                except Exception:
                    m["mentions"] = []
                m["only_self_and_owner"] = bool(m.get("only_self_and_owner"))
                m["is_tool_step_log"] = bool(m.get("is_tool_step_log"))
            reasoning_logs = [
                dict(r)
                for r in conn.execute("SELECT * FROM reasoning_logs ORDER BY started_at DESC LIMIT 100").fetchall()
            ]
            tool_audits = [
                dict(r)
                for r in conn.execute("SELECT * FROM tool_audit_logs ORDER BY created_at DESC LIMIT 150").fetchall()
            ]
            for a in tool_audits:
                try:
                    a["args"] = json.loads(a.get("args_json") or "{}")
                except Exception:
                    a["args"] = a.get("args_json") or {}
                a["approved_by_user"] = bool(a.get("approved_by_user", 1))
            settings_rows = conn.execute("SELECT key, value FROM settings").fetchall()
            settings = {r["key"]: r["value"] for r in settings_rows}

            ws_dir = Path(os.path.expandvars(os.path.expanduser(settings.get("workspace_dir") or str(DEFAULT_WORKSPACE))))
            workspace_files = {}
            if ws_dir.exists() and ws_dir.is_dir():
                try:
                    for p in ws_dir.rglob("*"):
                        if p.is_file() and p.stat().st_size < 100_000:
                            rel = p.relative_to(ws_dir).as_posix()
                            try:
                                workspace_files[rel] = p.read_text(encoding="utf-8")
                            except Exception:
                                pass
                except Exception:
                    pass

            return {
                "agents": agents,
                "messages": messages,
                "reasoningLogs": reasoning_logs,
                "toolAudits": tool_audits,
                "settings": settings,
                "workspaceFiles": workspace_files,
            }

    def save_agent(self, agent: dict) -> dict:
        now = int(time.time() * 1000)
        aid = str(agent.get("id") or f"agent_{now}")
        incoming_key = str(agent.get("api_key") or "").strip()
        if incoming_key == STORED_KEY_PLACEHOLDER:
            incoming_key = self.get_raw_api_key(aid)

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO agents (
                  id, name, handle, provider, base_url, api_key, model,
                  system_prompt, supports_reasoning, reasoning_effort, avatar_color, role_badge, enabled, sort_order, created_at,
                  wire_api, disable_response_storage, enable_tools, custom_provider_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    aid,
                    agent.get("name"),
                    agent.get("handle") or f"@{agent.get('name')}",
                    agent.get("provider") or "openai",
                    agent.get("base_url") or "",
                    incoming_key,
                    agent.get("model") or "",
                    agent.get("system_prompt") or "",
                    1 if agent.get("supports_reasoning") else 0,
                    agent.get("reasoning_effort") or "high",
                    agent.get("avatar_color") or "#2563eb",
                    agent.get("role_badge") or "AI 助手",
                    1 if agent.get("enabled", True) else 0,
                    int(agent.get("sort_order", 0)),
                    agent.get("created_at") or now,
                    agent.get("wire_api") or "chat_completions",
                    1 if agent.get("disable_response_storage") else 0,
                    1 if agent.get("enable_tools", True) else 0,
                    agent.get("custom_provider_name") or "",
                ),
            )
        return {"ok": True, "has_api_key": bool(incoming_key), "api_key_masked": mask_api_key_preview(incoming_key)}

    def reorder_agents(self, ordered_ids: list) -> dict:
        with self._lock, self._connect() as conn:
            for idx, agent_id in enumerate(ordered_ids):
                conn.execute("UPDATE agents SET sort_order = ? WHERE id = ?", (idx, str(agent_id)))
        return {"ok": True}

    def replace_all_config(self, agents_list: list, settings_dict: dict | None = None) -> dict:
        now = int(time.time() * 1000)
        existing_keys = {}
        with self._lock, self._connect() as conn:
            for r in conn.execute("SELECT id, api_key FROM agents").fetchall():
                existing_keys[r["id"]] = r["api_key"] or ""
            conn.execute("DELETE FROM agents")
            for idx, agent in enumerate(agents_list or []):
                aid = agent.get("id") or f"agent_{now}_{idx}"
                name = (agent.get("name") or f"AI_{idx+1}").strip().lstrip("@")
                raw_k = str(agent.get("api_key") or "").strip()
                if raw_k == STORED_KEY_PLACEHOLDER:
                    raw_k = existing_keys.get(aid, "")
                conn.execute(
                    """
                    INSERT INTO agents (
                      id, name, handle, provider, base_url, api_key, model,
                      system_prompt, supports_reasoning, reasoning_effort, avatar_color, role_badge, enabled, sort_order, created_at,
                      wire_api, disable_response_storage, enable_tools, custom_provider_name
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        aid,
                        name,
                        agent.get("handle") or f"@{name}",
                        agent.get("provider") or "openai",
                        agent.get("base_url") or "",
                        raw_k,
                        agent.get("model") or "",
                        agent.get("system_prompt") or "",
                        1 if agent.get("supports_reasoning") else 0,
                        agent.get("reasoning_effort") or "high",
                        agent.get("avatar_color") or "#2563eb",
                        agent.get("role_badge") or "AI 助手",
                        1 if agent.get("enabled", True) else 0,
                        int(agent.get("sort_order", idx)),
                        int(agent.get("created_at") or (now + idx)),
                        agent.get("wire_api") or ("responses" if agent.get("provider") == "responses" else "chat_completions"),
                        1 if agent.get("disable_response_storage") else 0,
                        1 if agent.get("enable_tools", True) else 0,
                        agent.get("custom_provider_name") or "",
                    ),
                )
            if isinstance(settings_dict, dict):
                for k, v in settings_dict.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                        (str(k), "true" if v is True else ("false" if v is False else str(v))),
                    )
            conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('db_seeded', 'true')")
        return {"ok": True}

    def delete_agent(self, agent_id: str) -> dict:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
            conn.execute("DELETE FROM reasoning_logs WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM task_queue WHERE agent_id = ?", (agent_id,))
            conn.execute("DELETE FROM tool_audit_logs WHERE agent_id = ?", (agent_id,))
        return {"ok": True}

    def save_message(self, msg: dict) -> dict:
        msg_id = str(msg.get("id") or "")
        if msg_id.startswith("msg_live_"):
            return {"ok": True, "skipped_live": True}
        now = int(time.time() * 1000)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO messages (
                  id, sender_type, sender_id, sender_name, content,
                  mentions_json, reply_to_id, task_id, audit_id, turn_depth, is_urgent, only_self_and_owner, is_tool_step_log,
                  tool_summary, protocol_badge, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg_id or f"msg_{now}",
                    msg.get("sender_type") or "user",
                    msg.get("sender_id") or "user",
                    msg.get("sender_name") or "用户",
                    msg.get("content") or "",
                    json.dumps(msg.get("mentions") or [], ensure_ascii=False),
                    msg.get("reply_to_id"),
                    msg.get("task_id"),
                    msg.get("audit_id"),
                    int(msg.get("turn_depth") or 0),
                    1 if msg.get("is_urgent") else 0,
                    1 if msg.get("only_self_and_owner") else 0,
                    1 if msg.get("is_tool_step_log") else 0,
                    msg.get("tool_summary"),
                    msg.get("protocol_badge"),
                    int(msg.get("created_at") or now),
                ),
            )
        return {"ok": True}

    def save_reasoning(self, log: dict) -> dict:
        now = int(time.time() * 1000)
        r_text = str(log.get("reasoning_text") or "")
        if len(r_text) > 150000:
            r_text = r_text[:40000] + f"\n\n... [思考过程过长，已自动折叠中间 {len(r_text) - 120000} 字符] ...\n\n" + r_text[-80000:]
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO reasoning_logs (
                  id, task_id, agent_id, agent_name, task_prompt, reasoning_text, status, started_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    log.get("id") or f"rlog_{log.get('task_id')}",
                    log.get("task_id") or "",
                    log.get("agent_id") or "",
                    log.get("agent_name") or "",
                    log.get("task_prompt") or "",
                    r_text,
                    log.get("status") or "streaming",
                    int(log.get("started_at") or now),
                    now,
                ),
            )
        return {"ok": True}

    def save_settings(self, settings: dict) -> dict:
        with self._lock, self._connect() as conn:
            for k, v in settings.items():
                val_str = "true" if v is True else ("false" if v is False else str(v))
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (str(k), val_str))
        return {"ok": True}

    def save_tool_audit(self, audit: dict) -> dict:
        now = int(time.time() * 1000)
        args_val = audit.get("args")
        args_str = args_val if isinstance(args_val, str) else json.dumps(args_val or {}, ensure_ascii=False)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tool_audit_logs (
                  id, task_id, agent_id, agent_name, tool_name, args_json,
                  permission_mode, approved_by_user, status, step_num, duration_ms, exit_code, resolved_path, result_text, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit.get("id") or f"audit_{now}",
                    audit.get("task_id") or "",
                    audit.get("agent_id") or "",
                    audit.get("agent_name") or "",
                    audit.get("tool_name") or "",
                    args_str,
                    audit.get("permission_mode") or "ask",
                    1 if audit.get("approved_by_user", True) else 0,
                    str(audit.get("status") or "completed"),
                    int(audit.get("step_num") or 1),
                    int(audit.get("duration_ms") or 0),
                    int(audit.get("exit_code") if audit.get("exit_code") is not None else 0),
                    str(audit.get("resolved_path") or ""),
                    (audit.get("result_text") or "")[:150000],
                    int(audit.get("created_at") or now),
                ),
            )
        return {"ok": True}

    def clear_messages(self) -> dict:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM messages")
            conn.execute("DELETE FROM reasoning_logs")
            conn.execute("DELETE FROM task_queue")
            conn.execute("DELETE FROM tool_audit_logs")
        return {"ok": True}


DB = LocalSQLiteDB(DB_PATH)


# ============================================================================
# 2. 本地 Agent 工具执行引擎 (一口气全量读取 .pdf/.docx、高危目录拦截、无 Bypass 安全终端)
# ============================================================================
def expand_windows_and_user_vars(raw_path: str, strip_outer_quotes: bool = True) -> str:
    if not raw_path:
        return ""
    s = str(raw_path).strip()
    if strip_outer_quotes and len(s) >= 2 and ((s[0] == '"' and s[-1] == '"') or (s[0] == "'" and s[-1] == "'")):
        s = s[1:-1]
    if "%USERPROFILE%" in s.upper():
        home_dir = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        s = re.sub(r"%USERPROFILE%", lambda _: home_dir, s, flags=re.IGNORECASE)
    if "$env:USERPROFILE" in s:
        home_dir = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        s = re.sub(r"\$env:USERPROFILE", lambda _: home_dir, s, flags=re.IGNORECASE)
    s = os.path.expandvars(os.path.expanduser(s))
    return s


def resolve_local_path(workspace_dir: str, input_path: str = ".") -> Path:
    ws_expanded = expand_windows_and_user_vars(workspace_dir or str(DEFAULT_WORKSPACE))
    root = Path(ws_expanded or str(DEFAULT_WORKSPACE)).resolve()
    root.mkdir(parents=True, exist_ok=True)

    cleaned = expand_windows_and_user_vars(input_path or ".")
    if not cleaned or cleaned == ".":
        return root

    candidate = Path(cleaned)
    if candidate.is_absolute() or re.match(r"^[A-Za-z]:[/\\]", cleaned):
        return candidate.resolve()

    return (root / cleaned.lstrip("/\\")).resolve()


def _decode_process_bytes(raw_bytes: bytes) -> str:
    if not raw_bytes:
        return ""
    for enc in ("utf-8", "gbk", "cp936", "utf-16"):
        try:
            return raw_bytes.decode(enc)
        except Exception:
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def extract_docx_text_native(docx_path: Path) -> str:
    """使用 Python 标准库 zipfile + xml.etree.ElementTree 零依赖一次性提取 .docx Word 文档全文与表格内容"""
    try:
        with zipfile.ZipFile(docx_path, "r") as zf:
            if "word/document.xml" not in zf.namelist():
                return "[.docx 解析提示] 未找到 word/document.xml"
            xml_bytes = zf.read("word/document.xml")
        root = ET.fromstring(xml_bytes)
        paragraphs = []
        for elem in root.iter():
            tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag == "p":
                texts = []
                for child in elem.iter():
                    ctag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    if ctag == "t" and child.text:
                        texts.append(child.text)
                    elif ctag == "tab":
                        texts.append("\t")
                    elif ctag in ("br", "cr"):
                        texts.append("\n")
                line = "".join(texts).strip()
                if line:
                    paragraphs.append(line)
        return "\n".join(paragraphs)
    except Exception as exc:
        return f"[读取 .docx 异常: {exc}]"


def _try_extract_pdf_with_installed_libs(pdf_path: Path) -> tuple[bool, str, int]:
    try:
        import fitz  # type: ignore
        doc = fitz.open(str(pdf_path))
        pages_text = []
        num_pages = len(doc)
        for i, page in enumerate(doc):
            t = page.get_text("text").strip()
            if t:
                pages_text.append(f"--- [第 {i + 1}/{num_pages} 页] ---\n{t}")
        doc.close()
        if pages_text:
            return True, "\n\n".join(pages_text), num_pages
    except Exception:
        pass

    for mod_name in ("pypdf", "PyPDF2"):
        try:
            mod = __import__(mod_name)
            reader = mod.PdfReader(str(pdf_path))
            num_pages = len(reader.pages)
            pages_text = []
            for i, page in enumerate(reader.pages):
                t = (page.extract_text() or "").strip()
                if t:
                    pages_text.append(f"--- [第 {i + 1}/{num_pages} 页] ---\n{t}")
            if pages_text:
                return True, "\n\n".join(pages_text), num_pages
        except Exception:
            continue

    try:
        import pdfplumber  # type: ignore
        pages_text = []
        with pdfplumber.open(str(pdf_path)) as pdf:
            num_pages = len(pdf.pages)
            for i, page in enumerate(pdf.pages):
                t = (page.extract_text() or "").strip()
                if t:
                    pages_text.append(f"--- [第 {i + 1}/{num_pages} 页] ---\n{t}")
        if pages_text:
            return True, "\n\n".join(pages_text), num_pages
    except Exception:
        pass

    return False, "", 0


def extract_pdf_text_native(pdf_path: Path) -> str:
    ok, text, num_pages = _try_extract_pdf_with_installed_libs(pdf_path)
    if ok and text:
        return f"[PDF 解析成功 | 共 {num_pages} 页]\n{text}"

    try:
        import zlib
        raw = pdf_path.read_bytes()
        extracted_chunks = []
        for m in re.finditer(rb"stream[\r\n]+(.*?)[\r\n]+endstream", raw, re.DOTALL):
            stream_data = m.group(1)
            try:
                decompressed = zlib.decompress(stream_data)
            except Exception:
                decompressed = stream_data
            for txt_match in re.finditer(rb"\(([^()]{2,})\)", decompressed):
                piece = txt_match.group(1).decode("latin1", errors="ignore")
                piece_clean = "".join(ch for ch in piece if ch.isprintable() or ch in "\n\t ")
                if len(piece_clean.strip()) >= 2:
                    extracted_chunks.append(piece_clean.strip())
        if extracted_chunks:
            return "[PDF 基础文本流提取结果（提示：当前环境未安装 pypdf/PyMuPDF，已使用标准库基础流提取；如需完整解析复杂编码 PDF，可执行 pip install pypdf）]\n" + " ".join(extracted_chunks[:8000])
    except Exception:
        pass

    return "[PDF 读取提示] 当前环境未安装 pypdf / PyMuPDF 或文件为扫描件图片，未能提取出文本。可安装可选依赖 (pip install pypdf) 后重试。"


def run_shell_process(command: str, cwd_path: Path, shell_mode: str = "auto") -> dict:
    """
    安全执行并读取 PowerShell 或 CMD 命令的标准输出与错误输出（已移除策略绕过参数）
    """
    cmd_str = expand_windows_and_user_vars(str(command or "").strip(), strip_outer_quotes=False)
    if not cmd_str:
        return {"ok": False, "output": "命令不能为空"}

    is_risky_cwd, risk_reason = is_high_risk_system_path(cwd_path)
    if is_risky_cwd:
        return {"ok": False, "output": f"[安全拦截] 禁止在系统敏感目录执行命令: {risk_reason} ({cwd_path})"}

    cwd_path.mkdir(parents=True, exist_ok=True)
    is_win = sys.platform.startswith("win")

    if is_win:
        if shell_mode == "powershell":
            exec_args = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                cmd_str,
            ]
            use_shell = False
        elif shell_mode == "cmd":
            exec_args = ["cmd.exe", "/d", "/s", "/c", cmd_str]
            use_shell = False
        else:
            if re.search(r"\b(New-Item|Get-ChildItem|Set-Content|Get-Content|Out-File|Test-Path|\$env:)\b", cmd_str, re.I):
                exec_args = [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    cmd_str,
                ]
                use_shell = False
            else:
                exec_args = cmd_str
                use_shell = True
    else:
        exec_args = cmd_str
        use_shell = True

    proc = subprocess.run(
        exec_args,
        cwd=str(cwd_path),
        shell=use_shell,
        capture_output=True,
        timeout=90,
    )
    stdout_text = _decode_process_bytes(proc.stdout).strip()
    stderr_text = _decode_process_bytes(proc.stderr).strip()
    combined = "\n".join(filter(None, [stdout_text, stderr_text])).strip()
    shell_label = "PowerShell" if shell_mode == "powershell" else ("CMD" if shell_mode == "cmd" else "Terminal")
    if proc.returncode != 0:
        return {
            "ok": False,
            "exit_code": proc.returncode,
            "cwd": str(cwd_path),
            "command": cmd_str,
            "shell": shell_label,
            "output": f"[{shell_label} 退出码 {proc.returncode} | 目录: {cwd_path}]\n$ {cmd_str}\n{combined}",
        }
    return {
        "ok": True,
        "exit_code": 0,
        "cwd": str(cwd_path),
        "command": cmd_str,
        "shell": shell_label,
        "output": f"[{shell_label} 执行成功 | 目录: {cwd_path}]\n$ {cmd_str}\n{combined or '(命令执行成功，无额外控制台输出)'}",
    }


def _read_single_local_file_full(workspace_dir: str, raw_p: str, max_full_chars: int = 500_000) -> tuple[bool, str, str]:
    target = resolve_local_path(workspace_dir, raw_p)
    is_risky, risk_reason = is_high_risk_system_path(target)
    if is_risky:
        return False, str(target), f"[安全拦截] 禁止读取系统高危敏感路径: {risk_reason} ({target})"
    if not target.exists() or not target.is_file():
        return False, str(target), f"文件不存在: {target} (原始参数: {raw_p})"

    suffix = target.suffix.lower()
    if suffix == ".pdf":
        full_text = extract_pdf_text_native(target)
    elif suffix == ".docx":
        full_text = extract_docx_text_native(target)
    else:
        raw_bytes = target.read_bytes()
        full_text = _decode_process_bytes(raw_bytes)

    total_len = len(full_text)
    content_out = full_text[:max_full_chars]
    trunc_note = f"\n[注: 超大文件总长 {total_len} 字符，已读取前 {max_full_chars} 字符]" if total_len > max_full_chars else ""
    return True, str(target), f"[一次性全量读取文件成功: {target} (共 {total_len} 字符，已完整读取无需再次分段调用)]\n{content_out}{trunc_note}"


def execute_local_agent_tool(workspace_dir: str, tool_name: str, args: dict) -> dict:
    try:
        if tool_name == "read_local_file":
            # 支持单个 file_path 或批量 file_paths 数组一口气全量读取！
            file_paths_list = args.get("file_paths")
            if isinstance(file_paths_list, list) and len(file_paths_list) > 0:
                outputs = []
                all_ok = True
                resolved_list = []
                for fp in file_paths_list[:10]:
                    ok, rpath, out_str = _read_single_local_file_full(workspace_dir, str(fp))
                    all_ok = all_ok and ok
                    resolved_list.append(rpath)
                    outputs.append(out_str)
                return {
                    "ok": all_ok,
                    "resolved_path": ", ".join(resolved_list),
                    "output": "\n\n========================================\n\n".join(outputs),
                }

            raw_p = args.get("file_path") or args.get("path") or ""
            ok, rpath, out_str = _read_single_local_file_full(workspace_dir, str(raw_p))
            return {
                "ok": ok,
                "resolved_path": rpath,
                "output": out_str,
            }

        if tool_name == "write_local_file":
            raw_p = args.get("file_path") or args.get("path") or "new_file.txt"
            target = resolve_local_path(workspace_dir, raw_p)
            is_risky, risk_reason = is_high_risk_system_path(target)
            if is_risky:
                return {"ok": False, "output": f"[安全拦截] 禁止写入系统高危敏感路径: {risk_reason} ({target})"}
            target.parent.mkdir(parents=True, exist_ok=True)
            content = str(args.get("content", ""))
            target.write_text(content, encoding="utf-8")
            return {
                "ok": True,
                "resolved_path": str(target),
                "output": f"[本地文件写入成功] 实际落盘路径: {target} (共 {len(content.encode('utf-8'))} 字节, {len(content.splitlines())} 行)",
            }

        if tool_name == "list_local_directory":
            raw_p = args.get("dir_path") or args.get("file_path") or args.get("path") or "."
            target = resolve_local_path(workspace_dir, raw_p)
            is_risky, risk_reason = is_high_risk_system_path(target)
            if is_risky:
                return {"ok": False, "output": f"[安全拦截] 禁止遍历系统高危敏感目录: {risk_reason} ({target})"}
            if not target.exists() or not target.is_dir():
                return {"ok": False, "output": f"目录不存在: {target} (原始参数: {raw_p})"}
            items = []
            for entry in sorted(target.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                items.append(
                    {
                        "name": entry.name,
                        "type": "directory" if entry.is_dir() else "file",
                        "size": entry.stat().st_size if entry.is_file() else 0,
                    }
                )
            return {
                "ok": True,
                "resolved_path": str(target),
                "output": f"[目录列表: {target}]\n" + json.dumps(items, ensure_ascii=False, indent=2),
            }

        if tool_name in ("run_powershell_command", "run_cmd_command", "run_terminal_command"):
            custom_cwd = args.get("cwd") or args.get("working_dir") or "."
            cwd_target = resolve_local_path(workspace_dir, custom_cwd)
            if tool_name == "run_powershell_command":
                mode = "powershell"
            elif tool_name == "run_cmd_command":
                mode = "cmd"
            else:
                mode = str(args.get("shell") or "auto").lower()
            return run_shell_process(args.get("command", ""), cwd_target, shell_mode=mode)

        return {"ok": False, "output": f"未知工具: {tool_name}"}
    except Exception as exc:
        return {"ok": False, "output": f"执行异常: {exc}"}


def select_folder_dialog() -> str | None:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = filedialog.askdirectory(title="选择授权给 AI Agent 读写的本地工作区文件夹")
        root.destroy()
        return os.path.normpath(folder) if folder else None
    except Exception:
        return None


def export_config_dialog(config_payload: dict) -> dict:
    try:
        import tkinter as tk
        from tkinter import filedialog

        # 如果导出的 payload 中 api_key 是占位符，从数据库补齐真实 key 供用户本地备份
        agents_list = config_payload.get("agents")
        if isinstance(agents_list, list):
            for a in agents_list:
                if isinstance(a, dict) and a.get("api_key") == STORED_KEY_PLACEHOLDER:
                    a["api_key"] = DB.get_raw_api_key(str(a.get("id") or ""))

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        file_path = filedialog.asksaveasfilename(
            title="导出全部 AI 配置与全局系统设置",
            defaultextension=".json",
            initialfile="ai-group-chat-config.json",
            filetypes=[("JSON 配置文件", "*.json"), ("所有文件", "*.*")],
        )
        root.destroy()
        if not file_path:
            return {"ok": False, "cancelled": True}
        target = Path(file_path)
        target.write_text(json.dumps(config_payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return {"ok": True, "path": str(target)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "fallback_browser": True}


def export_chat_dialog(payload: dict) -> dict:
    try:
        import tkinter as tk
        from tkinter import filedialog

        fmt = str(payload.get("format") or "md").lower()
        content = str(payload.get("content") or "")
        default_ext = ".md" if fmt == "md" else (".json" if fmt == "json" else ".txt")
        init_name = f"ai-group-chat-history-{int(time.time())}{default_ext}"

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        file_path = filedialog.asksaveasfilename(
            title="导出群聊记录与协作日志",
            defaultextension=default_ext,
            initialfile=init_name,
            filetypes=[
                ("Markdown 聊天记录 (*.md)", "*.md"),
                ("纯文本聊天记录 (*.txt)", "*.txt"),
                ("完整数据 JSON (*.json)", "*.json"),
                ("所有文件 (*.*)", "*.*"),
            ],
        )
        root.destroy()
        if not file_path:
            return {"ok": False, "cancelled": True}
        target = Path(file_path)
        target.write_text(content, encoding="utf-8")
        return {"ok": True, "path": str(target)}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "fallback_browser": True}


def import_config_dialog() -> dict:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        file_path = filedialog.askopenfilename(
            title="选择要导入的 AI 配置文件 (.json)",
            filetypes=[("JSON 配置文件", "*.json"), ("所有文件", "*.*")],
        )
        root.destroy()
        if not file_path:
            return {"ok": False, "cancelled": True}
        raw = Path(file_path).read_text(encoding="utf-8")
        parsed = json.loads(raw)
        agents = parsed.get("agents") if isinstance(parsed, dict) else (parsed if isinstance(parsed, list) else None)
        settings = parsed.get("settings") if isinstance(parsed, dict) else None
        if not isinstance(agents, list):
            return {"ok": False, "error": "配置文件格式无效：缺少 agents 数组"}
        DB.replace_all_config(agents, settings)
        return {"ok": True, "path": str(file_path), "state": DB.get_all_state()}
    except Exception as exc:
        return {"ok": False, "error": str(exc), "fallback_browser": True}


# ============================================================================
# 3. 多协议原生大模型工具定义（一口气全量读取 + share_with_other_ai 私密隔离标志）
# ============================================================================
TOOL_DEFINITIONS_RAW = [
    {
        "name": "write_local_file",
        "description": "在本地磁盘上新建或覆盖写入文件（自动创建父文件夹）。支持相对路径、Windows 绝对路径以及 %USERPROFILE%\\Desktop 等环境变量。",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "文件路径，如 'src/main.py' 或 '%USERPROFILE%\\\\Desktop\\\\project\\\\app.py'",
                },
                "content": {"type": "string", "description": "要写入文件的完整文本或代码内容"},
                "share_with_other_ai": {
                    "type": "boolean",
                    "description": "是否将该次工具执行输出同步到其他 AI 的上下文中。默认 false（仅你自己和群主可见，节省其他 AI 的 Token）。",
                },
            },
            "required": ["file_path", "content"],
        },
    },
    {
        "name": "read_local_file",
        "description": "一次性全量读取本地文件完整内容（原生内置支持 .pdf 论文全文提取、.docx Word 文档提取及各类代码/Markdown/文本文件，单次调用即可读出整篇全文，严禁分段多次调用！也支持传入 file_paths 数组一次批量读取多个文件）。",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "要一次性完整读取的单个文件路径（支持 .pdf, .docx, .md, .py, .txt 等）"},
                "file_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "可选：若需同时读取多个文件，可传入文件路径列表一次性全部读完",
                },
                "share_with_other_ai": {
                    "type": "boolean",
                    "description": "是否将读取到的文件原文暴露给其他 AI。默认 false（仅你自己和群主可见，避免大段文件原文塞爆其他 AI 的上下文）。",
                },
            },
        },
    },
    {
        "name": "list_local_directory",
        "description": "列出本地文件夹中的文件与子目录列表。支持相对路径、绝对路径与 %USERPROFILE% 环境变量。",
        "parameters": {
            "type": "object",
            "properties": {
                "dir_path": {"type": "string", "description": "要查看的目录路径，默认为 '.'"},
                "share_with_other_ai": {
                    "type": "boolean",
                    "description": "是否将目录列表放入其他 AI 上下文，默认 false（仅自己与群主可见）",
                },
            },
        },
    },
    {
        "name": "run_powershell_command",
        "description": "在本地 Windows PowerShell 中执行命令并读取返回的标准输出与错误输出。",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的 PowerShell 命令字符串"},
                "cwd": {"type": "string", "description": "可选执行目录路径（支持 %USERPROFILE%\\Desktop 等）"},
                "share_with_other_ai": {
                    "type": "boolean",
                    "description": "是否将命令输出共享给其他 AI，默认 false（仅自己与群主可见）",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "run_cmd_command",
        "description": "在本地 Windows CMD (cmd.exe /c) 中执行命令并读取返回的输出。",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的 CMD 命令字符串"},
                "cwd": {"type": "string", "description": "可选执行目录路径（支持 %USERPROFILE%\\Desktop 等）"},
                "share_with_other_ai": {
                    "type": "boolean",
                    "description": "是否将命令输出共享给其他 AI，默认 false（仅自己与群主可见）",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "run_terminal_command",
        "description": "在本地终端执行命令并读取输出（自动识别 PowerShell 或 CMD）。",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "要执行的终端命令"},
                "cwd": {"type": "string", "description": "可选工作目录"},
                "share_with_other_ai": {
                    "type": "boolean",
                    "description": "是否将命令输出共享给其他 AI，默认 false（仅自己与群主可见）",
                },
            },
            "required": ["command"],
        },
    },
    {
        "name": "ask_other_ai",
        "description": "向群内的另一个 AI 发起协作对话或请求结果。只有当你自己的文件读写与代码任务已完成、确实需要对方接手或修改时才调用。",
        "parameters": {
            "type": "object",
            "properties": {
                "target_ai": {"type": "string", "description": "目标 AI 昵称，如 Gemini, Codex, Claude, DeepSeek"},
                "message": {"type": "string", "description": "发送给目标 AI 的具体协作内容"},
                "is_urgent": {"type": "boolean", "description": "是否紧急打断对方当前思考"},
            },
            "required": ["target_ai", "message", "is_urgent"],
        },
    },
]

AGENT_TOOLS_OPENAI_CHAT = [{"type": "function", "function": t} for t in TOOL_DEFINITIONS_RAW]
AGENT_TOOLS_OPENAI_RESPONSES = [
    {"type": "function", "name": t["name"], "description": t["description"], "parameters": t["parameters"]}
    for t in TOOL_DEFINITIONS_RAW
]
AGENT_TOOLS_ANTHROPIC = [
    {"name": t["name"], "description": t["description"], "input_schema": t["parameters"]}
    for t in TOOL_DEFINITIONS_RAW
]
AGENT_TOOLS_GEMINI = [
    {
        "functionDeclarations": [
            {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}
            for t in TOOL_DEFINITIONS_RAW
        ]
    }
]


# ============================================================================
# 4. 本地 HTTP / SSE 服务端（内置防 DNS Rebinding、Host/Origin 校验与 X-Session-Token 鉴权）
# ============================================================================

def urlopen_stream_with_retry(build_req_fn, timeout: int = 180, retries: int = 1):
    """
    针对第三方中转网关或长思考模型偶发的 RemoteDisconnected / ConnectionResetError，
    在尚未发出任何流式分块前自动使用全新连接重试 1 次，并将超时提升至 180 秒。
    """
    last_exc = None
    for attempt in range(retries + 1):
        try:
            req = build_req_fn()
            req.add_unredirected_header("Connection", "close")
            return urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError:
            raise
        except (http.client.RemoteDisconnected, ConnectionResetError, urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(0.6)
                continue
            raise
    raise last_exc


class AppRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format_str, *args):
        pass

    def _verify_request_security(self, require_session_token: bool = True) -> bool:
        """
        核心安全防线：
        1. 校验客户端来源 IP 必须为本机环回地址 (127.0.0.1 / ::1)
        2. 严格校验 Host 请求头必须为 127.0.0.1 或 localhost，缓解 DNS Rebinding 域名重绑定攻击风险
        3. 严格校验 Origin / Referer / Sec-Fetch-Site，阻断跨站请求伪造 (CSRF)
        4. 对所有 /api/* 路由强制验证 256-bit 随机令牌 X-Session-Token
        """
        client_ip = self.client_address[0] if self.client_address else ""
        if client_ip not in ("127.0.0.1", "::1", "localhost"):
            self._send_json({"ok": False, "error": "Forbidden: Localhost access only"}, status=403)
            return False

        host_hdr = (self.headers.get("Host") or "").strip().lower()
        if not re.match(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$", host_hdr):
            self._send_json(
                {"ok": False, "error": f"Forbidden: Untrusted Host header ({host_hdr}) - DNS Rebinding blocked"},
                status=403,
            )
            return False

        sec_fetch = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if sec_fetch and sec_fetch not in ("same-origin", "none"):
            self._send_json({"ok": False, "error": f"Forbidden: Cross-site request blocked ({sec_fetch})"}, status=403)
            return False

        for hdr_name in ("Origin", "Referer"):
            val = (self.headers.get(hdr_name) or "").strip()
            if val:
                parsed_u = urllib.parse.urlparse(val)
                if parsed_u.hostname not in ("127.0.0.1", "localhost", "::1"):
                    self._send_json(
                        {"ok": False, "error": f"Forbidden: Untrusted {hdr_name} ({val})"},
                        status=403,
                    )
                    return False

        if require_session_token:
            req_token = (self.headers.get("X-Session-Token") or "").strip()
            if not req_token or not secrets.compare_digest(req_token, SERVER_SESSION_TOKEN):
                self._send_json(
                    {"ok": False, "error": "Unauthorized: Invalid or missing X-Session-Token"},
                    status=401,
                )
                return False

        return True

    def _send_json(self, data: dict, status: int = 200):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(raw)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        return json.loads(raw)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            if not self._verify_request_security(require_session_token=False):
                return
            if not HTML_PATH.exists():
                self.send_error(404, "Missing static/index.html")
                return
            html_str = HTML_PATH.read_text(encoding="utf-8")
            # 动态注入当前进程专属 256-bit 会话令牌
            token_script = f'<script>window.__AI_STUDIO_SESSION_TOKEN__ = "{SERVER_SESSION_TOKEN}";</script>'
            if "</head>" in html_str:
                html_str = html_str.replace("</head>", f"  {token_script}\n</head>", 1)
            else:
                html_str = token_script + html_str
            content = html_str.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "SAMEORIGIN")
            self.end_headers()
            self.wfile.write(content)
            return

        if parsed.path in ("/LICENSE", "/LICENSE_AGPL-3.0.txt"):
            if not self._verify_request_security(require_session_token=False):
                return
            lic_file = BASE_DIR / "LICENSE_AGPL-3.0.txt"
            if not lic_file.exists():
                lic_file = BASE_DIR / "LICENSE"
            if lic_file.exists():
                data = lic_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

        if urllib.parse.unquote(parsed.path) in ("/免责协议.txt", "/disclaimer.txt"):
            if not self._verify_request_security(require_session_token=False):
                return
            disc_file = BASE_DIR / "免责协议.txt"
            if disc_file.exists():
                data = disc_file.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

        if parsed.path == "/api/state":
            if not self._verify_request_security(require_session_token=True):
                return
            self._send_json(DB.get_all_state(mask_keys=True))
            return

        self.send_error(404, "Not Found")

    def do_POST(self):
        if not self._verify_request_security(require_session_token=True):
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/agent/save":
            body = self._read_json_body()
            self._send_json(DB.save_agent(body))
            return

        if path == "/api/agents/reorder":
            body = self._read_json_body()
            self._send_json(DB.reorder_agents(body.get("orderedIds") or []))
            return

        if path == "/api/config/replace":
            body = self._read_json_body()
            DB.replace_all_config(body.get("agents") or [], body.get("settings") or {})
            self._send_json({"ok": True, "state": DB.get_all_state(mask_keys=True)})
            return

        if path == "/api/dialog/export-config":
            body = self._read_json_body()
            self._send_json(export_config_dialog(body))
            return

        if path == "/api/dialog/export-chat":
            body = self._read_json_body()
            self._send_json(export_chat_dialog(body))
            return

        if path == "/api/dialog/import-config":
            self._send_json(import_config_dialog())
            return

        if path == "/api/agent/delete":
            body = self._read_json_body()
            self._send_json(DB.delete_agent(body.get("id", "")))
            return

        if path == "/api/message/save":
            body = self._read_json_body()
            self._send_json(DB.save_message(body))
            return

        if path == "/api/reasoning/save":
            body = self._read_json_body()
            self._send_json(DB.save_reasoning(body))
            return

        if path == "/api/settings/save":
            body = self._read_json_body()
            self._send_json(DB.save_settings(body))
            return

        if path == "/api/audit/save":
            body = self._read_json_body()
            self._send_json(DB.save_tool_audit(body))
            return

        if path == "/api/history/clear":
            self._send_json(DB.clear_messages())
            return

        if path == "/api/tool/issue-ticket":
            # 当用户在前端审批弹窗中点击“批准”时，签发与 toolName + args 严格绑定的一次性执行票据
            body = self._read_json_body()
            t_name = str(body.get("toolName") or "")
            t_args = body.get("args") or {}
            ticket = issue_one_time_approval_ticket(t_name, t_args)
            self._send_json({"ok": True, "approvalTicket": ticket})
            return

        if path == "/api/tool/execute":
            if DB.get_setting("disclaimer_accepted_v1", "false") != "true":
                self._send_json(
                    {
                        "ok": False,
                        "output": "[安全守卫拦截] 您尚未阅读并同意《免责协议》（SQLite 状态未签署），禁止执行任何本地工具。",
                    },
                    status=403,
                )
                return

            body = self._read_json_body()
            tool_name = str(body.get("toolName") or "")
            args = body.get("args") or {}
            approval_ticket = str(body.get("approvalTicket") or "")

            # 后端强制校验权限设置：若当前处于 'ask' 模式，必须持有有效的一次性审批票据！
            is_cmd_tool = tool_name in ("run_powershell_command", "run_cmd_command", "run_terminal_command")
            perm_key = "cmd_permission_mode" if is_cmd_tool else "fs_permission_mode"
            current_perm_mode = DB.get_setting(perm_key, "ask")

            if current_perm_mode == "ask":
                if not consume_one_time_approval_ticket(approval_ticket, tool_name, args):
                    self._send_json(
                        {
                            "ok": False,
                            "output": "[后端安全守卫拦截] 当前处于“每次询问批准 (ask)”模式，但本次请求缺少有效的一次性批准票据 (approvalTicket)，已拒绝执行。",
                        },
                        status=403,
                    )
                    return

            res = execute_local_agent_tool(
                body.get("workspaceDir", str(DEFAULT_WORKSPACE)),
                tool_name,
                args,
            )
            self._send_json(res)
            return

        if path == "/api/dialog/select-folder":
            chosen = select_folder_dialog()
            self._send_json({"folder": chosen})
            return

        if path == "/api/llm/abort":
            body = self._read_json_body()
            task_id = body.get("taskId", "")
            with ABORT_LOCK:
                ev = ACTIVE_STREAM_ABORTS.get(task_id)
                if ev:
                    ev.set()
            self._send_json({"aborted": True})
            return

        if path == "/api/llm/stream":
            self._handle_llm_stream()
            return

        self.send_error(404, "Unknown API endpoint")

    def _handle_llm_stream(self):
        body = self._read_json_body()
        task_id = body.get("taskId") or f"task_{int(time.time()*1000)}"
        agent = body.get("agent") or {}
        messages = body.get("messages") or []
        enable_tools = bool(body.get("enableTools", True))

        if DB.get_setting("disclaimer_accepted_v1", "false") != "true":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            err_payload = f"data: {json.dumps({'type': 'error', 'error': '尚未在 SQLite 数据库中签署同意《免责协议》，请先阅读并勾选同意免责声明。'}, ensure_ascii=False)}\n\n".encode("utf-8")
            self.wfile.write(err_payload)
            self.wfile.flush()
            return

        abort_event = threading.Event()
        with ABORT_LOCK:
            ACTIVE_STREAM_ABORTS[task_id] = abort_event

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def emit_sse(event_dict: dict):
            payload = f"data: {json.dumps(event_dict, ensure_ascii=False)}\n\n".encode("utf-8")
            self.wfile.write(payload)
            self.wfile.flush()

        try:
            provider = (agent.get("provider") or "openai").lower()
            supports_reasoning = bool(agent.get("supports_reasoning"))
            base_url = (agent.get("base_url") or "").rstrip("/")
            api_key = (agent.get("api_key") or "").strip()
            # 如果前端传来的是脱敏占位符，自动从本地 SQLite 读取真实密钥
            if api_key == STORED_KEY_PLACEHOLDER or "••••" in api_key:
                api_key = DB.get_raw_api_key(str(agent.get("id") or ""))
            model = (agent.get("model") or "").strip()
            sys_msg = "\n\n".join(
                str(m.get("content", "")).strip()
                for m in messages
                if m.get("role") == "system" and str(m.get("content", "")).strip()
            )

            if provider == "gemini":
                clean_model = model.replace("models/", "") or "gemini-2.5-pro"
                url = f"{base_url}/models/{urllib.parse.quote(clean_model)}:streamGenerateContent?alt=sse&key={urllib.parse.quote(api_key)}"
                norm_msgs = normalize_alternating_messages(messages, user_role="user", assistant_role="model")
                contents = [
                    {
                        "role": m["role"],
                        "parts": [{"text": m["content"]}],
                    }
                    for m in norm_msgs
                ]
                req_body = {"contents": contents, "generationConfig": {}}
                if sys_msg:
                    req_body["systemInstruction"] = {"parts": [{"text": sys_msg}]}
                if supports_reasoning:
                    req_body["generationConfig"]["thinkingConfig"] = {"includeThoughts": True}
                if enable_tools:
                    req_body["tools"] = AGENT_TOOLS_GEMINI

                req = urllib.request.Request(
                    url,
                    data=json.dumps(req_body).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen_stream_with_retry(lambda: req, timeout=180) as resp:
                    for raw_line in resp:
                        if abort_event.is_set():
                            emit_sse({"type": "aborted"})
                            return
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line.startswith("data:"):
                            continue
                        data_str = line[5:].strip()
                        if not data_str:
                            continue
                        parsed = json.loads(data_str)
                        parts = parsed.get("candidates", [{}])[0].get("content", {}).get("parts", [])
                        for p in parts:
                            if p.get("thought") is True and supports_reasoning and p.get("text"):
                                emit_sse({"type": "reasoning", "chunk": p["text"]})
                            elif p.get("text"):
                                emit_sse({"type": "content", "chunk": p["text"]})
                            elif p.get("functionCall"):
                                fc = p["functionCall"]
                                cid = f"call_{int(time.time()*1000)}"
                                emit_sse(
                                    {
                                        "type": "tool_delta",
                                        "toolId": cid,
                                        "name": fc.get("name") or "",
                                        "delta": json.dumps(fc.get("args") or {}, ensure_ascii=False),
                                    }
                                )
                                emit_sse(
                                    {
                                        "type": "tool_call",
                                        "toolCall": {
                                            "id": cid,
                                            "name": fc.get("name"),
                                            "args": fc.get("args") or {},
                                        },
                                    }
                                )

            elif provider == "anthropic":
                url = f"{base_url}/messages"
                chat_msgs = normalize_alternating_messages(messages, user_role="user", assistant_role="assistant")
                req_body = {
                    "model": model or "claude-3-7-sonnet-20250219",
                    "max_tokens": 8192 if supports_reasoning else 4096,
                    "messages": chat_msgs,
                    "stream": True,
                }
                if sys_msg:
                    req_body["system"] = sys_msg
                if supports_reasoning:
                    req_body["thinking"] = {"type": "enabled", "budget_tokens": 2048}
                if enable_tools:
                    req_body["tools"] = AGENT_TOOLS_ANTHROPIC

                req = urllib.request.Request(
                    url,
                    data=json.dumps(req_body).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                        "anthropic-version": "2023-06-01",
                    },
                    method="POST",
                )
                anthropic_tool_buf = {}
                with urlopen_stream_with_retry(lambda: req, timeout=180) as resp:
                    for raw_line in resp:
                        if abort_event.is_set():
                            emit_sse({"type": "aborted"})
                            return
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line.startswith("data:"):
                            continue
                        data_str = line[5:].strip()
                        if not data_str:
                            continue
                        parsed = json.loads(data_str)
                        ev_type = parsed.get("type")
                        if ev_type == "message_stop":
                            break
                        if ev_type == "content_block_start":
                            idx = parsed.get("index", 0)
                            cb = parsed.get("content_block") or {}
                            if cb.get("type") == "tool_use":
                                cid = cb.get("id") or f"call_{idx}"
                                tname = cb.get("name") or ""
                                anthropic_tool_buf[idx] = {
                                    "id": cid,
                                    "name": tname,
                                    "json_str": "",
                                }
                                emit_sse({"type": "tool_delta", "toolId": cid, "name": tname, "delta": ""})
                        elif ev_type == "content_block_delta":
                            idx = parsed.get("index", 0)
                            delta = parsed.get("delta") or {}
                            if supports_reasoning and delta.get("type") == "thinking_delta":
                                emit_sse({"type": "reasoning", "chunk": delta.get("thinking", "")})
                            elif delta.get("type") == "text_delta":
                                emit_sse({"type": "content", "chunk": delta.get("text", "")})
                            elif delta.get("type") == "input_json_delta" and idx in anthropic_tool_buf:
                                p_json = delta.get("partial_json", "")
                                anthropic_tool_buf[idx]["json_str"] += p_json
                                emit_sse(
                                    {
                                        "type": "tool_delta",
                                        "toolId": anthropic_tool_buf[idx]["id"],
                                        "name": anthropic_tool_buf[idx]["name"],
                                        "delta": p_json,
                                    }
                                )

                for tb in anthropic_tool_buf.values():
                    if tb["name"]:
                        try:
                            args_obj = json.loads(tb["json_str"] or "{}")
                        except Exception:
                            args_obj = {}
                        emit_sse(
                            {
                                "type": "tool_call",
                                "toolCall": {"id": tb["id"], "name": tb["name"], "args": args_obj},
                            }
                        )

            elif provider == "responses" or (agent.get("wire_api") or "").lower() == "responses":
                url = f"{base_url}/responses"
                input_items = []
                for m in messages:
                    if m.get("role") == "system":
                        continue
                    role_name = "assistant" if m.get("role") == "assistant" else "user"
                    input_items.append({"role": role_name, "content": str(m.get("content", ""))})
                effort = agent.get("reasoning_effort") or "high"

                def _build_responses_req(with_tools: bool) -> urllib.request.Request:
                    rb = {
                        "model": model or "gpt-4.1",
                        "input": input_items,
                        "stream": True,
                    }
                    if sys_msg:
                        rb["instructions"] = sys_msg
                    if supports_reasoning and effort != "none":
                        rb["reasoning"] = {"effort": effort, "summary": "auto"}
                    if agent.get("disable_response_storage"):
                        rb["store"] = False
                    if with_tools:
                        rb["tools"] = AGENT_TOOLS_OPENAI_RESPONSES
                    return urllib.request.Request(
                        url,
                        data=json.dumps(rb).encode("utf-8"),
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": f"Bearer {api_key}",
                            "User-Agent": "AIGroupChatStudio/2.4",
                        },
                        method="POST",
                    )

                try:
                    resp_ctx = urlopen_stream_with_retry(lambda: _build_responses_req(enable_tools), timeout=180)
                except urllib.error.HTTPError as e:
                    if enable_tools and e.code in (400, 422):
                        resp_ctx = urlopen_stream_with_retry(lambda: _build_responses_req(False), timeout=180)
                    else:
                        raise

                got_any_delta = False
                emitted_tool_ids: set[str] = set()
                emitted_tool_sigs: set[str] = set()
                resp_func_calls: dict[str, dict] = {}
                chat_tool_calls_buf: dict[int, dict] = {}

                def _emit_unique_responses_tool_call(call_id: str, item_id: str, name: str, args_raw):
                    if not name:
                        return
                    if (call_id and call_id in emitted_tool_ids) or (item_id and item_id in emitted_tool_ids):
                        return
                    try:
                        args_obj = json.loads(args_raw) if isinstance(args_raw, str) else (args_raw or {})
                    except Exception:
                        args_obj = {}
                    sig = f"{name}::{json.dumps(args_obj, sort_keys=True, ensure_ascii=False)}"
                    if sig in emitted_tool_sigs:
                        return
                    if call_id:
                        emitted_tool_ids.add(call_id)
                    if item_id:
                        emitted_tool_ids.add(item_id)
                    emitted_tool_sigs.add(sig)
                    emit_sse(
                        {
                            "type": "tool_call",
                            "toolCall": {
                                "id": call_id or item_id or f"call_{int(time.time()*1000)}",
                                "name": name,
                                "args": args_obj,
                            },
                        }
                    )

                with resp_ctx as resp:
                    raw_all = []
                    for raw_line in resp:
                        if abort_event.is_set():
                            emit_sse({"type": "aborted"})
                            return
                        decoded_line = raw_line.decode("utf-8", errors="replace").strip()
                        raw_all.append(decoded_line)
                        if not decoded_line.startswith("data:"):
                            continue
                        data_str = decoded_line[5:].strip()
                        if not data_str:
                            continue
                        if data_str == "[DONE]":
                            break
                        try:
                            parsed = json.loads(data_str)
                        except Exception:
                            continue
                        ev_type = parsed.get("type", "")

                        if ev_type in ("response.output_text.delta", "response.content_part.delta"):
                            chunk = parsed.get("delta") or ""
                            if isinstance(chunk, dict):
                                chunk = chunk.get("text") or ""
                            if chunk:
                                got_any_delta = True
                                emit_sse({"type": "content", "chunk": str(chunk)})

                        elif ev_type in (
                            "response.reasoning_summary_text.delta",
                            "response.reasoning.delta",
                            "response.reasoning_text.delta",
                        ):
                            if supports_reasoning:
                                r_chunk = parsed.get("delta") or ""
                                if isinstance(r_chunk, dict):
                                    r_chunk = r_chunk.get("text") or ""
                                if r_chunk:
                                    emit_sse({"type": "reasoning", "chunk": str(r_chunk)})

                        elif ev_type == "response.output_item.added":
                            item = parsed.get("item") or {}
                            if item.get("type") == "function_call":
                                item_id = item.get("id") or item.get("call_id") or f"fc_{len(resp_func_calls)}"
                                call_id = item.get("call_id") or item_id
                                tname = item.get("name") or ""
                                init_args = item.get("arguments") or ""
                                resp_func_calls[item_id] = {
                                    "id": call_id,
                                    "item_id": item_id,
                                    "name": tname,
                                    "arguments": init_args,
                                }
                                emit_sse(
                                    {
                                        "type": "tool_delta",
                                        "toolId": call_id,
                                        "name": tname,
                                        "delta": str(init_args),
                                    }
                                )

                        elif ev_type == "response.function_call_arguments.delta":
                            item_id = parsed.get("item_id") or parsed.get("call_id") or ""
                            delta_arg = parsed.get("delta") or ""
                            if item_id not in resp_func_calls:
                                resp_func_calls[item_id] = {
                                    "id": parsed.get("call_id") or item_id or f"fc_{len(resp_func_calls)}",
                                    "item_id": item_id,
                                    "name": parsed.get("name") or "",
                                    "arguments": "",
                                }
                            resp_func_calls[item_id]["arguments"] += str(delta_arg)
                            emit_sse(
                                {
                                    "type": "tool_delta",
                                    "toolId": resp_func_calls[item_id]["id"],
                                    "name": resp_func_calls[item_id]["name"],
                                    "delta": str(delta_arg),
                                }
                            )

                        elif ev_type in ("response.function_call_arguments.done", "response.output_item.done"):
                            item = parsed.get("item") or {}
                            if item.get("type") == "function_call" or ev_type == "response.function_call_arguments.done":
                                item_id = item.get("id") or parsed.get("item_id") or ""
                                cached = resp_func_calls.get(item_id, {})
                                call_id = item.get("call_id") or parsed.get("call_id") or cached.get("id") or item_id or f"call_{int(time.time()*1000)}"
                                name = item.get("name") or parsed.get("name") or cached.get("name") or ""
                                args_str = (
                                    item.get("arguments")
                                    or parsed.get("arguments")
                                    or cached.get("arguments")
                                    or "{}"
                                )
                                _emit_unique_responses_tool_call(call_id, item_id, name, args_str)

                        elif ev_type in ("response.completed", "response.done", "response.failed"):
                            resp_obj = parsed.get("response") or {}
                            for out_item in resp_obj.get("output") or []:
                                if out_item.get("type") == "function_call":
                                    item_id = out_item.get("id") or ""
                                    call_id = out_item.get("call_id") or item_id or f"call_{int(time.time()*1000)}"
                                    name = out_item.get("name") or ""
                                    args_str = out_item.get("arguments") or "{}"
                                    _emit_unique_responses_tool_call(call_id, item_id, name, args_str)
                                elif not got_any_delta:
                                    for cpart in out_item.get("content") or []:
                                        if cpart.get("text"):
                                            got_any_delta = True
                                            emit_sse({"type": "content", "chunk": cpart["text"]})
                            break

                        elif "choices" in parsed:
                            choice0 = (parsed.get("choices") or [{}])[0]
                            delta = choice0.get("delta") or {}
                            if supports_reasoning:
                                r_chunk = delta.get("reasoning_content") or delta.get("reasoning") or ""
                                if r_chunk:
                                    emit_sse({"type": "reasoning", "chunk": r_chunk})
                            if delta.get("content"):
                                got_any_delta = True
                                emit_sse({"type": "content", "chunk": delta["content"]})
                            for tc in delta.get("tool_calls") or []:
                                idx = tc.get("index", 0)
                                if idx not in chat_tool_calls_buf:
                                    chat_tool_calls_buf[idx] = {
                                        "id": tc.get("id") or f"call_{idx}",
                                        "name": "",
                                        "arguments": "",
                                    }
                                fn = tc.get("function") or {}
                                if fn.get("name"):
                                    chat_tool_calls_buf[idx]["name"] += fn["name"]
                                if fn.get("arguments"):
                                    chat_tool_calls_buf[idx]["arguments"] += fn["arguments"]
                                    emit_sse(
                                        {
                                            "type": "tool_delta",
                                            "toolId": chat_tool_calls_buf[idx]["id"],
                                            "name": chat_tool_calls_buf[idx]["name"],
                                            "delta": fn["arguments"],
                                        }
                                    )
                            if choice0.get("finish_reason") in ("stop", "length", "content_filter", "tool_calls", "function_call"):
                                break

                    for item_id, fc_info in resp_func_calls.items():
                        _emit_unique_responses_tool_call(
                            fc_info.get("id") or item_id,
                            item_id,
                            fc_info.get("name") or "",
                            fc_info.get("arguments") or "{}",
                        )

                    for tc in chat_tool_calls_buf.values():
                        _emit_unique_responses_tool_call(
                            tc["id"],
                            tc["id"],
                            tc["name"],
                            tc["arguments"] or "{}",
                        )

                    if not got_any_delta and not emitted_tool_ids and raw_all:
                        joined = "\n".join(raw_all).strip()
                        if joined.startswith("{"):
                            try:
                                full_json = json.loads(joined)
                                if full_json.get("output_text"):
                                    emit_sse({"type": "content", "chunk": str(full_json["output_text"])})
                                else:
                                    for out_item in full_json.get("output") or []:
                                        if out_item.get("type") == "function_call":
                                            _emit_unique_responses_tool_call(
                                                out_item.get("call_id") or "call_1",
                                                out_item.get("id") or "call_1",
                                                out_item.get("name") or "",
                                                out_item.get("arguments") or "{}",
                                            )
                                        for cpart in out_item.get("content") or []:
                                            if cpart.get("text"):
                                                emit_sse({"type": "content", "chunk": cpart["text"]})
                            except Exception:
                                pass

            else:
                url = f"{base_url}/chat/completions"
                req_body = {
                    "model": model or "o3-mini",
                    "messages": messages,
                    "stream": True,
                }
                effort = agent.get("reasoning_effort") or "high"
                if supports_reasoning and effort not in ("none", ""):
                    req_body["reasoning_effort"] = effort
                if agent.get("disable_response_storage"):
                    req_body["store"] = False
                if enable_tools:
                    req_body["tools"] = AGENT_TOOLS_OPENAI_CHAT

                req = urllib.request.Request(
                    url,
                    data=json.dumps(req_body).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                        "User-Agent": "AIGroupChatStudio/2.4",
                    },
                    method="POST",
                )
                tool_calls_buf = {}
                with urlopen_stream_with_retry(lambda: req, timeout=180) as resp:
                    for raw_line in resp:
                        if abort_event.is_set():
                            emit_sse({"type": "aborted"})
                            return
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if not line.startswith("data:"):
                            continue
                        data_str = line[5:].strip()
                        if not data_str:
                            continue
                        if data_str == "[DONE]":
                            break
                        parsed = json.loads(data_str)
                        choice0 = (parsed.get("choices") or [{}])[0]
                        delta = choice0.get("delta") or {}
                        if supports_reasoning:
                            r_chunk = delta.get("reasoning_content") or delta.get("reasoning") or ""
                            if r_chunk:
                                emit_sse({"type": "reasoning", "chunk": r_chunk})
                        if delta.get("content"):
                            emit_sse({"type": "content", "chunk": delta["content"]})
                        for tc in delta.get("tool_calls") or []:
                            idx = tc.get("index", 0)
                            if idx not in tool_calls_buf:
                                tool_calls_buf[idx] = {"id": tc.get("id") or f"call_{idx}", "name": "", "arguments": ""}
                            fn = tc.get("function") or {}
                            if fn.get("name"):
                                tool_calls_buf[idx]["name"] += fn["name"]
                            if fn.get("arguments"):
                                tool_calls_buf[idx]["arguments"] += fn["arguments"]
                                emit_sse(
                                    {
                                        "type": "tool_delta",
                                        "toolId": tool_calls_buf[idx]["id"],
                                        "name": tool_calls_buf[idx]["name"],
                                        "delta": fn["arguments"],
                                    }
                                )
                        if choice0.get("finish_reason") in ("stop", "length", "tool_calls", "function_call"):
                            break

                emitted_sigs = set()
                for tc in tool_calls_buf.values():
                    if tc["name"]:
                        try:
                            parsed_args = json.loads(tc["arguments"] or "{}")
                        except Exception:
                            parsed_args = {}
                        sig = f"{tc['name']}::{json.dumps(parsed_args, sort_keys=True, ensure_ascii=False)}"
                        if sig not in emitted_sigs:
                            emitted_sigs.add(sig)
                            emit_sse(
                                {
                                    "type": "tool_call",
                                    "toolCall": {"id": tc["id"], "name": tc["name"], "args": parsed_args},
                                }
                            )

            emit_sse({"type": "done"})
        except urllib.error.HTTPError as http_err:
            err_body = http_err.read().decode("utf-8", errors="replace")[:300]
            emit_sse({"type": "error", "error": f"HTTP {http_err.code}: {err_body}"})
        except Exception as exc:
            emit_sse({"type": "error", "error": str(exc)})
        finally:
            with ABORT_LOCK:
                ACTIVE_STREAM_ABORTS.pop(task_id, None)


def launch_desktop_window(url: str):
    """直接使用用户系统默认浏览器打开工作台（带完整地址栏与刷新按钮）。"""
    try:
        webbrowser.open(url, new=2)
    except Exception:
        pass


def main():
    global SERVER_BOUND_PORT
    port = 18765
    server = None
    for p in range(18765, 18800):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), AppRequestHandler)
            port = p
            SERVER_BOUND_PORT = p
            break
        except OSError:
            continue

    if server is None:
        print("[Error] 无法绑定本地端口 18765~18800")
        sys.exit(1)

    url = f"http://127.0.0.1:{port}"
    print("=" * 72)
    print("  AI 协作群聊工作台 (Python + SQLite 本地服务端已启动)")
    print(f"  本地安全地址: {url} (已启用 Host/Origin 校验 + 256-bit 会话令牌保护)")
    print(f"  本地 SQLite 数据库: {DB_PATH} (全量数据与免责协议签署状态唯一存储源)")
    print(f"  默认 Agent 授权工作区: {DEFAULT_WORKSPACE}")
    print("  提示: 关闭此终端窗口即可停止服务。")
    print("=" * 72)

    threading.Timer(0.6, lambda: launch_desktop_window(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在关闭服务...")
        server.server_close()


if __name__ == "__main__":
    main()
