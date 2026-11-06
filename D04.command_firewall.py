#!/usr/bin/env python3
"""
D04 · Pre-tool-use Hook —— 危险命令防火墙（Claude Code 钩子）
对应真实悬赏：[BOUNTY $100] HOOK: Pre-tool-use hook that blocks destructive bash commands
(https://github.com/claude-builders-bounty/claude-builders-bounty/issues/3)

验收标准（来自悬赏原帖，逐条实现）：
  [x] 符合 Claude Code hooks 格式（stdin JSON，exit code 协议）
  [x] 拦截：rm -rf / DROP TABLE / git push --force / TRUNCATE / 无 WHERE 的 DELETE FROM
  [x] 每次拦截记录到 ~/.claude/hooks/blocked.log：时间戳、被拦命令、项目路径
  [x] 给 Claude 显示清晰的拦截原因

用法（安装）：
  1. mkdir -p ~/.claude/hooks && cp D04.command_firewall.py ~/.claude/hooks/
  2. 在 ~/.claude/settings.json 注册（PreToolUse 匹配 Bash）：
     { "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [
         { "type": "command", "command": "python3 ~/.claude/hooks/D04.command_firewall.py" } ] } ] } }
  3. 独立测试：echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"cwd":"/tmp"}' | python3 D04.command_firewall.py

零依赖，纯标准库。退出码协议：0=放行，2=拦截（stderr 显示给 Claude）。
"""
import json
import os
import re
import sys
from datetime import datetime

LOG_PATH = os.path.expanduser("~/.claude/hooks/blocked.log")

# ---- 危险模式（对每类给出人话解释） ----------------------------------------
PATTERNS = [
    (re.compile(r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r|-r\s+-f|-f\s+-r)\b", re.I),
     "rm -rf 会递归强删目录且不进回收站，不可恢复。请先 ls 确认目标，或用 trash。"),
    (re.compile(r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b", re.I),
     "DROP TABLE/DATABASE 会直接删除整表数据。如确需执行，请先备份并改用带审批的迁移脚本。"),
    (re.compile(r"\bTRUNCATE\s+(TABLE\s+)?[\w.\"`]+\b", re.I),
     "TRUNCATE 会清空整表且不可回滚。请确认目标表，或改用 DELETE 加 LIMIT 分批。"),
    (re.compile(r"\bgit\s+push\b[^|;&\n]*(?:(?<![\w-])--force(?!-)|(?<![\w-])-f(?![\w-]))"),
     "git push --force 会覆盖远端历史，可能抹掉他人提交。请改用 --force-with-lease 并先 fetch。"),
]

DELETE_NO_WHERE = re.compile(r"\bDELETE\s+FROM\s+[\w.\"`]+(?![^;]*\bWHERE\b)", re.I | re.S)


def find_violation(command: str):
    """返回 (原因, 规则名) 或 (None, None)。"""
    for pat, reason in PATTERNS:
        if pat.search(command):
            return reason, pat.pattern
    if DELETE_NO_WHERE.search(command):
        return ("DELETE FROM 不带 WHERE 会删除全表数据。请加 WHERE 条件或先 SELECT 计数确认。",
                "DELETE FROM without WHERE")
    return None, None


def read_event():
    raw = sys.stdin.read()
    try:
        return json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        # 即使输入损坏也绝不崩溃：放行但记录（钩子必须永不阻断正常工作流）
        log("MALFORMED_STDIN", raw[:200])
        return {}


def log(command: str, cwd: str, rule: str = ""):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%dT%H:%M:%S%z")
    entry = json.dumps({"timestamp": ts, "command": command,
                        "project_path": cwd, "rule": rule}, ensure_ascii=False)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


def main():
    event = read_event()
    tool = event.get("tool_name", "")
    cmd = (event.get("tool_input") or {}).get("command", "")
    cwd = event.get("cwd") or event.get("project_path") or os.getcwd()

    # 只管 Bash 类工具；其他工具放行（钩子不该越权）
    if tool and tool not in ("Bash", "bash", "shell", "ExecuteCommand", "run_command"):
        sys.exit(0)
    if not cmd:
        sys.exit(0)

    reason, rule = find_violation(cmd)
    if reason is None:
        sys.exit(0)  # 放行

    log(cmd, cwd, rule)
    # 拦截：stderr 会作为反馈显示给 Claude（Claude Code 钩子协议）
    sys.stderr.write(
        f"[命令防火墙] 已拦截并记录到 {LOG_PATH}\n"
        f"被拦命令: {cmd}\n"
        f"拦截原因: {reason}\n"
        f"如确认必须执行，请人工在终端运行，不要让 Agent 绕过本钩子。\n"
    )
    # 同时尝试 JSON 双通道（新版协议），失败不影响 exit 2 协议
    try:
        sys.stdout.write(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }))
    except Exception:
        pass
    sys.exit(2)  # Claude Code：exit 2 = 阻断工具调用并把 stderr 喂给 Claude


if __name__ == "__main__":
    main()
