from pathlib import Path
import json
import re
import sys
from urllib.parse import urlparse

DANGEROUS_PATTERNS = [
    ("download_to_shell", re.compile(r"(curl|wget).*\|\s*(sh|bash|zsh|python|node)", re.I)),
    ("encoded_payload", re.compile(r"(base64\s+(-d|--decode)|powershell.*(-enc|-encodedcommand)|atob\s*\()", re.I)),
    ("shell_exec", re.compile(r"\b(eval|exec|os\.system|subprocess|child_process\.exec)\b", re.I)),
    ("dangerous_delete", re.compile(r"\brm\s+-rf\b|\bdel\s+/[sq]\b", re.I)),
    ("permission_change", re.compile(r"\bchmod\s+\+x\b", re.I)),
    ("network_fetch", re.compile(r"\b(curl|wget|Invoke-WebRequest|iwr|fetch)\b", re.I)),
]

KNOWN_MCP_HOSTS = {
    "github.com",
    "api.github.com",
    "mcp.context7.com",
}

def finding(file, severity, rule, detail):
    return {
        "file": str(file),
        "severity": severity,
        "rule": rule,
        "detail": detail,
    }

def scan_text_patterns(path, text):
    results = []
    for i, line in enumerate(text.splitlines(), start=1):
        for name, pattern in DANGEROUS_PATTERNS:
            if pattern.search(line):
                results.append(finding(path, "medium", name, f"line {i}: {line.strip()[:180]}"))
    return results

def load_json(path):
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception as e:
        return None, str(e)

def scan_vscode_tasks(repo):
    path = repo / ".vscode" / "tasks.json"
    if not path.exists():
        return []

    data = load_json(path)
    if isinstance(data, tuple):
        return [finding(path, "high", "invalid_json", data[1])]

    results = []
    tasks = data.get("tasks", []) if isinstance(data, dict) else []

    for idx, task in enumerate(tasks):
        label = task.get("label", f"task[{idx}]")
        task_type = task.get("type", "")
        command = str(task.get("command", ""))
        args = " ".join(map(str, task.get("args", [])))
        combined = f"{command} {args}"

        run_on = task.get("runOptions", {}).get("runOn")
        if run_on == "folderOpen":
            results.append(finding(path, "high", "autorun_task", f"{label} runs on folder open"))

        if task_type == "shell":
            results.append(finding(path, "medium", "shell_task", f"{label}: {combined[:180]}"))

        results.extend(scan_text_patterns(path, combined))

    return results

def urls_in_value(value):
    text = json.dumps(value)
    return re.findall(r"https?://[^\s\"']+", text)

def scan_cursor_mcp(repo):
    path = repo / ".cursor" / "mcp.json"
    if not path.exists():
        return []

    data = load_json(path)
    if isinstance(data, tuple):
        return [finding(path, "high", "invalid_json", data[1])]

    results = [finding(path, "info", "project_mcp_config", "Repo contains project-level Cursor MCP config")]

    for url in urls_in_value(data):
        parsed = urlparse(url)
        host = parsed.hostname or ""

        if parsed.scheme != "https":
            results.append(finding(path, "high", "non_https_mcp_url", url))

        if host not in KNOWN_MCP_HOSTS:
            results.append(finding(path, "medium", "unknown_mcp_host", host or url))

        if host in {"localhost", "127.0.0.1", "0.0.0.0"} or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
            results.append(finding(path, "high", "local_or_ip_mcp_url", url))

    text = json.dumps(data)
    results.extend(scan_text_patterns(path, text))

    for risky_cmd in ["npx", "uvx", "python", "python3", "node", "bash", "sh", "powershell"]:
        if re.search(rf'"command"\s*:\s*"{re.escape(risky_cmd)}"', text, re.I):
            results.append(finding(path, "medium", "mcp_exec_command", f"MCP server uses command: {risky_cmd}"))

    return results

def scan_package_json(repo):
    path = repo / "package.json"
    if not path.exists():
        return []

    data = load_json(path)
    if isinstance(data, tuple):
        return [finding(path, "high", "invalid_json", data[1])]

    results = []
    scripts = data.get("scripts", {}) if isinstance(data, dict) else {}

    for name, cmd in scripts.items():
        if name in {"preinstall", "install", "postinstall", "prepare"}:
            results.append(finding(path, "high", "install_hook", f"{name}: {cmd[:180]}"))
        results.extend(scan_text_patterns(path, str(cmd)))

    return results

def scan_generic_files(repo):
    targets = [
        "Makefile",
        "Dockerfile",
        "docker-compose.yml",
        ".github/workflows",
    ]

    results = []

    for target in targets:
        path = repo / target
        if path.is_file():
            results.extend(scan_text_patterns(path, path.read_text(errors="ignore")))
        elif path.is_dir():
            for file in path.rglob("*"):
                if file.is_file():
                    results.extend(scan_text_patterns(file, file.read_text(errors="ignore")))

    return results

def scan_repo(repo_path):
    repo = Path(repo_path).resolve()
    results = []
    results.extend(scan_vscode_tasks(repo))
    results.extend(scan_cursor_mcp(repo))
    results.extend(scan_package_json(repo))
    results.extend(scan_generic_files(repo))
    return results

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "."
    results = scan_repo(repo)

    if not results:
        print("No suspicious repo automation patterns found.")
        sys.exit(0)

    for r in results:
        print(f"[{r['severity'].upper()}] {r['file']} :: {r['rule']} :: {r['detail']}")

    high_count = sum(1 for r in results if r["severity"] == "high")
    sys.exit(2 if high_count else 1)