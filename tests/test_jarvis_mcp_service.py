"""Static checks for deploy/jarvis-mcp.service (cwd-independent)."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SERVICE_PATH = REPO_ROOT / "deploy" / "jarvis-mcp.service"

REQUIRED_SNIPPETS = [
    "[Unit]",
    "Description=Jarvis Obsidian MCP Server",
    "After=network.target",
    "[Service]",
    "User=ccuser",
    "WorkingDirectory=/home/ccuser/obsidian-web-mcp",
    "EnvironmentFile=/home/ccuser/.jarvis-mcp.env",
    "ExecStart=/home/ccuser/.local/bin/uv run vault-mcp",
    "Restart=always",
    "RestartSec=5",
    "[Install]",
    "WantedBy=multi-user.target",
]

FORBIDDEN_NAME_PARTS = ("KEY", "TOKEN", "SECRET", "PASSWORD")


def test_jarvis_mcp_service_definition():
    assert SERVICE_PATH.is_file(), f"missing unit file: {SERVICE_PATH}"
    text = SERVICE_PATH.read_text(encoding="utf-8")

    for snippet in REQUIRED_SNIPPETS:
        assert snippet in text, f"missing directive/snippet: {snippet!r}"

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("Environment="):
            continue
        # Environment=VAR=value  or  Environment="VAR=value"
        assignment = stripped.removeprefix("Environment=").strip().strip("\"'")
        name = assignment.split("=", 1)[0]
        upper = name.upper()
        for part in FORBIDDEN_NAME_PARTS:
            assert part not in upper, (
                f"Environment= must not name secrets inline: {line!r}"
            )
