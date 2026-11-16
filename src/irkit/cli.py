from __future__ import annotations

import json
import os
import platform
import shlex
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer

from .board import case_context, review_card
from .evidence import initialize_case
from .store import Store, dumps
from .templates import MAIN, ROLE_TOOLS, ROLES, agent_definitions

app = typer.Typer(no_args_is_help=True, help="Claude 原生子 Agent 的本地日志调查工具")


def default_cases():
    if platform.system() == "Darwin":
        return Path.home() / "Library/Application Support/IRKit/cases"
    return Path.home() / ".local/share/irkit/cases"


def provider_configuration():
    """Reuse the user's model/auth configuration without enabling their hooks, tools or plugins.

    Secrets are only passed in the child environment, never written into the case workspace.
    Claude settings env normally overrides inherited environment; preserve that behavior here.
    """
    config_root = Path(os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude")))
    path = config_root / "settings.json"
    if not path.exists():
        return {}, None
    try:
        settings = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise ValueError("Cannot read Claude provider settings; check your settings.json") from exc
    permitted = {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_DEFAULT_OPUS_MODEL",
        "ANTHROPIC_DEFAULT_SONNET_MODEL",
        "ANTHROPIC_DEFAULT_HAIKU_MODEL",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "CLOUD_ML_REGION",
        "AWS_REGION",
        "AWS_PROFILE",
    }
    provider_env = {k: str(v) for k, v in settings.get("env", {}).items() if k in permitted}
    return provider_env, settings.get("model")


def configure_workspace(store):
    workspace = store.root / "workspace"
    (workspace / ".claude/agents").mkdir(parents=True, exist_ok=True)
    (workspace / "CLAUDE.md").write_text(MAIN, encoding="utf-8")
    config = {
        "mcpServers": {
            "ir": {"command": sys.executable, "args": ["-m", "irkit", "mcp", "--case", str(store.root)]}
        }
    }
    (workspace / ".mcp.json").write_text(dumps(config), encoding="utf-8")
    for name, prompt in ROLES.items():
        tools = ", ".join(f"mcp__ir__{t}" for t in ROLE_TOOLS[name])
        (workspace / ".claude/agents" / f"{name}.md").write_text(
            f"---\nname: {name}\ndescription: {agent_definitions()[name]['description']}\ntools: {tools}\n---\n{prompt}",
            encoding="utf-8",
        )
    (workspace / "agents.json").write_text(dumps(agent_definitions()), encoding="utf-8")
    settings = {
        "disableAllHooks": True,
        "enableAllProjectMcpServers": False,
        "permissions": {
            "allow": [
                "mcp__ir__*",
                "Agent(ir-prepare)",
                "Agent(ir-investigate)",
                "Agent(ir-synthesize)",
                "SendMessage",
                "TaskOutput",
                "TaskStop",
            ],
            "deny": ["Bash", "Read", "Write", "Edit", "WebFetch", "WebSearch", "Skill"],
        },
    }
    (workspace / "settings.json").write_text(dumps(settings), encoding="utf-8")
    return workspace


def launch_arguments(store, model=None, print_mode=False, budget=3.0):
    workspace = configure_workspace(store)
    executable = shutil.which("claude")
    if not executable:
        raise ValueError("Claude Code CLI not found. Install/login, then irkit resume CASE_DIR")
    args = [
        executable,
        "--strict-mcp-config",
        "--mcp-config",
        str(workspace / ".mcp.json"),
        "--setting-sources",
        "project",
        "--settings",
        str(workspace / "settings.json"),
        "--tools",
        "Agent,SendMessage,TaskOutput,TaskStop,AskUserQuestion",
        "--no-chrome",
        "--disable-slash-commands",
        "--agents",
        dumps(agent_definitions()),
        "--append-system-prompt",
        MAIN,
    ]
    provider_env, configured_model = provider_configuration()
    if selected_model := model or configured_model:
        args += ["--model", selected_model]
    if print_mode:
        if budget <= 0:
            raise ValueError("Budget must be positive")
        args += [
            "--print",
            "--output-format",
            "json",
            "--max-budget-usd",
            str(budget),
            "--permission-mode",
            "dontAsk",
        ]
    args += [
        "从 case_context 读取案件背景和输入。按既定流程使用原生子 Agent 完成有界调查，"
        "把阶段报告保存到本案件 reports。已有任务时先确认交付和未决项，不无故重复数据化。"
    ]
    env = dict(os.environ)
    env.update(provider_env)
    env.update(
        {
            "CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH": "1",
            "CLAUDE_CODE_MAX_CONCURRENT_SUBAGENTS": "4",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            # Keep native subagent calls attached to the main turn through synthesis.
            "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS": "1",
            # Defense in depth for CLI versions that still background a call.
            "CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS": "0",
            "MCP_TIMEOUT": "30000",
            "MCP_TOOL_TIMEOUT": "360000",
        }
    )
    return args, env, workspace


def launch(store, model=None, print_mode=False, budget=3.0):
    args, env, workspace = launch_arguments(store, model, print_mode, budget)
    typer.echo(f"案件：{store.root}\n日志片段将通过 Claude 当前配置的模型服务进行分析。", err=True)
    os.chdir(workspace)
    os.execvpe(args[0], args, env)


@app.command()
def investigate(
    log_dir: Annotated[Path, typer.Argument(exists=True, file_okay=False, readable=True)],
    background: str = "",
    background_file: Annotated[Path | None, typer.Option(exists=True, dir_okay=False)] = None,
    cases_dir: Path | None = None,
    prepare_only: bool = False,
    model: str | None = None,
    print_mode: Annotated[bool, typer.Option("--print", help="非交互模式，返回 Claude JSON 输出")] = False,
    budget: Annotated[float, typer.Option(help="仅 --print 的模型预算美元上限")] = 3.0,
):
    """复制登记日志，生成案件工作区并启动 Claude。背景可为空。"""
    if background and background_file:
        raise typer.BadParameter("Use --background or --background-file, not both")
    if background_file:
        background = background_file.read_text(encoding="utf-8")
    if len(background) > 30000:
        raise typer.BadParameter("Background exceeds 30000 characters")
    try:
        store = initialize_case(log_dir, cases_dir or default_cases(), background)
        configure_workspace(store)
        if prepare_only:
            typer.echo(
                dumps(
                    {
                        "case_dir": str(store.root),
                        "counts": store.counts(),
                        "resume": f"uv run irkit resume {shlex.quote(str(store.root))}",
                    }
                )
            )
            return
        launch(store, model, print_mode, budget)
    except (ValueError, OSError, RuntimeError) as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def resume(
    case_dir: Path,
    model: str | None = None,
    print_mode: Annotated[bool, typer.Option("--print")] = False,
    budget: float = 3.0,
):
    """根据持久黑板开启 Claude 会话继续案件。不是外部 Agent 调度器。"""
    try:
        launch(Store(case_dir), model, print_mode, budget)
    except (ValueError, OSError, RuntimeError) as exc:
        raise typer.BadParameter(str(exc)) from exc


@app.command()
def inspect(case_dir: Path):
    """只读查看案件概况。"""
    typer.echo(json.dumps(case_context(Store(case_dir)), ensure_ascii=False, indent=2))


@app.command()
def review(case_dir: Path, card_id: str, revision: int, decision: str, note: str):
    """人工将卡片标记为 reviewed 或 rejected。模型工具无此操作。"""
    typer.echo(dumps(review_card(Store(case_dir), card_id, revision, decision, note)))


@app.command()
def mcp(case: Annotated[Path, typer.Option()]):
    """启动绑定一个案件的 stdio MCP 服务（由 Claude 调用）。"""
    from .mcpserver import build_server

    build_server(case).run(transport="stdio")


@app.command()
def doctor():
    """检查本地依赖和 Python 执行层，不调用模型、不读取凭据。"""
    import tempfile

    from .execution import run_process

    with tempfile.TemporaryDirectory(prefix="irkit-doctor-") as directory:
        result = run_process(
            [sys.executable, "-I", "-c", "import duckdb; print('local worker ready')"], Path(directory), timeout=10
        )
    typer.echo(
        dumps(
            {
                "python": sys.version.split()[0],
                "claude": shutil.which("claude"),
                "platform": platform.system(),
                "execution": result,
            }
        )
    )
    if result["status"] != "succeeded":
        raise typer.Exit(1)


@app.command()
def web(case_dir: Path, port: int = 8765):
    """在本机浏览器查看案件、Agent 事件、卡片及证据。"""
    from .web import serve

    serve(case_dir, port)
