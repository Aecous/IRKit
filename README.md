# IRKit · 日志应急响应工作台

IRKit 用于从本地日志还原安全事件。提供日志目录和可选背景，Claude Code 主 Agent 派发数据准备、取证、补证和综合复核，最终报告可以逐条回查到事件卡、查询和原始日志。

## 架构

```mermaid
flowchart LR
    Web["Web 工作台 / CLI"] --> Main["Claude Code 主 Agent"]
    Web --> Raw["日志副本与 SHA-256"]
    Main --> Prep["数据准备子 Agent"]
    Main --> Find["取证与补证子 Agent"]
    Main --> Review["综合复核子 Agent"]
    Raw --> Prep
    Prep --> Data[("DuckDB 数据集")]
    Data --> Find
    Prep --> Board[("SQLite 案件黑板")]
    Find <--> Board
    Main <--> Board
    Review <--> Board
    Review --> Report["可回查的调查报告"]
    Board --> Views["事件卡 · 来源行为 · 运行记录"]
```

**Claude Code 原生子 Agent 负责分工，SQLite 黑板负责交接。** 主 Agent 传递任务问题、ID 和数据范围。子 Agent 使用独立上下文，通过 MCP 读写当前案件的产物，返回摘要和引用。

| 角色 | 工作 |
| --- | --- |
| 主 Agent | 根据日志覆盖和已知线索拆分任务，将关键证据缺口交给取证子 Agent 补查。 |
| `ir-prepare` | 识别格式、时间和字段，批量入库或编写转换脚本，将数据行与原文位置关联。 |
| `ir-investigate` | 用 SQL 查询、抽样回查原文，记录事件、前因、后果和待验证问题。 |
| `ir-synthesize` | 复核事件关系、统计口径和关键证据，生成阶段报告或最终报告。 |

黑板保存任务、数据集目录、事件卡、检查和报告引用。事件卡记录带证据的观察，检查记录查询覆盖、结果和证据缺口。来源 IP 及其检查引用保存在事件卡里。同来源的其他操作随事件一起分析，重要的新行为进入普通补证流程。Web 的「来源行为」和报告第四章都由卡片与检查聚合，可查看匹配字段、时间、环境和查询引用。旧案件的来源复查记录仍可查看。

最终报告包含五章：事件背景与调查范围、事件结论与影响评估、攻击时间线与攻击路径、攻击来源与具体行为、证据缺口与处置建议。关键补证未完成时可以保存阶段报告。报告通过证据引用区分原始观察、聚合统计和推断，实际影响以可用的业务证据为准。

## 安装与模型配置

依赖 Python 3.12+、uv 和已配置模型服务的 Claude Code。执行层使用 macOS 和 Linux 共用的 POSIX 子进程实现，目前端到端验证在 macOS 完成。

```sh
git clone https://github.com/Aecous/IRKit.git
cd IRKit
uv sync --locked
uv run irkit doctor
```

CLI 和 Web 都从本机 Claude Code 环境取得模型配置。IRKit 读取 `~/.claude/settings.json` 中与模型服务相关的配置。设置了 `CLAUDE_CONFIG_DIR` 时，使用该目录下的 `settings.json`。同名环境变量以此文件中的设置为准。配置示例中的值是占位符，请在本机配置文件中替换。

```json
{
  "env": {
    "ANTHROPIC_API_KEY": "YOUR_API_KEY"
  }
}
```

使用兼容网关时，可设置 `ANTHROPIC_BASE_URL` 和 `ANTHROPIC_MODEL`，并按网关要求选择 `ANTHROPIC_API_KEY` 或 `ANTHROPIC_AUTH_TOKEN`。也可在启动 IRKit 的 shell 中设置这些变量。修改 shell 变量后需重启 Web 进程，修改 Claude 配置文件后由下一轮调查读取。CLI 的 `--model` 可指定本轮模型。

`irkit doctor` 验证 Claude CLI 和本地 Python/DuckDB 执行能力，无需连接模型服务。密钥保存在本机 Claude 配置或进程环境中。把真实日志、数据库、报告和会话记录存放在仓库之外。云模型会收到调查所需的日志片段和查询结果，应选择符合数据处理要求的模型服务。

## 使用 Web 工作台

1. 首次启动时登记一个日志目录作为工作台入口。`--prepare-only` 复制登记日志并打印 `case_dir`，适合在网页里再发起模型调查。

   ```sh
   uv run irkit investigate "/绝对路径/日志目录" --prepare-only
   uv run irkit web "/上一步返回的/case_dir" --port 8765
   ```

2. 打开 [本地工作台](http://127.0.0.1:8765)，选择项目，点击「下发调查任务」。背景可以留空，由 Agent 自主定位可疑活动。任务窗口提供模型预算，初始值为 8 美元。

   | 方式 | 用法 |
   | --- | --- |
   | 分析新的日志目录 | 提供日志目录，执行日志登记、数据准备和调查。已有入口案件未运行时，可选「继续指定调查」直接使用这批副本。 |
   | 继续指定调查 | 沿用所选调查的事件卡和检查。有可用数据集时可以勾选「跳过数据初始化」。 |
   | 复用入库数据，重新独立分析 | 复用所选调查已发布的数据集，从空白分析状态开始。 |

3. 在「会话过程」展开主 Agent 与子 Agent，查看工具调用和调查进度。「事件卡片」和「来源行为」可以回查检查与查询。「报告」展示最终报告或阶段报告。

Web 按项目、调查、运行组织记录。工作台一次运行一个后台调查，调查中的取证子 Agent 可并行工作。首次登记会复制输入，请预留磁盘空间，并将日志与样本、脚本等非日志材料分别存放。

## 使用 CLI

```sh
uv run irkit investigate "/绝对路径/日志目录" \
  --background "请核对昨晚异常活动的时间线、入口与影响范围"
uv run irkit inspect "/绝对路径/案件目录"
uv run irkit resume "/绝对路径/案件目录"
```

`--background-file` 可从文本文件读取背景。初次调查可通过 `--cases-dir` 指定存储位置。默认位置为 macOS 的 `~/Library/Application Support/IRKit/cases/`，以及 Linux 的 `~/.local/share/irkit/cases/`。自动化调用可加 `--print --budget 8` 以启用非交互模式并指定模型预算。

## 数据与执行

- 原始日志按 SHA-256 登记。转换器通过 `records()` 读取日志，通过 `emit()` 记录事件与文件位置。`SOURCE_PATHS` 支持格式不明时编写专用解析器。仓库附带 Nginx、Java、IIS 和 Windows 事件 XML 合成样例。
- 已发布的 DuckDB 数据集在查询中以只读方式连接。查询可以在自己的 `analysis.duckdb` 中建立派生表，最后一条语句的结果分页保存。大批量 JSONL 可通过流式路径入库。
- Python 转换和 SQL 在本地子进程执行，使用当前系统用户的操作权限。转换脚本与查询可以访问该用户有权访问的文件和网络。模型凭据环境变量不会传给这些子进程。
- 核心入口见 [Agent 工作流](src/irkit/templates.py)、[MCP 工具](src/irkit/mcpserver.py)、[案件存储](src/irkit/store.py)、[来源行为聚合](src/irkit/source_leads.py)和 [报告模板](src/irkit/report_template.py)。

```sh
uv run python scripts/demo.py
uv run pytest -q
node --test tests/*.mjs
uv run ruff check src tests scripts
```

`demo.py` 用固定合成数据验证从转换、原文回查到报告的工具链，无需调用模型。运行后可将返回的 `case` 路径传给 `irkit web` 查看结果。
