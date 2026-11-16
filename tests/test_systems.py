"""system_overview groups sources by the top directory of their original_path."""

from irkit.evidence import initialize_case
from irkit.systems import system_overview


def test_grouping_by_top_directory(tmp_path):
    logs = tmp_path / "logs"
    (logs / "ucenter/nginx").mkdir(parents=True)
    (logs / "ucenter/application").mkdir(parents=True)
    (logs / "风险策略系统/tomcat").mkdir(parents=True)
    (logs / "ucenter/nginx/access.log").write_text("a\nb\nc\n")
    (logs / "ucenter/application/app.log").write_text("x\ny\n")
    (logs / "风险策略系统/tomcat/catalina.out").write_text("z\n")
    case = initialize_case(logs, tmp_path / "cases", "")
    systems = {s["system"]: s for s in system_overview(case)["systems"]}
    assert set(systems) == {"ucenter", "风险策略系统"}
    assert systems["ucenter"]["sources"] == 2
    assert systems["风险策略系统"]["sources"] == 1
    # The larger system sorts first (volume is reported, not used as priority).
    assert system_overview(case)["systems"][0]["system"] == "ucenter"


def test_tool_exposed_to_all_roles():
    from irkit.templates import ROLE_TOOLS

    assert all("system_overview" in tools for tools in ROLE_TOOLS.values())
