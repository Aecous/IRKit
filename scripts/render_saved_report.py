#!/usr/bin/env python3
"""Render authored existing findings without launching Agents or rerunning investigation."""

import argparse
import json
import re
from pathlib import Path

from irkit.report import render_report
from irkit.report_export import write_html_pair
from irkit.report_template import validate
from irkit.store import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", type=Path)
    parser.add_argument("content", type=Path, help="JSON with assessment/report_content/gaps/next_questions")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--name", default="调查报告")
    parser.add_argument(
        "--final",
        action="store_true",
        help="Require the normal final-delivery gates; default saves available findings only",
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[\w.\-\u4e00-\u9fff ]{1,100}", args.name) or args.name in {".", ".."}:
        parser.error("name must be a simple filename stem")
    store = Store(args.case)
    data = json.loads(args.content.read_text(encoding="utf-8"))
    validate(store, data["report_content"], require_narrative=True)
    artifact = render_report(
        store,
        data["assessment"],
        data.get("gaps", []),
        data.get("next_questions", []),
        delivery="final" if args.final else "progress",
        report_content=data["report_content"],
    )
    output = args.output_dir.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    main_file = output / f"{args.name}.md"
    appendix_file = output / f"{args.name}.evidence.md"
    old_appendix_name = Path(artifact["appendix_path"]).name
    main_file.write_text(
        store.path(artifact["path"]).read_text().replace(old_appendix_name, appendix_file.name),
        encoding="utf-8",
    )
    appendix_file.write_text(store.path(artifact["appendix_path"]).read_text(), encoding="utf-8")
    for path in (main_file, appendix_file):
        path.chmod(0o600)
    write_html_pair(main_file, appendix_file)
    print(
        json.dumps(
            dict(
                report_id=artifact["id"],
                delivery=artifact["delivery"],
                files=[
                    str(p)
                    for p in (
                        main_file,
                        main_file.with_suffix(".html"),
                        appendix_file,
                        appendix_file.with_suffix(".html"),
                    )
                ],
            ),
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
