"""Readable, standalone HTML exports from generated Markdown; no JavaScript or remote assets."""

import html
import re
from pathlib import Path
from urllib.parse import quote, unquote

from markdown_it import MarkdownIt

CSS = """
:root { color-scheme: light; font-family: system-ui, -apple-system, "PingFang SC", sans-serif; color: #1d2939; background: #f3f5f8; }
body { max-width: 980px; margin: 32px auto; padding: 48px 56px; background: white; line-height: 1.85; }
h1 { font-size: 30px; line-height: 1.4; } h2 { margin-top: 44px; border-bottom: 2px solid #e3eaf4; padding-bottom: 10px; }
h3 { margin-top: 28px; } p { overflow-wrap: anywhere; } a { color: #2458a6; text-decoration: none; }
a:hover { text-decoration: underline; } table { width: 100%; border-collapse: collapse; font-size: 14px; margin: 20px 0; }
th, td { border: 1px solid #dce3ec; padding: 10px 12px; vertical-align: top; text-align: left; overflow-wrap: anywhere; }
th { background: #edf2f9; } code { background: #f3f5f8; padding: 2px 4px; } pre { padding: 16px; background: #f3f5f8; overflow: auto; font-size: 13px; line-height: 1.5; }
nav { padding: 14px 20px; background: #f6f8fc; display: flex; flex-wrap: wrap; gap: 16px; font-size: 14px; }
@media(max-width:720px) { body { margin: 0; padding: 22px; } table { display: block; overflow-x: auto; } }
@media print { body { margin: 0; max-width: none; padding: 0; } nav { display:none; } h2,h3 { break-after: avoid; } tr { break-inside: avoid; } }
"""


def html_document(text, title, markdown_links=None):
    parser = MarkdownIt("commonmark", {"html": False}).enable("table")
    tokens = parser.parse(text)
    nav = []
    for index, token in enumerate(tokens):
        if token.type == "heading_open" and token.tag == "h2":
            name = tokens[index + 1].content
            key = "e-" + name[2:] if re.fullmatch(r"E-\d+", name) else f"section-{len(nav) + 1}"
            token.attrSet("id", key)
            if re.match(r"[1-5]\. ", name):
                nav.append((key, name))
        if token.children:
            for child in token.children:
                if child.type == "link_open":
                    href = child.attrGet("href") or ""
                    path, separator, fragment = href.partition("#")
                    target = (markdown_links or {}).get(unquote(path))
                    if target is not None:
                        child.attrSet(
                            "href", quote(target, safe="/") + (separator + fragment if separator else "")
                        )
    body = parser.renderer.render(tokens, parser.options, {})
    navigation = (
        "<nav>" + "".join(f'<a href="#{key}">{html.escape(name)}</a>' for key, name in nav) + "</nav>"
        if nav
        else ""
    )
    return (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        + "<title>"
        + html.escape(title)
        + "</title><style>"
        + CSS
        + "</style></head><body>"
        + navigation
        + body
        + "</body></html>\n"
    )


def write_html_pair(main, appendix):
    main, appendix = Path(main), Path(appendix)
    links = {main.name: main.with_suffix(".html").name, appendix.name: appendix.with_suffix(".html").name}
    for path in (main, appendix):
        out = path.with_suffix(".html")
        out.write_text(html_document(path.read_text(encoding="utf-8"), path.stem, links), encoding="utf-8")
        out.chmod(0o600)
