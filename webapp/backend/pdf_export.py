"""Render a generated markdown assessment report to a printable PDF.

Reports live on disk as ``{reports_dir}/{report_id}.md`` (produced by the
graph engine / batch processor elsewhere in this repo). This module converts
that markdown to a self-contained black-on-white HTML document — styled as a
compliance/leadership document, not a themed web page — and rasterizes it to
PDF bytes with WeasyPrint.

Style conventions are ported (principles only, not the literal CSS vars —
this is static server-rendered HTML, no custom properties involved) from
Chinook_Cyber/cyber-planning-web-app's print-mode approach
(src/lib/exportBrief.ts's ``@media print`` block and the sans/mono font
pairing + tightened heading letter-spacing from src/app/globals.css):
force black text on white regardless of any viewer theme, avoid breaking
table rows/sections across a page boundary, and set
``print-color-adjust: exact`` so nothing gets silently desaturated by the
renderer.
"""

from __future__ import annotations

import os
import re
from html import escape as html_escape

import markdown as _markdown
from weasyprint import HTML

REPORT_STYLE = """
  :root { color-scheme: light; }
  * { box-sizing: border-box; }

  html, body {
    margin: 0;
    padding: 0;
    background: #ffffff;
    color: #111111;
    -webkit-print-color-adjust: exact;
    print-color-adjust: exact;
    color-adjust: exact;
  }

  body {
    font-family: "Inter", "Helvetica Neue", Arial, system-ui, -apple-system,
      "Segoe UI", Roboto, sans-serif;
    font-size: 11pt;
    line-height: 1.55;
  }

  .report {
    max-width: 100%;
    margin: 0 auto;
    padding: 0.4in 0.5in;
  }

  h1, h2, h3, h4, h5, h6 {
    color: #000000;
    letter-spacing: -0.02em;
    font-weight: 700;
    margin: 1.1em 0 0.4em;
    break-after: avoid;
    page-break-after: avoid;
  }

  h1 { font-size: 20pt; margin-top: 0; }
  h2 { font-size: 15pt; border-bottom: 1px solid #cccccc; padding-bottom: 0.15em; }
  h3 { font-size: 12.5pt; }
  h4 { font-size: 11.5pt; }

  p { margin: 0.5em 0; }

  strong { color: #000000; font-weight: 700; }
  em { color: #333333; }

  a { color: #111111; text-decoration: underline; }

  ul, ol { margin: 0.4em 0; padding-left: 1.4em; }
  li { margin: 0.15em 0; }

  /* Markdown "---" horizontal rules — render as a clean thin gray section
     divider, never a jarring double line. */
  hr {
    border: none;
    border-top: 1px solid #cccccc;
    margin: 1.4em 0;
  }

  /* Inline code and bracketed framework IDs like [T1558.003] / [D3-SPP] —
     monospace so they read as distinct identifiers, not prose. */
  code, .framework-id {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo,
      Consolas, "Liberation Mono", monospace;
    font-size: 0.92em;
    background: #f2f2f2;
    border: 1px solid #e0e0e0;
    border-radius: 3px;
    padding: 0.05em 0.35em;
    color: #111111;
  }

  pre {
    font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo,
      Consolas, "Liberation Mono", monospace;
    font-size: 0.9em;
    background: #f6f6f6;
    border: 1px solid #e0e0e0;
    border-radius: 4px;
    padding: 0.7em 0.9em;
    overflow-x: auto;
    white-space: pre-wrap;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  pre code {
    background: none;
    border: none;
    padding: 0;
  }

  /* Tables (e.g. the Affected Hosts table) — simple bordered cells, light
     header-row background, never split a row across a page. */
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.8em 0 1.1em;
    font-size: 10pt;
    break-inside: avoid;
    page-break-inside: avoid;
  }
  th, td {
    border: 1px solid #cccccc;
    padding: 0.4em 0.6em;
    text-align: left;
    vertical-align: top;
  }
  thead th {
    background: #eeeeee;
    color: #000000;
    font-weight: 700;
    break-after: avoid;
    page-break-after: avoid;
  }
  tr {
    break-inside: avoid;
    page-break-inside: avoid;
  }

  blockquote {
    margin: 0.6em 0;
    padding: 0.2em 1em;
    border-left: 3px solid #cccccc;
    color: #333333;
  }

  @page {
    size: letter;
    margin: 0.6in 0.55in;
  }
"""

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{title}</title>
<style>{style}</style>
</head>
<body>
<div class="report">
{body}
</div>
</body>
</html>"""


def _disable_raw_html(markdown_text: str) -> str:
    """Render raw HTML from reports as text, not executable/rendered markup.

    Findings and LLM prose are untrusted. Python-Markdown intentionally
    preserves raw HTML, which is inappropriate before WeasyPrint receives the
    resulting document. Markdown syntax remains available; only tag-looking
    sequences are neutralized.
    """
    return re.sub(r"<(?=[!/A-Za-z])", "&lt;", markdown_text).replace(">", "&gt;")


def _local_only_url_fetcher(url: str, *args, **kwargs):
    """Reports are self-contained; deny remote/file resource fetches in PDF rendering."""
    if url.startswith("data:"):
        # No current report assets use data URLs, but they are safe to support
        # if a future renderer embeds a local image deliberately.
        from weasyprint.urls import default_url_fetcher
        return default_url_fetcher(url, *args, **kwargs)
    raise ValueError(f"External resource fetching is disabled for report PDFs: {url}")


def render_markdown_pdf(markdown_text: str, *, title: str = "MITRE CSD-H Report") -> bytes:
    """Render immutable run-scoped Markdown without a legacy reports path."""
    body_html = _markdown.markdown(
        _disable_raw_html(markdown_text),
        extensions=["tables", "fenced_code"],
    )
    full_html = HTML_TEMPLATE.format(title=html_escape(title, quote=True), style=REPORT_STYLE, body=body_html)
    return HTML(string=full_html, url_fetcher=_local_only_url_fetcher).write_pdf()


def render_report_pdf(report_id: str, reports_dir: str) -> bytes:
    """Render ``{reports_dir}/{report_id}.md`` to PDF bytes.

    Raises FileNotFoundError (uncaught, for the caller to turn into a 404)
    if the source markdown file does not exist.
    """
    md_path = os.path.join(reports_dir, f"{report_id}.md")
    if not os.path.isfile(md_path):
        raise FileNotFoundError(
            f"Report '{report_id}' not found: no such file {md_path}"
        )

    with open(md_path, "r", encoding="utf-8") as f:
        md_text = f.read()

    return render_markdown_pdf(md_text, title=report_id)
