#!/usr/bin/env python3
"""Generate PDF reports from markdown files using simple HTML conversion."""
import re
from pathlib import Path

try:
    from weasyprint import HTML, CSS
    HAS_WEASYPRINT = True
except ImportError:
    HAS_WEASYPRINT = False
    print("WeasyPrint not available, skipping PDF generation")

CSS_STYLE = """
@page {
    margin: 2cm;
    size: A4;
}
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
    max-width: 100%;
}
h1 {
    color: #000;
    border-bottom: 2px solid #11F250;
    padding-bottom: 0.3em;
    margin-top: 1.5em;
}
h2 {
    color: #222;
    border-bottom: 1px solid #ddd;
    padding-bottom: 0.2em;
    margin-top: 1.2em;
}
h3 {
    color: #333;
    margin-top: 1em;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
    font-size: 10pt;
}
th, td {
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
}
th {
    background-color: #f5f5f5;
    font-weight: bold;
}
tr:nth-child(even) {
    background-color: #fafafa;
}
code {
    background-color: #f4f4f4;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'SF Mono', Monaco, 'Courier New', monospace;
    font-size: 9pt;
}
pre {
    background-color: #f4f4f4;
    padding: 12px;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 9pt;
    line-height: 1.4;
    white-space: pre-wrap;
}
pre code {
    background: none;
    padding: 0;
}
blockquote {
    border-left: 4px solid #11F250;
    margin: 1em 0;
    padding-left: 1em;
    color: #666;
}
hr {
    border: none;
    border-top: 1px solid #ddd;
    margin: 2em 0;
}
strong {
    color: #000;
}
"""

def simple_md_to_html(md_content: str) -> str:
    """Simple markdown to HTML conversion."""
    html = md_content

    # Code blocks (```...```)
    html = re.sub(r'```(\w*)\n(.*?)```', r'<pre><code>\2</code></pre>', html, flags=re.DOTALL)

    # Headers
    html = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)

    # Bold
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)

    # Inline code
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)

    # Horizontal rules
    html = re.sub(r'^---+$', r'<hr>', html, flags=re.MULTILINE)

    # Tables (simple conversion)
    lines = html.split('\n')
    in_table = False
    new_lines = []
    table_lines = []

    for line in lines:
        if '|' in line and not line.strip().startswith('<'):
            if not in_table:
                in_table = True
                table_lines = []
            table_lines.append(line)
        else:
            if in_table:
                new_lines.append(convert_table(table_lines))
                in_table = False
                table_lines = []
            new_lines.append(line)

    if in_table:
        new_lines.append(convert_table(table_lines))

    html = '\n'.join(new_lines)

    # Paragraphs (simple - wrap remaining text blocks)
    html = re.sub(r'\n\n+', r'\n\n', html)

    return html

def convert_table(lines: list) -> str:
    """Convert markdown table to HTML."""
    if len(lines) < 2:
        return '\n'.join(lines)

    html = '<table>\n'

    # Header row
    header_cells = [c.strip() for c in lines[0].strip('|').split('|')]
    html += '<thead><tr>'
    for cell in header_cells:
        html += f'<th>{cell}</th>'
    html += '</tr></thead>\n'

    # Body rows (skip separator line)
    html += '<tbody>\n'
    for line in lines[2:]:
        if line.strip():
            cells = [c.strip() for c in line.strip('|').split('|')]
            html += '<tr>'
            for cell in cells:
                html += f'<td>{cell}</td>'
            html += '</tr>\n'
    html += '</tbody>\n'

    html += '</table>'
    return html

def md_to_pdf(md_path: Path, pdf_path: Path):
    """Convert markdown file to PDF."""
    if not HAS_WEASYPRINT:
        print(f"Skipping {md_path} - WeasyPrint not available")
        return

    md_content = md_path.read_text()
    html_content = simple_md_to_html(md_content)

    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>{md_path.stem}</title>
    </head>
    <body>
        {html_content}
    </body>
    </html>
    """

    HTML(string=full_html).write_pdf(
        pdf_path,
        stylesheets=[CSS(string=CSS_STYLE)]
    )
    print(f"Generated: {pdf_path}")

def main():
    reports_dir = Path(__file__).parent

    md_files = [
        "TEST_REPORT.md",
        "BUG_REPORT.md",
        "VALIDATION_REPORT.md"
    ]

    for md_file in md_files:
        md_path = reports_dir / md_file
        if md_path.exists():
            pdf_path = reports_dir / md_file.replace(".md", ".pdf")
            md_to_pdf(md_path, pdf_path)
        else:
            print(f"Not found: {md_path}")

if __name__ == "__main__":
    main()
