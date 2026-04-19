#!/usr/bin/env python3
"""Generate HTML reports from markdown files."""
import re
from pathlib import Path

CSS_STYLE = """
@media print {
    body { margin: 0; }
    @page { margin: 2cm; }
}
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    font-size: 11pt;
    line-height: 1.6;
    color: #333;
    max-width: 900px;
    margin: 0 auto;
    padding: 2rem;
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
h3 { color: #333; margin-top: 1em; }
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
th { background-color: #f5f5f5; font-weight: bold; }
tr:nth-child(even) { background-color: #fafafa; }
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
pre code { background: none; padding: 0; }
hr { border: none; border-top: 1px solid #ddd; margin: 2em 0; }
strong { color: #000; }
.print-instructions {
    background: #fffde7;
    border: 1px solid #ffc107;
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 2rem;
}
@media print { .print-instructions { display: none; } }
"""

def simple_md_to_html(md_content: str) -> str:
    """Simple markdown to HTML conversion."""
    html = md_content

    # Code blocks
    html = re.sub(r'```(\w*)\n(.*?)```', r'<pre><code>\2</code></pre>', html, flags=re.DOTALL)

    # Headers
    html = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
    html = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
    html = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', html, flags=re.MULTILINE)

    # Bold and inline code
    html = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', html)
    html = re.sub(r'`([^`]+)`', r'<code>\1</code>', html)

    # Horizontal rules
    html = re.sub(r'^---+$', r'<hr>', html, flags=re.MULTILINE)

    # Tables
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

    return '\n'.join(new_lines)

def convert_table(lines: list) -> str:
    """Convert markdown table to HTML."""
    if len(lines) < 2:
        return '\n'.join(lines)

    html = '<table>\n<thead><tr>'
    header_cells = [c.strip() for c in lines[0].strip('|').split('|')]
    for cell in header_cells:
        html += f'<th>{cell}</th>'
    html += '</tr></thead>\n<tbody>\n'

    for line in lines[2:]:
        if line.strip():
            cells = [c.strip() for c in line.strip('|').split('|')]
            html += '<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>\n'

    return html + '</tbody>\n</table>'

def md_to_html_file(md_path: Path, html_path: Path):
    """Convert markdown file to HTML."""
    md_content = md_path.read_text()
    html_content = simple_md_to_html(md_content)

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{md_path.stem.replace('_', ' ')}</title>
    <style>{CSS_STYLE}</style>
</head>
<body>
    <div class="print-instructions">
        <strong>To save as PDF:</strong> Press Cmd+P (Mac) or Ctrl+P (Windows), then select "Save as PDF" as the destination.
    </div>
    {html_content}
</body>
</html>"""

    html_path.write_text(full_html)
    print(f"Generated: {html_path}")

def main():
    reports_dir = Path(__file__).parent

    md_files = ["TEST_REPORT.md", "BUG_REPORT.md", "VALIDATION_REPORT.md", "TEST_REPORT_v2.md", "BUG_REPORT_v2.md"]

    for md_file in md_files:
        md_path = reports_dir / md_file
        if md_path.exists():
            html_path = reports_dir / md_file.replace(".md", ".html")
            md_to_html_file(md_path, html_path)

if __name__ == "__main__":
    main()
