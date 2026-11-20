from datetime import datetime
from html import escape
import os
from pathlib import Path
import tempfile

from app_state import default_data_directory


def generate_report(result, output_directory=None, metadata=None):
    """Generate a local HTML security report from a scanner result."""
    if not isinstance(result, dict):
        raise TypeError("Scan result must be a dictionary.")

    suspicious = result.get("suspicious", [])
    if not isinstance(suspicious, list):
        raise TypeError("Scan results must contain a list of findings.")

    metadata = metadata if isinstance(metadata, dict) else {}
    files_scanned = result.get(
        "scanned",
        result.get("files_scanned", result.get("total", 0))
    )

    reports_dir = Path(
        output_directory or default_data_directory() / "reports"
    )
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().astimezone()
    filename = reports_dir / (
        f"Scan_Report_{timestamp.strftime('%Y%m%d_%H%M%S_%f')}.html"
    )

    counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }
    rows = []
    retained_finding_count = 0
    for file in suspicious:
        if not isinstance(file, dict):
            continue
        retained_finding_count += 1
        risk = str(file.get("risk", "Unknown"))
        if risk in counts:
            counts[risk] += 1
        reasons = file.get("reasons", [])
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        reason_text = "; ".join(str(reason) for reason in reasons)
        rows.append(
            f"""
            <tr class="{escape(risk.lower())}">
                <td>{escape(str(file.get('name', 'Unknown')))}</td>
                <td>{escape(str(file.get('extension', '')))}</td>
                <td><strong>{escape(risk)}</strong>
                    ({escape(str(file.get('risk_score', 'N/A')))}/100)</td>
                <td>{escape(str(file.get('path', '')))}</td>
                <td>{escape(str(file.get('detection_type', 'Unknown')))}</td>
                <td>{escape(reason_text)}</td>
                <td><code>{escape(str(file.get('hash', 'N/A')))}</code></td>
            </tr>
            """
        )

    finding_count = result.get("finding_count", retained_finding_count)
    if not isinstance(finding_count, int) or finding_count < retained_finding_count:
        raise ValueError("Scan result contains an invalid finding count.")
    findings_truncated = bool(result.get("findings_truncated", False))
    cancelled = bool(result.get("cancelled", False))

    if not rows:
        rows.append(
            '<tr><td colspan="7">No suspicious files detected.</td></tr>'
        )

    scan_type_value = str(metadata.get("scan_type", "Unknown"))
    scan_type = escape(scan_type_value)
    started_at = escape(str(metadata.get("started_at", "Unknown")))
    duration = escape(str(metadata.get("duration", "Unknown")))
    error_count = int(result.get("error_count", 0) or 0)
    exclusions = metadata.get("exclusions", [])
    if not isinstance(exclusions, list):
        exclusions = []
    exclusion_rows = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in exclusions
    ) or "<li>None</li>"
    scan_errors = result.get("errors", [])
    if not isinstance(scan_errors, list):
        scan_errors = []
    error_rows = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in scan_errors
    ) or "<li>No scan errors.</li>"
    score = None
    if not error_count and not findings_truncated and not cancelled:
        score = max(
            0,
            100
            - counts["Critical"] * 40
            - counts["High"] * 25
            - counts["Medium"] * 12
            - counts["Low"] * 5
        )
    score_label = f"{score}/100" if score is not None else "Unavailable"
    if cancelled:
        scan_status = "Cancelled"
        completion_note = (
            '<p class="muted">Results are partial because the scan was cancelled; '
            "a security score is unavailable.</p>"
        )
    elif findings_truncated:
        scan_status = "Incomplete"
        completion_note = (
            '<p class="muted">Security score unavailable because finding details '
            "were truncated.</p>"
        )
    elif error_count:
        scan_status = "Incomplete"
        completion_note = (
            f'<p class="muted">Security score unavailable because the scan had '
            f'{error_count} error(s).</p>'
        )
    else:
        scan_status = "Complete"
        completion_note = ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="scan-type" content="{escape(scan_type_value, quote=True)}">
    <meta name="scan-status" content="{scan_status}">
    <meta name="finding-count" content="{finding_count}">
    <title>IT Security Scanner Report</title>
    <style>
        :root {{ color-scheme: dark; }}
        body {{ margin: 0; padding: 32px; background: #0b1220; color: #e7eefb;
            font: 14px/1.5 "Segoe UI", Arial, sans-serif; }}
        main {{ max-width: 1440px; margin: auto; }}
        h1 {{ margin: 0; font-size: 28px; color: #fff; }}
        h2 {{ margin: 0 0 14px; font-size: 17px; }}
        .muted {{ color: #9aaac2; }}
        .card {{ background: #111c2e; border: 1px solid #23334d;
            border-radius: 12px; padding: 20px; margin-bottom: 18px; }}
        .metrics {{ display: grid; grid-template-columns: repeat(auto-fit,minmax(150px,1fr));
            gap: 12px; margin-top: 20px; }}
        .metric {{ padding: 14px; border-radius: 8px; background: #172338; }}
        .metric strong {{ display: block; font-size: 22px; }}
        .metric span {{ color: #9aaac2; }}
        .critical td:first-child, .critical strong {{ color: #ff6b6b; }}
        .high td:first-child, .high strong {{ color: #ff8a65; }}
        .medium td:first-child, .medium strong {{ color: #ffca66; }}
        .low td:first-child, .low strong {{ color: #8dbbff; }}
        .table-wrap {{ overflow-x: auto; }}
        table {{ border-collapse: collapse; width: 100%; min-width: 1000px; }}
        th, td {{ border-bottom: 1px solid #263650; padding: 10px;
            text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
        th {{ color: #b7c8e3; background: #172338; }}
        code {{ font-size: 11px; }}
        ul {{ padding-left: 20px; }}
        @media print {{ body {{ background: #fff; color: #172338; padding: 12px; }}
            .card {{ background: #fff; border-color: #ccd5e2; }} }}
    </style>
</head>
<body>
<main>
    <div class="card">
        <p class="muted">LOCAL SECURITY ASSESSMENT</p>
        <h1>IT Security Scanner</h1>
        <p class="muted">Generated {escape(timestamp.strftime('%Y-%m-%d %H:%M:%S %Z'))}</p>
        <div class="metrics">
            <div class="metric"><strong>{escape(str(files_scanned))}</strong><span>Files scanned</span></div>
            <div class="metric"><strong>{finding_count}</strong><span>Findings</span></div>
            <div class="metric"><strong>{score_label}</strong><span>Security score</span></div>
            <div class="metric"><strong>{error_count}</strong><span>Scan errors</span></div>
            <div class="metric"><strong>{scan_type}</strong><span>Scan type</span></div>
            <div class="metric"><strong>{duration}</strong><span>Duration</span></div>
        </div>
        <p><b>Started:</b> {started_at}</p>
        <p><b>Severity:</b>
            Critical {counts['Critical']} · High {counts['High']} ·
            Medium {counts['Medium']} · Low {counts['Low']}
        </p>
        {completion_note}
        {
            f'<p class="muted">Only {retained_finding_count} of {finding_count} finding details are included because the result limit was reached.</p>'
            if findings_truncated
            else ""
        }
    </div>

    <div class="card">
        <h2>Threat findings ({finding_count})</h2>
        <div class="table-wrap">
            <table>
                <thead><tr>
                    <th>File</th><th>Extension</th><th>Severity</th>
                    <th>Path</th><th>Detection</th><th>Indicators</th><th>SHA-256</th>
                </tr></thead>
                <tbody>{''.join(rows)}</tbody>
            </table>
        </div>
    </div>
    <div class="card">
        <h2>Excluded locations</h2>
        <ul>{exclusion_rows}</ul>
        <p class="muted">Generated locally by IT Security Scanner. No scan data was uploaded.</p>
    </div>
    <div class="card">
        <h2>Scan errors</h2>
        <ul>{error_rows}</ul>
    </div>
</main>
</body>
</html>
"""

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".scan-report-",
        suffix=".tmp",
        dir=reports_dir
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            file.write(html)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_name, filename)
    except Exception:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    return str(filename)
