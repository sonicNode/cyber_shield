"""
Report Generator - Creates HTML reports from threat data
"""

import pandas as pd
import datetime
import os

_LOCAL_REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
_CLOUD_REPORTS_DIR = os.path.join("/tmp", "cyber_shield_reports")

def _get_reports_dir():
    """Pick writable directory for reports."""
    try:
        os.makedirs(_LOCAL_REPORTS_DIR, exist_ok=True)
        test_file = os.path.join(_LOCAL_REPORTS_DIR, ".write_test")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return _LOCAL_REPORTS_DIR
    except (OSError, PermissionError):
        os.makedirs(_CLOUD_REPORTS_DIR, exist_ok=True)
        return _CLOUD_REPORTS_DIR

REPORTS_DIR = _get_reports_dir()


class ReportGenerator:

    def __init__(self):
        os.makedirs(REPORTS_DIR, exist_ok=True)

    # ─────────────────────────────────────────────────────────────────
    def executive_summary(self, df: pd.DataFrame) -> str:
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        total  = len(df)
        high   = len(df[df['risk_level'] == 'High'])   if total > 0 else 0
        medium = len(df[df['risk_level'] == 'Medium']) if total > 0 else 0
        low    = len(df[df['risk_level'] == 'Low'])    if total > 0 else 0
        avg_sc = round(df['risk_score'].mean(), 1)     if total > 0 else 0

        top5_rows = ""
        if total > 0:
            for _, r in df.nlargest(5, 'risk_score').iterrows():
                badge_color = "#ff4d4d" if r['risk_level'] == 'High' else ("#ffa500" if r['risk_level'] == 'Medium' else "#00cc66")
                top5_rows += f"""
                <tr>
                    <td>{r['threat_name']}</td>
                    <td>{r['asset_type']}</td>
                    <td><span style="color:{badge_color};font-weight:bold">{r['risk_level']}</span></td>
                    <td>{r['risk_score']:.1f}</td>
                    <td>{r['timestamp'][:10]}</td>
                </tr>"""

        asset_breakdown = ""
        if total > 0:
            ab = df.groupby('asset_type')['risk_score'].mean().sort_values(ascending=False)
            for asset, score in ab.items():
                pct = int((score / 100) * 200)
                color = "#ff4d4d" if score >= 66 else ("#ffa500" if score >= 33 else "#00cc66")
                asset_breakdown += f"""
                <div style="margin:10px 0">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px">
                        <span>{asset}</span><span style="color:{color}">{score:.1f}</span>
                    </div>
                    <div style="background:#2d3748;border-radius:4px;height:8px">
                        <div style="background:{color};width:{min(pct,200)}px;height:8px;border-radius:4px"></div>
                    </div>
                </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cyber Shield – Executive Summary</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 40px; }}
  .header {{ background: linear-gradient(135deg,#667eea,#764ba2); padding: 40px; border-radius: 16px; margin-bottom: 32px; }}
  .header h1 {{ font-size: 2.2rem; margin-bottom: 8px; }}
  .header p  {{ opacity: .8; font-size: 1rem; }}
  .kpi-grid  {{ display: grid; grid-template-columns: repeat(5,1fr); gap: 16px; margin-bottom: 32px; }}
  .kpi-card  {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 24px; text-align: center; }}
  .kpi-card .val {{ font-size: 2.4rem; font-weight: 700; margin-bottom: 4px; }}
  .kpi-card .lbl {{ color: #8b949e; font-size: .85rem; }}
  .section   {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 28px; margin-bottom: 24px; }}
  .section h2 {{ font-size: 1.3rem; margin-bottom: 20px; color: #e6edf3; border-bottom: 1px solid #30363d; padding-bottom: 12px; }}
  table      {{ width: 100%; border-collapse: collapse; }}
  th         {{ background: #21262d; color: #8b949e; font-weight: 600; padding: 12px; text-align: left; font-size: .85rem; text-transform: uppercase; letter-spacing: .05em; }}
  td         {{ padding: 12px; border-bottom: 1px solid #21262d; font-size: .9rem; }}
  tr:hover td {{ background: #1c2128; }}
  .footer    {{ text-align: center; color: #8b949e; font-size: .8rem; margin-top: 32px; padding-top: 16px; border-top: 1px solid #30363d; }}
  @media print {{ body {{ background: white; color: black; }} }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡️ Cyber Shield – Executive Summary</h1>
  <p>Context-Aware Threat Intelligence Scoring System &nbsp;|&nbsp; Report Generated: {now}</p>
</div>

<div class="kpi-grid">
  <div class="kpi-card"><div class="val" style="color:#667eea">{total}</div><div class="lbl">Total Threats</div></div>
  <div class="kpi-card"><div class="val" style="color:#ff4d4d">{high}</div><div class="lbl">🔴 High Risk</div></div>
  <div class="kpi-card"><div class="val" style="color:#ffa500">{medium}</div><div class="lbl">🟠 Medium Risk</div></div>
  <div class="kpi-card"><div class="val" style="color:#00cc66">{low}</div><div class="lbl">🟢 Low Risk</div></div>
  <div class="kpi-card"><div class="val" style="color:#e6edf3">{avg_sc}</div><div class="lbl">Avg Risk Score</div></div>
</div>

<div class="section">
  <h2>Top 5 Critical Threats</h2>
  <table>
    <thead><tr><th>Threat Name</th><th>Asset Type</th><th>Risk Level</th><th>Score</th><th>Date</th></tr></thead>
    <tbody>{top5_rows if top5_rows else '<tr><td colspan="5" style="text-align:center;color:#8b949e">No data</td></tr>'}</tbody>
  </table>
</div>

<div class="section">
  <h2>Risk by Asset Type (Average Score)</h2>
  {asset_breakdown if asset_breakdown else '<p style="color:#8b949e">No data available</p>'}
</div>

<div class="section">
  <h2>Key Recommendations</h2>
  <ul style="padding-left:20px;line-height:2">
    <li>🔴 <strong>High Risk threats</strong> require immediate isolation and emergency patching within 24 hours.</li>
    <li>🟠 <strong>Medium Risk threats</strong> should be addressed within 72 hours with increased monitoring.</li>
    <li>🟢 <strong>Low Risk threats</strong> can be scheduled for the next maintenance window.</li>
    <li>📌 Prioritize <strong>Database</strong> and <strong>Server</strong> assets — highest context weight.</li>
    <li>🔐 Apply Zero Trust principles for all external and DMZ environments.</li>
    <li>📊 Run weekly AI model retraining as new threats are logged.</li>
  </ul>
</div>

<div class="footer">
  Cyber Shield | Context-Aware Threat Intelligence Scoring System | CYL66 | Dept. of CSE (Cyber Security)
</div>
</body></html>"""

        path = os.path.join(REPORTS_DIR, f"executive_summary_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    # ─────────────────────────────────────────────────────────────────
    def detailed_report(self, df: pd.DataFrame) -> str:
        now   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        total = len(df)

        rows = ""
        if total > 0:
            for _, r in df.sort_values('risk_score', ascending=False).iterrows():
                badge_color = "#ff4d4d" if r['risk_level']=='High' else ("#ffa500" if r['risk_level']=='Medium' else "#00cc66")
                rows += f"""
                <tr>
                    <td>{r.get('timestamp','')[:16]}</td>
                    <td>{r.get('threat_name','')}</td>
                    <td>{r.get('threat_category','')}</td>
                    <td>{r.get('asset_type','')}</td>
                    <td>{r.get('environment','')}</td>
                    <td>{r.get('user_role','')}</td>
                    <td>{r.get('severity','')}</td>
                    <td>{r.get('likelihood','')}</td>
                    <td>{r.get('impact','')}</td>
                    <td>{r.get('context_factor',0):.2f}</td>
                    <td><strong style="color:{badge_color}">{r.get('risk_score',0):.1f}</strong></td>
                    <td><span style="color:{badge_color};font-weight:bold">{r.get('risk_level','')}</span></td>
                </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cyber Shield – Detailed Threat Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 40px; }}
  .header {{ background: linear-gradient(135deg,#1a1f2e,#252d3d); border: 1px solid #30363d; padding: 32px; border-radius: 16px; margin-bottom: 32px; }}
  .header h1 {{ font-size: 1.8rem; margin-bottom: 8px; }}
  .meta {{ color: #8b949e; font-size: .9rem; }}
  .formula {{ background: #21262d; border-left: 4px solid #667eea; padding: 16px 24px; border-radius: 8px; margin-bottom: 28px; font-family: monospace; font-size: 1rem; }}
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .82rem; }}
  th {{ background: #21262d; color: #8b949e; font-weight: 600; padding: 10px 12px; text-align: left; white-space: nowrap; font-size: .75rem; text-transform: uppercase; letter-spacing: .05em; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; white-space: nowrap; }}
  tr:hover td {{ background: #1c2128; }}
  .footer {{ text-align:center; color:#8b949e; font-size:.8rem; margin-top:32px; padding-top:16px; border-top:1px solid #30363d; }}
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Cyber Shield – Detailed Threat Report</h1>
  <p class="meta">Generated: {now} &nbsp;|&nbsp; Total Records: {total} &nbsp;|&nbsp; CYL66 | Dept. of CSE (Cyber Security)</p>
</div>

<div class="formula">
  📐 <strong>Scoring Formula:</strong> &nbsp; Risk Score = (Severity + Likelihood + Impact) × Context Factor &nbsp;|&nbsp; Normalized to 0–100
</div>

<div class="table-wrap">
<table>
  <thead>
    <tr>
      <th>Timestamp</th><th>Threat Name</th><th>Category</th>
      <th>Asset</th><th>Environment</th><th>User Role</th>
      <th>Sev</th><th>Like</th><th>Imp</th>
      <th>Ctx Factor</th><th>Risk Score</th><th>Level</th>
    </tr>
  </thead>
  <tbody>
    {rows if rows else '<tr><td colspan="12" style="text-align:center;color:#8b949e;padding:32px">No threat data available</td></tr>'}
  </tbody>
</table>
</div>

<div class="footer">
  Cyber Shield | Context-Aware Threat Intelligence Scoring System | CYL66
</div>
</body></html>"""

        path = os.path.join(REPORTS_DIR, f"detailed_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path
