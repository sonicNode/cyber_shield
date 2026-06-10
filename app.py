"""
Cyber Shield - Context-Aware Threat Intelligence Scoring System
Main Streamlit Dashboard
"""
import html
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import datetime
import json
import os
from pathlib import Path
from scan_intelligence import show_scan_intelligence
from scoring_engine import ContextAwareScoringEngine
from website_checker import full_scan, heuristic_scan, severity_from_score
from ai_engine import AIThreatAnalyzer
from data_manager import ThreatDataManager
from report_generator import ReportGenerator

# ─── Page Config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Cyber Shield | Threat Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
:root {
    --bg: #07110f;
    --panel: #101b18;
    --panel2: #14241f;
    --line: #2c4a41;
    --text: #edf8f4;
    --muted: #93aaa2;
    --green: #58e6a7;
    --cyan: #4cd7e8;
    --amber: #f6bc45;
    --red: #ff6370;
}

.stApp {
    background:
        linear-gradient(90deg, rgba(88,230,167,0.035) 1px, transparent 1px),
        linear-gradient(180deg, rgba(88,230,167,0.03) 1px, transparent 1px),
        radial-gradient(circle at 80% 5%, rgba(76,215,232,0.16), transparent 35%),
        linear-gradient(135deg, #07110f, #0d1815 55%, #11160f);
    background-size: 44px 44px, 44px 44px, auto, auto;
    color: var(--text);
}

[data-testid="stHeader"] {
    background: transparent;
}

.main .block-container {
    max-width: 1320px;
    padding-top: 1.4rem;
    padding-bottom: 3rem;
}

section[data-testid="stSidebar"] {
    background: #07100e;
    border-right: 1px solid var(--line);
}

section[data-testid="stSidebar"] * {
    color: var(--text);
}

h1, h2, h3 {
    color: var(--text);
    letter-spacing: 0;
}

p, li, label {
    color: var(--muted);
}

hr {
    border-color: rgba(147,170,162,0.2);
}

.war-room-hero {
    background:
        linear-gradient(135deg, rgba(88,230,167,0.13), rgba(76,215,232,0.06)),
        #101b18;
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 18px;
}

.war-room-kicker {
    color: var(--green);
    font-size: 12px;
    font-weight: 900;
    letter-spacing: 2px;
    text-transform: uppercase;
}

.war-room-title {
    color: var(--text);
    font-size: 44px;
    font-weight: 900;
    line-height: 1.05;
    margin-top: 6px;
}

.war-room-subtitle {
    color: var(--muted);
    max-width: 850px;
    margin-top: 8px;
    font-size: 15px;
}

.action-card {
    background: rgba(16, 27, 24, 0.94);
    border: 1px solid var(--line);
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 12px;
}

.action-label {
    color: var(--muted);
    font-size: 11px;
    font-weight: 900;
    letter-spacing: 1px;
    text-transform: uppercase;
}

.action-value {
    color: var(--text);
    font-size: 24px;
    font-weight: 900;
    margin-top: 5px;
}

div[data-testid="metric-container"] {
    background: rgba(16, 27, 24, 0.94);
    border: 1px solid var(--line);
    border-left: 4px solid var(--green);
    border-radius: 8px;
    padding: 15px;
}

.stButton > button,
.stDownloadButton > button {
    background: linear-gradient(135deg, #17382f, #14535c);
    color: var(--text);
    border: 1px solid #347463;
    border-radius: 8px;
    font-weight: 800;
}

.stButton > button:hover,
.stDownloadButton > button:hover {
    border-color: var(--green);
    color: white;
    transform: translateY(-1px);
}

input, textarea {
    background-color: #0d1714 !important;
    color: var(--text) !important;
    border: 1px solid var(--line) !important;
    border-radius: 8px !important;
}

div[data-baseweb="select"] > div {
    background-color: #0d1714;
    border-color: var(--line);
    border-radius: 8px;
}

button[role="tab"] {
    background: #0d1714;
    border: 1px solid var(--line);
    border-radius: 8px;
    color: var(--muted);
}

button[role="tab"][aria-selected="true"] {
    background: #17382f;
    color: var(--green);
    border-color: var(--green);
}

div[data-testid="stExpander"] {
    background: rgba(16, 27, 24, 0.92);
    border: 1px solid var(--line);
    border-radius: 8px;
}

[data-testid="stDataFrame"] {
    border: 1px solid var(--line);
    border-radius: 8px;
    overflow: hidden;
}

.alert-badge-high {
    background: rgba(255,99,112,0.14);
    border-left: 4px solid var(--red);
    border-radius: 8px;
    padding: 10px 16px;
    margin: 6px 0;
    color: #ffc4ca;
}

.alert-badge-medium {
    background: rgba(246,188,69,0.14);
    border-left: 4px solid var(--amber);
    border-radius: 8px;
    padding: 10px 16px;
    margin: 6px 0;
    color: #ffe3a6;
}

.alert-badge-low {
    background: rgba(88,230,167,0.14);
    border-left: 4px solid var(--green);
    border-radius: 8px;
    padding: 10px 16px;
    margin: 6px 0;
    color: #c4ffe3;
}
</style>
""", unsafe_allow_html=True)

# ─── Initialize Engines ────────────────────────────────────────────────────────
@st.cache_resource
def init_engines():
    dm = ThreatDataManager()
    engine = ContextAwareScoringEngine()
    ai = AIThreatAnalyzer()
    rg = ReportGenerator()
    return dm, engine, ai, rg

dm, engine, ai_analyzer, report_gen = init_engines()

# ─── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Cyber Shield")
    st.markdown("**Context-Aware Threat Intelligence**")
    st.divider()
    
    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "➕ Add Threat", "🌐 Website Checker", "🤖 AI Analysis","🌍 Geo Threat Map","🧩 Response Playbook", "📄 Reports", "🗄️ Threat Database","🗂️ Incident Case File","🕸️ Attack Path Visualizer", "🕵️ Scan Intelligence"],
        index=0
    )
    
    st.divider()
    st.markdown("### ⚙️ Filter Settings")
    
    severity_filter = st.multiselect(
        "Risk Level",
        ["High", "Medium", "Low"],
        default=["High", "Medium", "Low"]
    )
    
    asset_filter = st.multiselect(
        "Asset Type",
        ["Server", "Workstation", "Database", "Network Device", "Cloud Instance"],
        default=["Server", "Workstation", "Database", "Network Device", "Cloud Instance"]
    )
    
    date_range = st.date_input(
        "Date Range",
        value=(datetime.date.today() - datetime.timedelta(days=30), datetime.date.today())
    )
    
    st.divider()
    st.caption("v1.0.0 | Cyber Shield Lab | CYL66")

# ─── Load & Filter Data ────────────────────────────────────────────────────────
df = dm.get_threats()
if len(df) > 0:
    if severity_filter:
        df = df[df['risk_level'].isin(severity_filter)]
    if asset_filter:
        df = df[df['asset_type'].isin(asset_filter)]


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
if "Dashboard" in page:
    st.markdown(f"""
    <div class="war-room-hero">
        <div class="war-room-kicker">Live Threat Operations</div>
        <div class="war-room-title">Cyber Shield </div>
        <div class="war-room-subtitle">
            Real-time threat intelligence, risk scoring, and mitigation planning.
            Last updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    
    all_df = dm.get_threats()
    
    # ── KPI Metrics ────────────────────────────────────────────────────────────
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total = len(all_df)
    high_c = len(all_df[all_df['risk_level'] == 'High']) if total > 0 else 0
    med_c  = len(all_df[all_df['risk_level'] == 'Medium']) if total > 0 else 0
    low_c  = len(all_df[all_df['risk_level'] == 'Low']) if total > 0 else 0
    avg_score = round(all_df['risk_score'].mean(), 1) if total > 0 else 0
    
    with col1:
        st.metric("Total Threats", total, delta=f"+{min(3, total)} today")
    with col2:
        st.metric("🔴 High Risk", high_c, delta=None)
    with col3:
        st.metric("🟠 Medium Risk", med_c, delta=None)
    with col4:
        st.metric("🟢 Low Risk", low_c, delta=None)
    with col5:
        st.metric("Avg Risk Score", avg_score, delta=None)
    
    st.divider()
    
    if len(all_df) == 0:
        st.info("📭 No threat data yet. Go to **➕ Add Threat** to log your first threat.")
    else:
        # ── Charts Row 1 ───────────────────────────────────────────────────────
        col_a, col_b = st.columns([1, 1])
        
        with col_a:
            st.markdown("### Risk Level Distribution")
            risk_counts = all_df['risk_level'].value_counts().reset_index()
            risk_counts.columns = ['Risk Level', 'Count']
            color_map = {'High': '#ff4d4d', 'Medium': '#ffa500', 'Low': '#00cc66'}
            fig_pie = px.pie(
                risk_counts, values='Count', names='Risk Level',
                color='Risk Level', color_discrete_map=color_map,
                hole=0.4
            )
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#e6edf3', margin=dict(t=20, b=20, l=20, r=20),
                legend=dict(bgcolor='rgba(0,0,0,0)')
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        
        with col_b:
            st.markdown("### Risk Scores by Asset Type")
            asset_avg = all_df.groupby('asset_type')['risk_score'].mean().reset_index()
            asset_avg.columns = ['Asset Type', 'Avg Risk Score']
            fig_bar = px.bar(
                asset_avg, x='Asset Type', y='Avg Risk Score',
                color='Avg Risk Score',
                color_continuous_scale=['#00cc66', '#ffa500', '#ff4d4d'],
                range_color=[0, 100]
            )
            fig_bar.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#e6edf3', margin=dict(t=20, b=20, l=20, r=20),
                xaxis=dict(gridcolor='#2d3748'), yaxis=dict(gridcolor='#2d3748'),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        
        # ── Charts Row 2 ───────────────────────────────────────────────────────
        col_c, col_d = st.columns([2, 1])
        
        with col_c:
            st.markdown("### Threat Timeline (Risk Score Over Time)")
            timeline_df = all_df.copy()
            timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'])
            timeline_df = timeline_df.sort_values('timestamp')
            
            color_map2 = {'High': '#ff4d4d', 'Medium': '#ffa500', 'Low': '#00cc66'}
            fig_scatter = px.scatter(
                timeline_df, x='timestamp', y='risk_score',
                color='risk_level', color_discrete_map=color_map2,
                size='risk_score', hover_data=['threat_name', 'asset_type'],
                title=""
            )
            fig_scatter.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#e6edf3', margin=dict(t=10, b=20, l=20, r=20),
                xaxis=dict(gridcolor='#2d3748'), yaxis=dict(gridcolor='#2d3748'),
                legend=dict(bgcolor='rgba(0,0,0,0)')
            )
            st.plotly_chart(fig_scatter, use_container_width=True)
        
        with col_d:
            st.markdown("### Top 5 Critical Threats")
            top5 = all_df.nlargest(5, 'risk_score')[['threat_name', 'risk_score', 'risk_level']]
            for _, row in top5.iterrows():
                lvl = row['risk_level']
                css_class = f"alert-badge-{lvl.lower()}"
                st.markdown(
                    f'<div class="{css_class}"><strong>{row["threat_name"]}</strong>'
                    f'<br>Score: {row["risk_score"]:.1f} | {lvl}</div>',
                    unsafe_allow_html=True
                )
        
        # ── Heatmap: Severity × Asset ──────────────────────────────────────────
        st.markdown("### Risk Heatmap: Asset Type × Threat Category")
        pivot = all_df.pivot_table(
            values='risk_score', index='asset_type',
            columns='threat_category', aggfunc='mean', fill_value=0
        )
        if not pivot.empty:
            fig_heat = px.imshow(
                pivot, color_continuous_scale=['#0d1117', '#ffa500', '#ff4d4d'],
                aspect='auto', text_auto='.1f'
            )
            fig_heat.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#e6edf3', margin=dict(t=20, b=20, l=20, r=20)
            )
            st.plotly_chart(fig_heat, use_container_width=True)
        
        # ── Recent Threats Table ───────────────────────────────────────────────
        st.markdown("### Recent Threat Log")
        display_cols = ['timestamp', 'threat_name', 'asset_type', 'risk_level',
                        'risk_score', 'severity', 'likelihood', 'impact']
        recent = all_df.sort_values('timestamp', ascending=False).head(15)[display_cols]
        
        def color_risk(val):
            if val == 'High':   return 'background-color: #3d0000; color: #ff9999'
            if val == 'Medium': return 'background-color: #2d1a00; color: #ffcc80'
            if val == 'Low':    return 'background-color: #002d1a; color: #80ffb4'
            return ''
        
        styled = recent.style.applymap(color_risk, subset=['risk_level'])
        st.dataframe(styled, use_container_width=True, height=350)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: ADD THREAT
# ══════════════════════════════════════════════════════════════════════════════
elif "Add Threat" in page:
    st.markdown("# ➕ Log New Threat")
    st.markdown("*Manually input threat data for risk scoring*")
    st.divider()
    
    with st.form("add_threat_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Threat Details")
            threat_name = st.text_input("Threat Name *", placeholder="e.g. SQL Injection Attack")
            threat_category = st.selectbox(
                "Threat Category *",
                ["Malware", "Phishing", "SQL Injection", "DDoS", "Ransomware",
                 "Insider Threat", "Zero-Day Exploit", "Brute Force", "Man-in-the-Middle", "Other"]
            )
            description = st.text_area("Description", placeholder="Describe the threat...", height=100)
            source_ip = st.text_input("Source IP (optional)", placeholder="e.g. 192.168.1.100")
            cve_id = st.text_input("CVE ID (optional)", placeholder="e.g. CVE-2024-1234")
        
        with col2:
            st.markdown("### Scoring Parameters")
            severity   = st.slider("Severity (1-10)",   1, 10, 5, help="How severe is the threat itself?")
            likelihood  = st.slider("Likelihood (1-10)", 1, 10, 5, help="How likely is it to be exploited?")
            impact      = st.slider("Impact (1-10)",     1, 10, 5, help="Potential damage if exploited?")
            
            st.markdown("### Context Parameters")
            asset_type  = st.selectbox(
                "Target Asset Type *",
                ["Server", "Workstation", "Database", "Network Device", "Cloud Instance", "Mobile Device"]
            )
            user_role   = st.selectbox("Affected User Role", ["Admin", "Standard User", "Guest", "Service Account"])
            environment = st.selectbox("Environment", ["Internal", "External", "DMZ", "Cloud"])
        
        submitted = st.form_submit_button("🔍 Calculate Risk Score & Save", use_container_width=True)
        
        if submitted and threat_name:
            result = engine.calculate_risk(
                severity=severity, likelihood=likelihood, impact=impact,
                asset_type=asset_type, user_role=user_role, environment=environment
            )
            
            threat_record = {
                "threat_name": threat_name,
                "threat_category": threat_category,
                "description": description,
                "source_ip": source_ip,
                "cve_id": cve_id,
                "severity": severity,
                "likelihood": likelihood,
                "impact": impact,
                "asset_type": asset_type,
                "user_role": user_role,
                "environment": environment,
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "context_factor": result["context_factor"],
                "timestamp": datetime.datetime.now().isoformat()
            }
            
            dm.add_threat(threat_record)
            
            # Show result
            st.divider()
            st.markdown("## 📊 Risk Assessment Result")
            
            r1, r2, r3, r4 = st.columns(4)
            with r1:
                st.metric("Risk Score", f"{result['risk_score']:.1f} / 100")
            with r2:
                lvl = result['risk_level']
                color = "🔴" if lvl == "High" else ("🟠" if lvl == "Medium" else "🟢")
                st.metric("Risk Level", f"{color} {lvl}")
            with r3:
                st.metric("Context Factor", f"{result['context_factor']:.2f}x")
            with r4:
                base = (severity + likelihood + impact)
                st.metric("Base Score", f"{base} / 30")
            
            st.markdown(f"**Formula:** Risk = (Severity + Likelihood + Impact) × Context Factor")
            st.markdown(f"**Calculation:** `({severity} + {likelihood} + {impact}) × {result['context_factor']:.2f} = {result['risk_score']:.1f}`")
            
            # Gauge chart
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=result['risk_score'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Risk Score", 'font': {'color': '#e6edf3'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickcolor': '#e6edf3'},
                    'bar': {'color': '#667eea'},
                    'steps': [
                        {'range': [0, 33], 'color': '#002d1a'},
                        {'range': [33, 66], 'color': '#2d1a00'},
                        {'range': [66, 100], 'color': '#3d0000'}
                    ],
                    'threshold': {
                        'line': {'color': '#ff4d4d', 'width': 4},
                        'thickness': 0.75,
                        'value': result['risk_score']
                    }
                },
                number={'font': {'color': '#e6edf3'}}
            ))
            fig_gauge.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', font_color='#e6edf3',
                height=300, margin=dict(t=40, b=20, l=40, r=40)
            )
            st.plotly_chart(fig_gauge, use_container_width=True)
            
            # ── Full Mitigation Strategy ──────────────────────────────────────
            st.divider()
            st.markdown("## 🛡️ Mitigation Strategy")
            mitigations = engine.get_mitigations(
                threat_category=threat_category,
                asset_type=asset_type,
                environment=environment,
                risk_level=result["risk_level"]
            )

            # NIST + Timeline banner
            col_n1, col_n2 = st.columns(2)
            with col_n1:
                st.markdown(
                    f'<div style="background:#1a1f2e;border:0.5px solid #30363d;border-radius:8px;'
                    f'padding:12px 16px;font-size:12px;color:#8b949e">'
                    f'<strong style="color:#667eea">📋 Framework</strong><br>{mitigations["nist"]}</div>',
                    unsafe_allow_html=True
                )
            with col_n2:
                st.markdown(
                    f'<div style="background:#1a1f2e;border:0.5px solid #30363d;border-radius:8px;'
                    f'padding:12px 16px;font-size:12px;color:#8b949e">'
                    f'<strong style="color:#667eea">⏱️ Timeline</strong><br>{mitigations["timeline"]}</div>',
                    unsafe_allow_html=True
                )

            st.markdown("")
            mit_tab1, mit_tab2, mit_tab3, mit_tab4 = st.tabs(
                ["🔴 Immediate", "🟠 Short-Term", "🟢 Long-Term", "🔧 Tools & Asset-Specific"]
            )

            with mit_tab1:
                st.markdown(f"**Actions required {'NOW' if result['risk_level'] == 'High' else 'soon'}:**")
                for item in mitigations["immediate"]:
                    icon = "🔴" if result["risk_level"] == "High" else ("🟠" if result["risk_level"] == "Medium" else "🟢")
                    bg   = "#3d0000" if result["risk_level"] == "High" else ("#2d1a00" if result["risk_level"] == "Medium" else "#002d1a")
                    tc   = "#ff9999" if result["risk_level"] == "High" else ("#ffcc80" if result["risk_level"] == "Medium" else "#80ffb4")
                    st.markdown(
                        f'<div style="background:{bg};border-radius:6px;padding:9px 14px;'
                        f'margin:5px 0;color:{tc};font-size:13px">{icon} {item}</div>',
                        unsafe_allow_html=True
                    )

            with mit_tab2:
                st.markdown("**Within 24–72 hours:**")
                for item in mitigations["short_term"]:
                    st.markdown(
                        f'<div style="background:#2d1a00;border-radius:6px;padding:9px 14px;'
                        f'margin:5px 0;color:#ffcc80;font-size:13px">🟠 {item}</div>',
                        unsafe_allow_html=True
                    )

            with mit_tab3:
                st.markdown("**30–90 day hardening plan:**")
                for item in mitigations["long_term"]:
                    st.markdown(
                        f'<div style="background:#002d1a;border-radius:6px;padding:9px 14px;'
                        f'margin:5px 0;color:#80ffb4;font-size:13px">🟢 {item}</div>',
                        unsafe_allow_html=True
                    )

            with mit_tab4:
                st.markdown("**Recommended Tools:**")
                tool_html = "".join([
                    f'<span style="background:#21262d;border:0.5px solid #30363d;border-radius:20px;'
                    f'padding:5px 12px;margin:4px;display:inline-block;color:#e6edf3;font-size:12px">🔧 {t}</span>'
                    for t in mitigations["tools"]
                ])
                st.markdown(f'<div style="margin-bottom:16px">{tool_html}</div>', unsafe_allow_html=True)

                if mitigations["asset_specific"]:
                    st.markdown(f"**{asset_type}-Specific Actions:**")
                    for item in mitigations["asset_specific"]:
                        st.markdown(
                            f'<div style="background:#1a1f2e;border-left:3px solid #667eea;border-radius:4px;'
                            f'padding:8px 14px;margin:5px 0;color:#c9d1d9;font-size:13px">📌 {item}</div>',
                            unsafe_allow_html=True
                        )

                if mitigations["env_specific"]:
                    st.markdown(f"**{environment} Environment Actions:**")
                    for item in mitigations["env_specific"]:
                        st.markdown(
                            f'<div style="background:#1a1f2e;border-left:3px solid #764ba2;border-radius:4px;'
                            f'padding:8px 14px;margin:5px 0;color:#c9d1d9;font-size:13px">📌 {item}</div>',
                            unsafe_allow_html=True
                        )

            st.success(f"✅ Threat '{threat_name}' logged successfully with Risk Score {result['risk_score']:.1f}!")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: WEBSITE CHECKER
# ══════════════════════════════════════════════════════════════════════════════
elif "Website Checker" in page:
    st.markdown("# 🌐 Website Threat Checker")
    st.markdown("*Scan any URL, domain, or IP address for threats using multiple intelligence sources*")
    st.divider()

    # ── API Key config ─────────────────────────────────────────────────────────
    # Try to load default keys from secrets or environment variables
    vt_default = ""
    ab_default = ""
    us_default = ""
    
    try:
        vt_default = st.secrets.get("VIRUSTOTAL_API_KEY", os.getenv("VIRUSTOTAL_API_KEY", ""))
    except Exception:
        vt_default = os.getenv("VIRUSTOTAL_API_KEY", "")
        
    try:
        ab_default = st.secrets.get("ABUSEIPDB_API_KEY", os.getenv("ABUSEIPDB_API_KEY", ""))
    except Exception:
        ab_default = os.getenv("ABUSEIPDB_API_KEY", "")
        
    try:
        us_default = st.secrets.get("URLSCAN_API_KEY", os.getenv("URLSCAN_API_KEY", ""))
    except Exception:
        us_default = os.getenv("URLSCAN_API_KEY", "")

    with st.expander("⚙️ Configure API Keys (optional — heuristic scan always works without keys)"):
        st.markdown("Get free keys from these sites:")
        st.markdown("- **VirusTotal**: https://www.virustotal.com/gui/join-us")
        st.markdown("- **AbuseIPDB**: https://www.abuseipdb.com/register")
        st.markdown("- **URLScan.io**: https://urlscan.io/user/signup")
        col_k1, col_k2, col_k3 = st.columns(3)
        with col_k1:
            vt_key  = st.text_input("VirusTotal API Key", value=vt_default, type="password", placeholder="Paste key here")
        with col_k2:
            ab_key  = st.text_input("AbuseIPDB API Key",  value=ab_default, type="password", placeholder="Paste key here")
        with col_k3:
            us_key  = st.text_input("URLScan.io API Key", value=us_default, type="password", placeholder="Paste key here")

    # ── Single URL scan ────────────────────────────────────────────────────────
    st.markdown("### 🔍 Scan a Single Target")
    scan_col1, scan_col2 = st.columns([4, 1])
    with scan_col1:
        target_input = st.text_input(
            "Enter URL, domain, or IP",
            placeholder="e.g. https://suspicious-site.xyz  or  192.168.1.1  or  evil-login.tk",
            label_visibility="collapsed"
        )
    with scan_col2:
        scan_btn = st.button("🔍 Scan Now", use_container_width=True)

    if scan_btn and target_input:
        with st.spinner(f"Scanning {target_input}..."):
            result = full_scan(
                target_input,
                virustotal_key=vt_key if 'vt_key' in dir() else "",
                abuseipdb_key=ab_key  if 'ab_key' in dir() else "",
                urlscan_key=us_key    if 'us_key' in dir() else "",
            )

        # Header result
        level = result["final_level"]
        score = result["final_score"]
        lcolor = {"High": "#ff4d4d", "Medium": "#ffa500", "Low": "#00cc66"}[level]
        licon  = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}[level]

        st.divider()
        r1, r2, r3, r4 = st.columns(4)
        with r1: st.metric("Final Risk Score", f"{score} / 100")
        with r2: st.metric("Risk Level",       f"{licon} {level}")
        with r3: st.metric("Target",           result["hostname"])
        with r4: st.metric("Engines Used",     result["engines_used"])

        # Flags
        if result["all_flags"]:
            st.markdown("#### ⚠️ Suspicious Indicators Found")
            for flag in result["all_flags"]:
                st.markdown(
                    f'<div style="background:#2d1a00;border-left:3px solid #ffa500;'
                    f'border-radius:0;padding:7px 12px;margin:4px 0;color:#ffcc80;font-size:13px">⚠️ {flag}</div>',
                    unsafe_allow_html=True
                )
        else:
            st.success("✅ No suspicious indicators detected by heuristic scanner.")

        # Per-source results
        st.markdown("#### 📡 Results by Source")
        for src in result["sources"]:
            src_score = src.get("risk_score", 0)
            src_level = severity_from_score(src_score)
            src_icon  = "🔴" if src_level == "High" else ("🟠" if src_level == "Medium" else "🟢")
            with st.expander(f"{src_icon} {src['source']} — Score: {src_score} — {src.get('details','')[:80]}"):
                st.json({k: v for k, v in src.items() if k not in ("flags",)})

        # Auto-save to database
        if score > 0:
            from scoring_engine import ContextAwareScoringEngine
            eng = ContextAwareScoringEngine()
            ctx = eng.calculate_risk(
                severity=min(10, int(score / 10)),
                likelihood=7, impact=6,
                asset_type="Server",
                user_role="Standard User",
                environment="External"
            )
            record = {
                "threat_name":     f"Web Scan: {result['hostname']}",
                "threat_category": "Other",
                "description":     f"Automated scan of {target_input}. Flags: {'; '.join(result['all_flags']) or 'None'}",
                "source_ip":       result.get("ip") or "",
                "cve_id":          "",
                "severity":        min(10, int(score / 10)),
                "likelihood":      7,
                "impact":          6,
                "asset_type":      "Server",
                "user_role":       "Standard User",
                "environment":     "External",
                "risk_score":      score,
                "risk_level":      level,
                "context_factor":  ctx["context_factor"],
                "timestamp":       result["timestamp"],
            }
            dm.add_threat(record)
            st.info(f"💾 Scan result auto-saved to Threat Database (score: {score})")

    st.divider()

    # ── Bulk scan (20 test cases) ──────────────────────────────────────────────
    st.markdown("### 🧪 Run 20 Test Cases")
    st.markdown("Tests the heuristic scanner against 20 known-good and known-suspicious URLs. No API keys needed.")

    if st.button("▶️ Run All 20 Test Cases", use_container_width=True):
        from test_cases import TEST_CASES
        progress = st.progress(0)
        results_out = []

        for i, (target, expected, desc) in enumerate(TEST_CASES):
            r = heuristic_scan(target)
            results_out.append({
                "Test": desc,
                "Target": target[:50] + ("..." if len(target) > 50 else ""),
                "Expected": expected,
                "Got": r["risk_level"],
                "Score": r["risk_score"],
                "Pass": "✅" if r["risk_level"] == expected else "❌",
                "Flags": len(r["flags"])
            })
            progress.progress((i + 1) / 20)

        results_df = pd.DataFrame(results_out)
        passed = sum(1 for r in results_out if r["Pass"] == "✅")

        c1, c2, c3 = st.columns(3)
        with c1: st.metric("Total Tests", 20)
        with c2: st.metric("✅ Passed", passed)
        with c3: st.metric("❌ Failed", 20 - passed)

        def color_pass(val):
            if val == "✅": return "background-color: #002d1a; color: #80ffb4"
            if val == "❌": return "background-color: #3d0000; color: #ff9999"
            return ""
        def color_level(val):
            if val == "High":   return "color: #ff4d4d"
            if val == "Medium": return "color: #ffa500"
            if val == "Low":    return "color: #00cc66"
            return ""

        styled_df = (results_df.style
            .map(color_pass,  subset=["Pass"])
            .map(color_level, subset=["Expected", "Got"]))
        st.dataframe(styled_df, use_container_width=True, height=500)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: AI ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
elif "AI Analysis" in page:
    st.markdown("# 🤖 AI Threat Analysis")
    st.markdown("*Machine Learning powered threat prioritization and insights*")
    st.divider()
    
    all_df = dm.get_threats()
    
    tab1, tab2, tab3 = st.tabs(["🧠 ML Model", "💬 AI Chat Analyst", "📈 Predictions"])
    
    with tab1:
        st.markdown("### Machine Learning Threat Classifier")
        
        if len(all_df) < 5:
            st.warning(f"⚠️ Need at least 5 threats to train the model. Currently have {len(all_df)}. Add more threats first.")
            st.info("The ML model uses Random Forest classification to learn patterns from your historical threat data and predict risk levels for new threats.")
        else:
            if st.button("🚀 Train / Retrain ML Model", use_container_width=True):
                with st.spinner("Training Random Forest classifier..."):
                    results = ai_analyzer.train_model(all_df)
                
                if results['success']:
                    st.success(f"✅ Model trained! Accuracy: **{results['accuracy']*100:.1f}%**")
                    
                    c1, c2, c3 = st.columns(3)
                    with c1: st.metric("Accuracy",  f"{results['accuracy']*100:.1f}%")
                    with c2: st.metric("Precision", f"{results['precision']*100:.1f}%")
                    with c3: st.metric("Recall",    f"{results['recall']*100:.1f}%")
                    
                    # Feature importance
                    if 'feature_importance' in results:
                        fi_df = pd.DataFrame({
                            'Feature': results['feature_names'],
                            'Importance': results['feature_importance']
                        }).sort_values('Importance', ascending=True)
                        
                        fig_fi = px.bar(fi_df, x='Importance', y='Feature', orientation='h',
                                        color='Importance', color_continuous_scale='viridis')
                        fig_fi.update_layout(
                            title="Feature Importance",
                            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                            font_color='#e6edf3', margin=dict(t=40, b=20, l=20, r=20),
                            xaxis=dict(gridcolor='#2d3748'), yaxis=dict(gridcolor='#2d3748'),
                            coloraxis_showscale=False
                        )
                        st.plotly_chart(fig_fi, use_container_width=True)
                else:
                    st.error(f"Training failed: {results.get('error', 'Unknown error')}")
            
            # Predict on new input
            st.markdown("### Predict Risk for New Threat")
            p1, p2, p3 = st.columns(3)
            with p1:
                p_sev = st.slider("Severity",   1, 10, 5, key="p_sev")
                p_lik = st.slider("Likelihood", 1, 10, 5, key="p_lik")
            with p2:
                p_imp = st.slider("Impact",     1, 10, 5, key="p_imp")
                p_ast = st.selectbox("Asset Type", ["Server","Workstation","Database","Network Device","Cloud Instance"], key="p_ast")
            with p3:
                p_rol = st.selectbox("User Role",  ["Admin","Standard User","Guest","Service Account"], key="p_rol")
                p_env = st.selectbox("Environment",["Internal","External","DMZ","Cloud"], key="p_env")
            
            if st.button("🔮 Predict Risk Level"):
                pred = ai_analyzer.predict(p_sev, p_lik, p_imp, p_ast, p_rol, p_env)
                if pred['success']:
                    color = "🔴" if pred['prediction'] == 'High' else ("🟠" if pred['prediction'] == 'Medium' else "🟢")
                    st.markdown(f"### {color} Predicted Risk Level: **{pred['prediction']}**")
                    
                    prob_df = pd.DataFrame({
                        'Risk Level': list(pred['probabilities'].keys()),
                        'Probability': list(pred['probabilities'].values())
                    })
                    fig_prob = px.bar(prob_df, x='Risk Level', y='Probability',
                                      color='Risk Level',
                                      color_discrete_map={'High':'#ff4d4d','Medium':'#ffa500','Low':'#00cc66'})
                    fig_prob.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#e6edf3', yaxis_tickformat='.0%',
                        xaxis=dict(gridcolor='#2d3748'), yaxis=dict(gridcolor='#2d3748'),
                        showlegend=False
                    )
                    st.plotly_chart(fig_prob, use_container_width=True)
                else:
                    st.warning("⚠️ Model not trained yet. Train the model first.")
    
    with tab2:
        st.markdown("### AI Security Analyst Chat")
        st.markdown("*Ask questions about your threat landscape, get AI-powered recommendations*")
        
        if "chat_history" not in st.session_state:
            st.session_state.chat_history = []
        
        # Display chat history
        for msg in st.session_state.chat_history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])
        
        prompt = st.chat_input("Ask about your threats... e.g. 'What are my top risks?' or 'Recommend mitigations for SQL injection'")
        
        if prompt:
            st.session_state.chat_history.append({"role": "user", "content": prompt})
            with st.chat_message("user"):
                st.markdown(prompt)
            
            with st.chat_message("assistant"):
                with st.spinner("Analyzing..."):
                    context_summary = ""
                    if len(all_df) > 0:
                        context_summary = f"""
Current threat database summary:
- Total threats: {len(all_df)}
- High risk: {len(all_df[all_df['risk_level']=='High'])}
- Medium risk: {len(all_df[all_df['risk_level']=='Medium'])}  
- Low risk: {len(all_df[all_df['risk_level']=='Low'])}
- Most affected asset: {all_df['asset_type'].value_counts().idxmax() if len(all_df) > 0 else 'N/A'}
- Top threat category: {all_df['threat_category'].value_counts().idxmax() if len(all_df) > 0 else 'N/A'}
- Average risk score: {all_df['risk_score'].mean():.1f}
- Latest threats: {', '.join(all_df.nlargest(3,'risk_score')['threat_name'].tolist())}
"""
                    response = ai_analyzer.chat(prompt, context_summary, st.session_state.chat_history)
                    st.markdown(response)
                    st.session_state.chat_history.append({"role": "assistant", "content": response})
        
        if st.button("🗑️ Clear Chat"):
            st.session_state.chat_history = []
            st.rerun()
    
    with tab3:
        st.markdown("### Threat Trend Predictions")
        
        if len(all_df) < 3:
            st.info("Add more threats to see trend predictions.")
        else:
            all_df_ts = all_df.copy()
            all_df_ts['timestamp'] = pd.to_datetime(all_df_ts['timestamp'])
            daily = all_df_ts.groupby(all_df_ts['timestamp'].dt.date)['risk_score'].mean().reset_index()
            daily.columns = ['date', 'avg_score']
            
            fig_trend = go.Figure()
            fig_trend.add_trace(go.Scatter(
                x=daily['date'], y=daily['avg_score'],
                mode='lines+markers', name='Avg Risk Score',
                line=dict(color='#667eea', width=2),
                marker=dict(size=8, color='#764ba2')
            ))
            fig_trend.update_layout(
                title="Daily Average Risk Score Trend",
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                font_color='#e6edf3',
                xaxis=dict(gridcolor='#2d3748'), yaxis=dict(gridcolor='#2d3748')
            )
            st.plotly_chart(fig_trend, use_container_width=True)
#geo threat map
elif "Geo Threat Map" in page:
    st.markdown("""
    <div class="war-room-hero">
        <div class="war-room-kicker">Threat Geography</div>
        <div class="war-room-title">Geolocation Threat Map</div>
        <div class="war-room-subtitle">
            Visualizes threat source locations using simulated geolocation for demonstration.
        </div>
    </div>
    """, unsafe_allow_html=True)

    all_df = dm.get_threats()

    if len(all_df) == 0:
        st.info("No threats available. Add a threat or run a scan first.")
    else:
        geo_points = [
            {"country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060},
            {"country": "United Kingdom", "city": "London", "lat": 51.5072, "lon": -0.1276},
            {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
            {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
            {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
            {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
            {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5558, "lon": -46.6396},
            {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
            {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
            {"country": "Canada", "city": "Toronto", "lat": 43.6532, "lon": -79.3832}
        ]

        map_rows = []

        for i, (_, row) in enumerate(all_df.iterrows()):
            point = geo_points[i % len(geo_points)]

            map_rows.append({
                "threat_name": row["threat_name"],
                "source_ip": row["source_ip"],
                "risk_level": row["risk_level"],
                "risk_score": float(row["risk_score"]),
                "country": point["country"],
                "city": point["city"],
                "lat": point["lat"],
                "lon": point["lon"]
            })

        map_df = pd.DataFrame(map_rows)

        color_map = {
            "High": "#ff6370",
            "Medium": "#f6bc45",
            "Low": "#58e6a7"
        }

        fig_geo = px.scatter_geo(
            map_df,
            lat="lat",
            lon="lon",
            color="risk_level",
            size="risk_score",
            hover_name="threat_name",
            hover_data={
                "source_ip": True,
                "city": True,
                "country": True,
                "risk_score": True,
                "lat": False,
                "lon": False
            },
            color_discrete_map=color_map,
            projection="natural earth"
        )

        fig_geo.update_layout(
            height=520,
            paper_bgcolor="rgba(0,0,0,0)",
            geo=dict(
                bgcolor="rgba(0,0,0,0)",
                landcolor="#13221d",
                oceancolor="#07110f",
                lakecolor="#07110f",
                coastlinecolor="#2c4a41",
                countrycolor="#2c4a41",
                showland=True,
                showocean=True,
                showcountries=True
            ),
            font=dict(color="#edf8f4"),
            legend=dict(
                bgcolor="rgba(0,0,0,0)"
            )
        )

        st.plotly_chart(fig_geo, use_container_width=True)

        st.divider()

        c1, c2, c3 = st.columns(3)

        with c1:
            st.metric("Mapped Threats", len(map_df))
        with c2:
            st.metric("Countries", map_df["country"].nunique())
        with c3:
            st.metric("Highest Risk", f"{map_df['risk_score'].max():.1f}")

        st.subheader("Geolocation Intelligence Table")

        st.dataframe(
            map_df[
                [
                    "threat_name",
                    "source_ip",
                    "city",
                    "country",
                    "risk_level",
                    "risk_score"
                ]
            ].sort_values("risk_score", ascending=False),
            use_container_width=True,
            height=350
        )

        st.warning(
            "Note: Demo mode uses simulated geolocation because private IP addresses such as 192.168.x.x "
            "cannot be mapped to real public locations."
        )
#===========================================
# PAGE: RESPONSE PLAYBOOK
#===========================================
elif "Response Playbook" in page:
    st.markdown("""
    <div class="war-room-hero">
        <div class="war-room-kicker">Mitigation Layer</div>
        <div class="war-room-title">Cyber Response Playbook</div>
        <div class="war-room-subtitle">
            Select a threat and generate a practical response plan with owners, timeline,
            containment steps, hardening tasks, tools, and evidence requirements.
        </div>
    </div>
    """, unsafe_allow_html=True)

    all_df = dm.get_threats()

    if len(all_df) == 0:
        st.info("No threats available. Add a threat or run a website scan first.")
    else:
        all_df["risk_score"] = pd.to_numeric(all_df["risk_score"], errors="coerce").fillna(0)
        all_df = all_df.sort_values("risk_score", ascending=False)

        selected = st.selectbox(
            "Select threat for mitigation",
            all_df["threat_name"].tolist()
        )

        row = all_df[all_df["threat_name"] == selected].iloc[0]

        threat_name = row["threat_name"]
        threat_category = row["threat_category"]
        asset_type = row["asset_type"]
        environment = row["environment"]
        risk_level = row["risk_level"]
        risk_score = row["risk_score"]

        owner_map = {
            "Server": "Infrastructure Team",
            "Workstation": "Endpoint Security Team",
            "Database": "Database Administrator",
            "Network Device": "Network Security Team",
            "Cloud Instance": "Cloud Security Team",
            "Mobile Device": "Device Management Team"
        }

        owner = owner_map.get(asset_type, "Security Team")

        if risk_level == "High":
            sla = "Contain within 4 hours"
            decision = "Escalate immediately"
        elif risk_level == "Medium":
            sla = "Remediate within 72 hours"
            decision = "Schedule controlled remediation"
        else:
            sla = "Review during maintenance"
            decision = "Monitor and harden"

        mitigations = engine.get_mitigations(
            threat_category=threat_category,
            asset_type=asset_type,
            environment=environment,
            risk_level=risk_level
        )

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.markdown(f"""
            <div class="action-card">
                <div class="action-label">Risk Score</div>
                <div class="action-value">{risk_score:.1f}</div>
            </div>
            """, unsafe_allow_html=True)

        with c2:
            st.markdown(f"""
            <div class="action-card">
                <div class="action-label">Decision</div>
                <div class="action-value" style="font-size:17px">{decision}</div>
            </div>
            """, unsafe_allow_html=True)

        with c3:
            st.markdown(f"""
            <div class="action-card">
                <div class="action-label">Owner</div>
                <div class="action-value" style="font-size:17px">{owner}</div>
            </div>
            """, unsafe_allow_html=True)

        with c4:
            st.markdown(f"""
            <div class="action-card">
                <div class="action-label">SLA</div>
                <div class="action-value" style="font-size:17px">{sla}</div>
            </div>
            """, unsafe_allow_html=True)

        st.divider()

        tab1, tab2, tab3, tab4 = st.tabs([
            "Containment",
            "Short-Term Fix",
            "Long-Term Hardening",
            "Evidence Pack"
        ])

        with tab1:
            st.subheader("Immediate Containment")
            for item in mitigations["immediate"]:
                st.checkbox(item, key=f"contain_{item}")

        with tab2:
            st.subheader("24-72 Hour Remediation")
            for item in mitigations["short_term"]:
                st.checkbox(item, key=f"short_{item}")

        with tab3:
            st.subheader("30-90 Day Hardening")
            for item in mitigations["long_term"]:
                st.checkbox(item, key=f"long_{item}")

            st.markdown("### Recommended Tools")
            for tool in mitigations["tools"]:
                st.write(f"- {tool}")

        with tab4:
            st.subheader("Evidence Required For Closure")
            st.write("- Screenshot or log showing the threat was detected")
            st.write("- Proof of containment or patching")
            st.write("- Updated risk score after mitigation")
            st.write("- Owner approval or review note")
            st.write("- Final closure timestamp")

            st.markdown("### Framework Mapping")
            st.info(mitigations["nist"])

            st.markdown("### Recommended Timeline")
            st.warning(mitigations["timeline"])

        report = f"""
CYBER SHIELD MITIGATION PLAYBOOK

Threat: {threat_name}
Category: {threat_category}
Risk Level: {risk_level}
Risk Score: {risk_score:.1f}
Asset Type: {asset_type}
Environment: {environment}
Owner: {owner}
SLA: {sla}
Decision: {decision}

IMMEDIATE CONTAINMENT:
{chr(10).join("- " + x for x in mitigations["immediate"])}

SHORT-TERM REMEDIATION:
{chr(10).join("- " + x for x in mitigations["short_term"])}

LONG-TERM HARDENING:
{chr(10).join("- " + x for x in mitigations["long_term"])}

TOOLS:
{chr(10).join("- " + x for x in mitigations["tools"])}

FRAMEWORK:
{mitigations["nist"]}

TIMELINE:
{mitigations["timeline"]}

EVIDENCE REQUIRED:
- Detection proof
- Remediation proof
- Updated risk score
- Owner approval
- Closure note
"""

        st.download_button(
            "Download Mitigation Playbook",
            data=report,
            file_name="mitigation_playbook.txt",
            mime="text/plain",
            use_container_width=True
        )

# ══════════════════════════════════════════════════════════════════════════════
# PAGE: REPORTS
# ══════════════════════════════════════════════════════════════════════════════
elif "Reports" in page:
    st.markdown("# 📄 Reports")
    st.markdown("*Generate comprehensive threat intelligence reports*")
    st.divider()
    
    all_df = dm.get_threats()
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 📊 Executive Summary Report")
        st.markdown("High-level overview of your threat landscape for management.")
        
        if st.button("Generate Executive Report", use_container_width=True):
            with st.spinner("Generating report..."):
                path = report_gen.executive_summary(all_df)
            st.success(f"✅ Report saved to `{path}`")
            
            with open(path, 'r') as f:
                content = f.read()
            st.download_button(
                "⬇️ Download HTML Report",
                data=content,
                file_name="executive_summary.html",
                mime="text/html",
                use_container_width=True
            )
    
    with col2:
        st.markdown("### 🔍 Detailed Threat Report")
        st.markdown("Full breakdown of all threats with scores and context.")
        
        if st.button("Generate Detailed Report", use_container_width=True):
            with st.spinner("Generating detailed report..."):
                path = report_gen.detailed_report(all_df)
            st.success(f"✅ Report saved to `{path}`")
            
            with open(path, 'r') as f:
                content = f.read()
            st.download_button(
                "⬇️ Download HTML Report",
                data=content,
                file_name="detailed_threat_report.html",
                mime="text/html",
                use_container_width=True
            )
    
    st.divider()
    
    st.markdown("### 📥 Export Raw Data")
    if len(all_df) > 0:
        csv = all_df.to_csv(index=False)
        st.download_button(
            "⬇️ Download CSV",
            data=csv,
            file_name="threat_data.csv",
            mime="text/csv"
        )
    
    # Report preview
    if len(all_df) > 0:
        st.divider()
        st.markdown("### 👁️ Report Preview")
        
        c1, c2, c3 = st.columns(3)
        with c1:
            st.metric("Total Incidents", len(all_df))
        with c2:
            st.metric("Critical (High)", len(all_df[all_df['risk_level']=='High']))
        with c3:
            st.metric("Avg Risk Score", f"{all_df['risk_score'].mean():.1f}")
        
        st.dataframe(
            all_df.sort_values('risk_score', ascending=False)
                  .head(10)[['threat_name','risk_level','risk_score','asset_type','timestamp']],
            use_container_width=True
        )


# ══════════════════════════════════════════════════════════════════════════════
# PAGE: THREAT DATABASE
# ══════════════════════════════════════════════════════════════════════════════
elif "Database" in page:
    st.markdown("# 🗄️ Threat Database")
    st.divider()
    
    all_df = dm.get_threats()
    
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        search = st.text_input("🔍 Search threats...", placeholder="Search by name, category, asset type...")
    with col2:
        sort_col = st.selectbox("Sort by", ["timestamp", "risk_score", "severity", "threat_name"])
    with col3:
        sort_asc = st.checkbox("Ascending", value=False)
    
    if search:
        mask = (
            all_df['threat_name'].str.contains(search, case=False, na=False) |
            all_df['threat_category'].str.contains(search, case=False, na=False) |
            all_df['asset_type'].str.contains(search, case=False, na=False)
        )
        display_df = all_df[mask]
    else:
        display_df = all_df.copy()
    
    display_df = display_df.sort_values(sort_col, ascending=sort_asc)
    
    st.markdown(f"Showing **{len(display_df)}** of **{len(all_df)}** threats")
    st.dataframe(display_df, use_container_width=True, height=500)
    
    st.divider()
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("🗑️ Clear All Data", type="secondary"):
            dm.clear_all()
            st.rerun()
    with col_b:
        if st.button("🌱 Load Sample Data", type="primary"):
            dm.load_sample_data(engine)
            st.success("Sample data loaded!")
            st.rerun()
#incident case file
elif "Incident Case File" in page:
    st.markdown("""
    <div class="war-room-hero">
        <div class="war-room-kicker">Investigation Layer</div>
        <div class="war-room-title">Incident Case File</div>
        <div class="war-room-subtitle">
            Build an investigation record for a threat with evidence, timeline notes,
            incident status, impact summary, and closure decision.
        </div>
    </div>
    """, unsafe_allow_html=True)

    all_df = dm.get_threats()

    if len(all_df) == 0:
        st.info("No threats available. Add a threat or scan a website first.")
    else:
        all_df["risk_score"] = pd.to_numeric(all_df["risk_score"], errors="coerce").fillna(0)
        all_df = all_df.sort_values("risk_score", ascending=False)

        selected = st.selectbox(
            "Select incident",
            all_df["threat_name"].tolist()
        )

        row = all_df[all_df["threat_name"] == selected].iloc[0]

        case_id = "CS-" + str(abs(hash(selected)))[:6]

        st.subheader("Case Overview")

        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.metric("Case ID", case_id)
        with c2:
            st.metric("Risk Level", row["risk_level"])
        with c3:
            st.metric("Risk Score", f"{float(row['risk_score']):.1f}")
        with c4:
            st.metric("Asset", row["asset_type"])

        st.divider()

        left, right = st.columns([1.1, 0.9])

        with left:
            st.subheader("Investigation Details")

            investigator = st.text_input("Investigator Name", placeholder="Enter analyst name")

            status = st.selectbox(
                "Case Status",
                ["Open", "Under Investigation", "Contained", "Remediated", "Closed"]
            )

            priority = st.selectbox(
                "Investigation Priority",
                ["Critical", "High", "Medium", "Low"]
            )

            root_cause = st.selectbox(
                "Suspected Root Cause",
                [
                    "Unpatched vulnerability",
                    "Weak credentials",
                    "Phishing/social engineering",
                    "Misconfiguration",
                    "Malicious file or malware",
                    "Suspicious external domain/IP",
                    "Insider activity",
                    "Unknown"
                ]
            )

            business_impact = st.text_area(
                "Business Impact",
                placeholder="Example: Could expose customer data, disrupt service, or allow unauthorized access.",
                height=100
            )

            evidence = st.text_area(
                "Evidence Collected",
                placeholder="Add logs, suspicious URLs, IPs, screenshots, CVE IDs, timestamps, or scanner findings.",
                height=140
            )

            investigation_notes = st.text_area(
                "Investigation Notes",
                placeholder="Write what was checked, what was confirmed, and what still needs review.",
                height=160
            )

        with right:
            st.subheader("Threat Snapshot")

            st.write("**Threat Name:**", row["threat_name"])
            st.write("**Category:**", row["threat_category"])
            st.write("**Asset Type:**", row["asset_type"])
            st.write("**Environment:**", row["environment"])
            st.write("**User Role:**", row["user_role"])
            st.write("**Source IP:**", row["source_ip"] if row["source_ip"] else "Not available")
            st.write("**CVE ID:**", row["cve_id"] if row["cve_id"] else "Not available")
            st.write("**Timestamp:**", row["timestamp"])

            st.markdown("### Closure Checklist")

            check1 = st.checkbox("Threat validated")
            check2 = st.checkbox("Affected asset identified")
            check3 = st.checkbox("Evidence collected")
            check4 = st.checkbox("Mitigation assigned")
            check5 = st.checkbox("Owner reviewed case")

            completed = sum([check1, check2, check3, check4, check5])
            st.progress(completed / 5)
            st.caption(f"{completed}/5 closure items complete")

        st.divider()

        st.subheader("Investigation Timeline")

        t1, t2, t3 = st.columns(3)

        with t1:
            detected_time = st.text_input("Detected Time", value=str(row["timestamp"]))
        with t2:
            contained_time = st.text_input("Contained Time", placeholder="Example: 2026-05-19 14:30")
        with t3:
            closed_time = st.text_input("Closed Time", placeholder="Fill when resolved")

        if status == "Closed" and completed < 5:
            st.warning("Case is marked Closed, but the closure checklist is not complete.")
        elif status in ["Contained", "Remediated", "Closed"]:
            st.success("Case has moved beyond active investigation.")
        else:
            st.info("Case is still active. Continue collecting evidence and mitigation proof.")

        report = f"""
CYBER SHIELD INCIDENT CASE FILE

Case ID: {case_id}
Case Status: {status}
Priority: {priority}
Investigator: {investigator if investigator else "Not assigned"}

THREAT SUMMARY
Threat Name: {row["threat_name"]}
Category: {row["threat_category"]}
Risk Level: {row["risk_level"]}
Risk Score: {float(row["risk_score"]):.1f}
Asset Type: {row["asset_type"]}
Environment: {row["environment"]}
User Role: {row["user_role"]}
Source IP: {row["source_ip"]}
CVE ID: {row["cve_id"]}
Detected Timestamp: {row["timestamp"]}

ROOT CAUSE
{root_cause}

BUSINESS IMPACT
{business_impact if business_impact else "Not provided"}

EVIDENCE COLLECTED
{evidence if evidence else "No evidence entered"}

INVESTIGATION NOTES
{investigation_notes if investigation_notes else "No notes entered"}

TIMELINE
Detected: {detected_time}
Contained: {contained_time if contained_time else "Not recorded"}
Closed: {closed_time if closed_time else "Not recorded"}

CLOSURE CHECKLIST
Threat validated: {"Yes" if check1 else "No"}
Affected asset identified: {"Yes" if check2 else "No"}
Evidence collected: {"Yes" if check3 else "No"}
Mitigation assigned: {"Yes" if check4 else "No"}
Owner reviewed case: {"Yes" if check5 else "No"}
"""

        st.download_button(
            "Download Incident Case File",
            data=report,
            file_name=f"{case_id}_incident_case_file.txt",
            mime="text/plain",
            use_container_width=True
        )
#attack path analysis
elif "Attack Path Visualizer" in page:
    st.markdown("""
    <div class="war-room-hero">
        <div class="war-room-kicker">Attack Movement</div>
        <div class="war-room-title">Attack Path Visualizer</div>
        <div class="war-room-subtitle">
            Visualizes how a threat could move from entry point to target asset, affected identity,
            environment, and business impact.
        </div>
    </div>
    """, unsafe_allow_html=True)

    all_df = dm.get_threats()

    if len(all_df) == 0:
        st.info("No threats available. Add a threat or run a website scan first.")
    else:
        all_df["risk_score"] = pd.to_numeric(all_df["risk_score"], errors="coerce").fillna(0)
        all_df = all_df.sort_values("risk_score", ascending=False)

        selected = st.selectbox(
            "Select threat to visualize",
            all_df["threat_name"].tolist()
        )

        row = all_df[all_df["threat_name"] == selected].iloc[0]

        threat_name = row["threat_name"]
        category = row["threat_category"]
        asset = row["asset_type"]
        role = row["user_role"]
        environment = row["environment"]
        risk_level = row["risk_level"]
        risk_score = float(row["risk_score"])

        entry_map = {
            "Phishing": "Email / Fake Login Page",
            "SQL Injection": "Web Form / API Input",
            "Malware": "Downloaded File / Script",
            "Ransomware": "Compromised Endpoint",
            "DDoS": "Public Network Exposure",
            "Brute Force": "Login Portal",
            "Insider Threat": "Internal User Access",
            "Zero-Day Exploit": "Unpatched Service",
            "Man-in-the-Middle": "Network Interception",
            "Other": "Unknown Entry Point"
        }

        impact_map = {
            "Database": "Data Exposure",
            "Server": "Service Compromise",
            "Workstation": "Endpoint Takeover",
            "Network Device": "Traffic Manipulation",
            "Cloud Instance": "Cloud Resource Abuse",
            "Mobile Device": "Device Compromise"
        }

        entry_point = entry_map.get(category, "Unknown Entry Point")
        impact = impact_map.get(asset, "Operational Risk")

        if risk_level == "High":
            path_color = "#ff6370"
        elif risk_level == "Medium":
            path_color = "#f6bc45"
        else:
            path_color = "#58e6a7"

        nodes = [
            "Threat",
            "Entry Point",
            "Target Asset",
            "Affected Identity",
            "Environment",
            "Impact"
        ]

        labels = [
            threat_name,
            entry_point,
            asset,
            role,
            environment,
            impact
        ]

        x = [0, 1, 2, 3, 4, 5]
        y = [0, 0, 0, 0, 0, 0]

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=x,
            y=y,
            mode="lines",
            line=dict(color=path_color, width=5),
            hoverinfo="skip"
        ))

        fig.add_trace(go.Scatter(
            x=x,
            y=y,
            mode="markers+text",
            marker=dict(
                size=[44, 40, 40, 40, 40, 44],
                color=["#101b18"] * 6,
                line=dict(color=path_color, width=3)
            ),
            text=nodes,
            textposition="top center",
            hovertext=labels,
            hoverinfo="text"
        ))

        for i, label in enumerate(labels):
            fig.add_annotation(
                x=x[i],
                y=-0.18,
                text=label,
                showarrow=False,
                font=dict(color="#edf8f4", size=12),
                align="center"
            )

        fig.update_layout(
            height=360,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#edf8f4"),
            margin=dict(t=40, b=80, l=20, r=20),
            xaxis=dict(visible=False),
            yaxis=dict(visible=False, range=[-0.5, 0.5])
        )

        st.plotly_chart(fig, use_container_width=True)

        st.divider()

        c1, c2, c3 = st.columns(3)

        with c1:
            st.metric("Risk Score", f"{risk_score:.1f}")
        with c2:
            st.metric("Risk Level", risk_level)
        with c3:
            st.metric("Likely Impact", impact)

        st.subheader("Defense Breakpoints")

        st.write("**1. Stop Entry:** Block or validate the entry point before the threat reaches the asset.")
        st.write("**2. Protect Asset:** Patch, isolate, monitor, or harden the affected system.")
        st.write("**3. Protect Identity:** Review user permissions and enforce stronger authentication.")
        st.write("**4. Reduce Impact:** Prepare backups, containment rules, and recovery evidence.")

        st.subheader("Attack Summary")

        summary = f"""
The threat **{threat_name}** is categorized as **{category}**.
It most likely enters through **{entry_point}**, targets a **{asset}**,
affects the **{role}** role, and operates in the **{environment}** environment.
The expected impact is **{impact}** with a current risk score of **{risk_score:.1f}**.
"""

        st.info(summary)

        report = f"""
CYBER SHIELD ATTACK PATH REPORT

Threat: {threat_name}
Category: {category}
Risk Level: {risk_level}
Risk Score: {risk_score:.1f}

ATTACK PATH:
Threat -> {entry_point} -> {asset} -> {role} -> {environment} -> {impact}

DEFENSE BREAKPOINTS:
1. Stop Entry: Block or validate {entry_point}
2. Protect Asset: Harden and monitor {asset}
3. Protect Identity: Review access for {role}
4. Reduce Impact: Prepare recovery plan for {impact}
"""

        st.download_button(
            "Download Attack Path Report",
            data=report,
            file_name="attack_path_report.txt",
            mime="text/plain",
            use_container_width=True
        )
#scan intelligence center
elif "Scan Intelligence" in page:

    st.markdown("# 🕵️ Scan Intelligence Center")
    st.markdown("*Detailed investigation and scan history analysis*")
    st.divider()

    all_df = dm.get_threats()

    if len(all_df) == 0:
        st.warning("No scan history available.")
    else:

        st.subheader("📜 Scan History")

        display_cols = [
            "threat_name",
            "risk_level",
            "risk_score",
            "asset_type",
            "timestamp"
        ]

        st.dataframe(
            all_df[display_cols].sort_values(
                "risk_score",
                ascending=False
            ),
            use_container_width=True,
            height=350
        )

        st.divider()

        st.subheader("🔍 Detailed Scan Investigation")

        selected = st.selectbox(
            "Select Threat",
            all_df["threat_name"]
        )

        row = all_df[
            all_df["threat_name"] == selected
        ].iloc[0]

        col1, col2, col3 = st.columns(3)

        with col1:
            st.metric("Risk Score", row["risk_score"])

        with col2:
            st.metric("Risk Level", row["risk_level"])

        with col3:
            st.metric("Asset Type", row["asset_type"])

        st.markdown("---")

        st.subheader("🎯 Attack Details")

        st.write("Threat Name:", row["threat_name"])

        st.write(
            "Affected Asset:",
            row["asset_type"]
        )

        st.write(
            "Environment:",
            row["environment"]
        )

        st.write(
            "User Role Targeted:",
            row["user_role"]
        )

        st.write(
            "Threat Category:",
            row["threat_category"]
        )

        st.write(
            "Source IP:",
            row["source_ip"]
        )

        st.write(
            "Timestamp:",
            row["timestamp"]
        )
        


       