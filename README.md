# 🛡️ Cyber Shield
## Context-Aware Threat Intelligence Scoring System
**Subject:** CYL66 | Dept. of CSE (Cyber Security) | VI Semester

---

## 📁 Project Structure
```
cyber_shield/
├── app.py               ← Main Streamlit dashboard (run this)
├── scoring_engine.py    ← Context-aware risk scoring formula
├── ai_engine.py         ← ML classifier + AI chat analyst
├── data_manager.py      ← SQLite database layer
├── report_generator.py  ← HTML report generator
├── requirements.txt     ← Python dependencies
├── data/                ← Auto-created, stores threats.db
└── reports/             ← Auto-created, stores HTML reports
```

---

## 🚀 Setup & Run (macOS)

### Step 1 – Install Python 3.11+
Download from https://www.python.org/downloads/
Or via Homebrew:
```bash
brew install python@3.11
```

### Step 2 – Open VS Code
- Open the `cyber_shield/` folder in VS Code
- Open the integrated terminal: `View → Terminal`

### Step 3 – Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```
You'll see `(venv)` in your terminal — that means it's active.

### Step 4 – Install dependencies
```bash
pip install -r requirements.txt
```

### Step 5 – Run the app
```bash
streamlit run app.py
```
Your browser will open at **http://localhost:8501** automatically.

---

## 🎯 How to Demo to the Panel

### 1. Load Sample Data First
- Go to **🗄️ Threat Database** page
- Click **"🌱 Load Sample Data"**
- This loads 20 realistic threats so the dashboard is full

### 2. Show the Dashboard (📊)
- 5 KPI cards: Total, High, Medium, Low, Avg Score
- Pie chart: Risk distribution
- Bar chart: Risk by asset type
- Scatter plot: Threat timeline
- Heatmap: Asset × Category
- Top 5 critical threats list

### 3. Add a Live Threat (➕)
- Type a threat name e.g. "SQL Injection on Auth Server"
- Set sliders (Severity: 9, Likelihood: 8, Impact: 10)
- Set Asset: Database, Role: Admin, Env: External
- Click **Calculate Risk Score** — shows live gauge

### 4. AI Analysis (🤖)
- Go to **ML Model** tab → Click **Train ML Model**
- See accuracy, precision, recall metrics + feature importance chart
- Go to **AI Chat Analyst** tab
- Ask: *"What are my top risks?"* or *"Recommend mitigations for ransomware"*

### 5. Generate Reports (📄)
- Click **Generate Executive Report** → download the HTML file
- Shows professional management-ready report

---

## 🧮 Scoring Formula
```
Risk Score = (Severity + Likelihood + Impact) × Context Factor

Context Factor = average(Asset Weight, User Role Weight, Environment Weight)

Asset Weights:    Database=1.6, Server=1.5, Network=1.4, Cloud=1.3, Workstation=1.1
Role Weights:     Admin=1.5, Service Account=1.3, User=1.0, Guest=0.8
Env Weights:      External=1.4, DMZ=1.3, Cloud=1.2, Internal=1.0

Normalized to 0–100 scale:
  High   ≥ 66
  Medium 33–65
  Low    < 33
```

---

## 🔧 VS Code Extensions (Recommended)
- Python (Microsoft)
- Pylance
- GitLens

---

## ⚡ Quick Reference
| Command | What it does |
|---------|-------------|
| `streamlit run app.py` | Start the app |
| `Ctrl+C` in terminal | Stop the app |
| `source venv/bin/activate` | Re-activate venv |

---

*Team: Jyotsna Joji · Rhythm Nirankari · Surabi G.M · Priyasha Biswas*
*Guide: Mrs. Shankaramma, Asst. Professor*
