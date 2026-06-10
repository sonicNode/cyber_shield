import sqlite3
import pandas as pd
import datetime
import os
import random
import sys

# On Streamlit Cloud the app directory is read-only, so use /tmp for the database.
# Locally, use the project's data/ directory.
_LOCAL_DB_DIR = os.path.join(os.path.dirname(__file__), "data")
_CLOUD_DB_DIR = os.path.join("/tmp", "cyber_shield_data")

def _get_db_path():
    """Pick writable directory: local data/ if possible, else /tmp."""
    try:
        os.makedirs(_LOCAL_DB_DIR, exist_ok=True)
        test_file = os.path.join(_LOCAL_DB_DIR, ".write_test")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return os.path.join(_LOCAL_DB_DIR, "threats.db")
    except (OSError, PermissionError):
        os.makedirs(_CLOUD_DB_DIR, exist_ok=True)
        return os.path.join(_CLOUD_DB_DIR, "threats.db")

DB_PATH = _get_db_path()


class ThreatDataManager:

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    threat_name      TEXT NOT NULL,
                    threat_category  TEXT,
                    description      TEXT,
                    source_ip        TEXT,
                    cve_id           TEXT,
                    severity         INTEGER,
                    likelihood       INTEGER,
                    impact           INTEGER,
                    asset_type       TEXT,
                    user_role        TEXT,
                    environment      TEXT,
                    risk_score       REAL,
                    risk_level       TEXT,
                    context_factor   REAL,
                    timestamp        TEXT
                )
            """)

    def add_threat(self, record: dict):
        cols = list(record.keys())
        vals = list(record.values())
        placeholders = ", ".join(["?"] * len(cols))
        col_names = ", ".join(cols)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(f"INSERT INTO threats ({col_names}) VALUES ({placeholders})", vals)

    def get_threats(self) -> pd.DataFrame:
        with sqlite3.connect(DB_PATH) as conn:
            df = pd.read_sql_query("SELECT * FROM threats ORDER BY timestamp DESC", conn)
        return df

    def clear_all(self):
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM threats")

    def load_sample_data(self, engine):
        """Load realistic sample threat data for demo."""
        self.clear_all()

        samples = [
            # (name, category, severity, likelihood, impact, asset, role, env)
            ("SQL Injection on Payment DB", "SQL Injection", 9, 8, 10, "Database", "Admin", "External"),
            ("Ransomware - HR Workstation", "Ransomware", 8, 7, 9, "Workstation", "Standard User", "Internal"),
            ("Phishing Campaign - Finance", "Phishing", 6, 9, 7, "Workstation", "Standard User", "External"),
            ("Brute Force - Admin Portal", "Brute Force", 7, 8, 8, "Server", "Admin", "External"),
            ("Zero-Day Apache Exploit", "Zero-Day Exploit", 10, 5, 10, "Server", "Service Account", "DMZ"),
            ("DDoS - Public Web Server", "DDoS", 7, 9, 6, "Server", "Service Account", "External"),
            ("Insider Data Exfiltration", "Insider Threat", 8, 4, 9, "Database", "Admin", "Internal"),
            ("Malware - Contractor Laptop", "Malware", 6, 6, 5, "Workstation", "Guest", "Internal"),
            ("Cloud Misconfiguration S3", "Other", 7, 8, 8, "Cloud Instance", "Service Account", "Cloud"),
            ("Man-in-the-Middle - WiFi", "Man-in-the-Middle", 7, 5, 7, "Network Device", "Standard User", "External"),
            ("Credential Stuffing Attack", "Brute Force", 6, 8, 6, "Server", "Standard User", "External"),
            ("Log4Shell Vulnerability", "Zero-Day Exploit", 10, 7, 10, "Server", "Service Account", "External"),
            ("Spear Phishing - C-Suite", "Phishing", 8, 6, 9, "Workstation", "Admin", "External"),
            ("Network Scan - Recon", "Other", 3, 9, 2, "Network Device", "Guest", "External"),
            ("Unauthorized DB Access", "Insider Threat", 7, 3, 8, "Database", "Standard User", "Internal"),
            ("Cryptominer on Cloud VM", "Malware", 5, 7, 4, "Cloud Instance", "Service Account", "Cloud"),
            ("ARP Spoofing - Internal", "Man-in-the-Middle", 6, 4, 6, "Network Device", "Guest", "Internal"),
            ("RDP Brute Force Attempt", "Brute Force", 7, 8, 7, "Server", "Admin", "External"),
            ("Suspicious PowerShell", "Malware", 6, 5, 6, "Workstation", "Standard User", "Internal"),
            ("API Key Exposed GitHub", "Other", 8, 9, 8, "Cloud Instance", "Service Account", "External"),
        ]

        base_date = datetime.datetime.now() - datetime.timedelta(days=29)

        for i, (name, cat, sev, lik, imp, asset, role, env) in enumerate(samples):
            result = engine.calculate_risk(
                severity=sev, likelihood=lik, impact=imp,
                asset_type=asset, user_role=role, environment=env
            )
            ts = base_date + datetime.timedelta(
                days=random.randint(0, 28),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )
            record = {
                "threat_name": name,
                "threat_category": cat,
                "description": f"Auto-generated sample: {name}",
                "source_ip": f"192.168.{random.randint(1,254)}.{random.randint(1,254)}",
                "cve_id": f"CVE-2024-{random.randint(1000,9999)}" if random.random() > 0.5 else "",
                "severity": sev, "likelihood": lik, "impact": imp,
                "asset_type": asset, "user_role": role, "environment": env,
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "context_factor": result["context_factor"],
                "timestamp": ts.isoformat()
            }
            self.add_threat(record)
    