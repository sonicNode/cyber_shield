"""
AI Engine: ML Threat Classifier + AI Chat Analyst
Uses Random Forest for classification, Claude API for chat
"""

import streamlit as st
import pandas as pd
import numpy as np
import json
import google.generativeai as genai
import os
import requests
from typing import Optional

# ── Label encoders (simple mapping, no sklearn LabelEncoder needed) ────────────
ASSET_MAP = {
    "Server": 5, "Database": 1, "Network Device": 3,
    "Cloud Instance": 0, "Workstation": 6, "Mobile Device": 2
}
ROLE_MAP = {
    "Admin": 0, "Service Account": 2, "Standard User": 3, "Guest": 1
}
ENV_MAP = {
    "External": 1, "DMZ": 0, "Cloud": 0, "Internal": 2
}
RISK_MAP = {"Low": 0, "Medium": 1, "High": 2}
RISK_INV = {0: "Low", 1: "Medium", 2: "High"}


class AIThreatAnalyzer:

    def __init__(self):
        self._model = None
        self._trained = False
        self._feature_names = ["severity", "likelihood", "impact",
                                "asset_encoded", "role_encoded", "env_encoded"]

    # ── ML: Train ──────────────────────────────────────────────────────────────
    def train_model(self, df: pd.DataFrame) -> dict:
        try:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            from sklearn.metrics import accuracy_score, precision_score, recall_score
            from sklearn.preprocessing import LabelEncoder

            data = df.copy()
            data["asset_encoded"] = data["asset_type"].map(ASSET_MAP).fillna(3)
            data["role_encoded"]  = data["user_role"].map(ROLE_MAP).fillna(2)
            data["env_encoded"]   = data["environment"].map(ENV_MAP).fillna(2)
            data["risk_encoded"]  = data["risk_level"].map(RISK_MAP)

            X = data[self._feature_names].values
            y = data["risk_encoded"].values

            if len(set(y)) < 2:
                return {"success": False, "error": "Need at least 2 different risk levels"}

            test_size = 0.2 if len(X) >= 10 else 0.0
            if test_size > 0:
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, random_state=42
                )
            else:
                X_train, X_test, y_train, y_test = X, X, y, y

            clf = RandomForestClassifier(
                n_estimators=100, max_depth=8,
                random_state=42, class_weight="balanced"
            )
            clf.fit(X_train, y_train)
            self._model = clf
            self._trained = True

            y_pred = clf.predict(X_test)
            acc  = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, average="weighted", zero_division=0)
            rec  = recall_score(y_test, y_pred, average="weighted", zero_division=0)

            fi = clf.feature_importances_.tolist()

            return {
                "success": True,
                "accuracy": acc,
                "precision": prec,
                "recall": rec,
                "feature_names": self._feature_names,
                "feature_importance": fi
            }

        except ImportError:
            return {"success": False, "error": "scikit-learn not installed"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ── ML: Predict ───────────────────────────────────────────────────────────
    def predict(self, severity, likelihood, impact, asset_type, user_role, environment) -> dict:
        if not self._trained or self._model is None:
            return {"success": False, "prediction": None, "probabilities": {}}

        asset_enc = ASSET_MAP.get(asset_type, 3)
        role_enc  = ROLE_MAP.get(user_role, 2)
        env_enc   = ENV_MAP.get(environment, 2)

        X = np.array([[severity, likelihood, impact, asset_enc, role_enc, env_enc]])
        pred     = self._model.predict(X)[0]
        probs    = self._model.predict_proba(X)[0]
        classes  = self._model.classes_

        prob_dict = {RISK_INV[c]: round(float(p), 3) for c, p in zip(classes, probs)}
        # Ensure all keys present
        for k in ["Low", "Medium", "High"]:
            prob_dict.setdefault(k, 0.0)

        return {
            "success": True,
            "prediction": RISK_INV[pred],
            "probabilities": prob_dict
        }

    # ── AI Chat ───────────────────────────────────────────────────────────────
    def chat(self, user_message: str, context_summary: str, history: list) -> str:
        """Call Gemini API for security analyst chat."""
        try:
            system_prompt = f"""You are CyberShield AI, an expert cybersecurity analyst assistant.
You help security teams understand and prioritize threats using context-aware risk scoring.

Your expertise:
- Threat intelligence analysis and prioritization
- CVSS scoring and risk assessment frameworks  
- Incident response and mitigation strategies
- Common attack vectors: malware, phishing, SQLi, DDoS, ransomware, etc.
- Zero Trust, NIST frameworks, CIS controls

Current threat database context:
{context_summary if context_summary else "No threat data loaded yet."}

Provide concise, actionable, expert-level responses.
Use emojis sparingly for readability. Format with markdown when helpful.
Always ground recommendations in the user's actual data when available."""

            # Try st.secrets first (Streamlit Cloud), then env var (local)
            api_key = None
            try:
                api_key = st.secrets["GEMINI_API_KEY"]
            except (KeyError, FileNotFoundError, AttributeError):
                api_key = os.getenv("GEMINI_API_KEY", "")
            
            if not api_key:
                return self._fallback_response(user_message, context_summary)
            
            client = genai.Client(api_key=api_key)

            full_prompt = f"{system_prompt}\n\nUser question: {user_message}"
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=full_prompt
            )

            return response.text + "\n\n---\n*🤖 Powered by Gemini AI*"

        except requests.exceptions.Timeout:
            return "⚠️ Request timed out. Please try again."
        except Exception as e:
            # Fallback: rule-based response with error details
            return self._fallback_response(user_message, context_summary, error_msg=str(e))

    def _fallback_response(self, question: str, context: str, error_msg: Optional[str] = None) -> str:
        """Simple rule-based fallback when API is unavailable."""
        badge = "\n\n---\n*⚙️ Offline mode — rule-based response (configure Gemini API key for AI-powered answers)*"
        if error_msg:
            badge += f"\n\n*(Error info: {error_msg})*"
        q = question.lower()
        if "top risk" in q or "highest" in q or "critical" in q:
            return ("🔴 **Top Risk Threats**\n\nBased on your data, focus on High-risk threats "
                    "with scores above 66. These require immediate attention and isolation. "
                    "Check the Dashboard for the Top 5 Critical Threats widget." + badge)
        if "mitigat" in q or "fix" in q or "remediat" in q:
            return ("🛡️ **Mitigation Priorities**\n\n"
                    "1. **High Risk**: Isolate immediately, patch within 24h\n"
                    "2. **Medium Risk**: Patch within 72h, increase monitoring\n"
                    "3. **Low Risk**: Include in next scheduled maintenance\n\n"
                    "Always follow your incident response playbook for High-risk threats." + badge)
        if "sql" in q:
            return ("💉 **SQL Injection Mitigation**\n\n"
                    "- Use parameterized queries / prepared statements\n"
                    "- Input validation and sanitization\n"
                    "- Web Application Firewall (WAF)\n"
                    "- Principle of least privilege on DB accounts\n"
                    "- Regular security code reviews" + badge)
        return ("I'm your CyberShield AI analyst. I can help you:\n"
                "- Analyze your top threats and priorities\n"
                "- Recommend mitigations for specific attack types\n"
                "- Explain risk scores and context factors\n"
                "- Guide incident response procedures\n\n"
                "What would you like to know about your threat landscape?" + badge)
