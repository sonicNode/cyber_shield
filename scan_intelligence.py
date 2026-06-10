import streamlit as st
import pandas as pd


def show_scan_intelligence():

    st.title("Scan Intelligence Center")

    data = [
        {
            "Target": "192.168.1.10",
            "Attack Type": "SQL Injection",
            "Affected Asset": "Payment Database",
            "Affected Component": "Login API",
            "Severity": "High",
            "Risk Score": 84,
            "Timestamp": "2026-05-12 10:30 AM",
            "Attack Source": "External IP",
            "Mitigation": "Use parameterized queries"
        },

        {
            "Target": "example.com",
            "Attack Type": "FTP Exposure",
            "Affected Asset": "File Server",
            "Affected Component": "FTP Port 21",
            "Severity": "Medium",
            "Risk Score": 61,
            "Timestamp": "2026-05-12 11:10 AM",
            "Attack Source": "Unknown Scanner",
            "Mitigation": "Disable anonymous FTP"
        }
    ]

    df = pd.DataFrame(data)

    st.dataframe(df, use_container_width=True)

    st.subheader("Detailed Investigation")

    selected = st.selectbox(
        "Select Scan",
        df["Target"]
    )

    row = df[df["Target"] == selected].iloc[0]

    st.markdown("---")

    st.subheader("Threat Details")

    st.write("Attack Type:", row["Attack Type"])
    st.write("Affected Asset:", row["Affected Asset"])
    st.write("Affected Component:", row["Affected Component"])
    st.write("Severity:", row["Severity"])
    st.write("Risk Score:", row["Risk Score"])
    st.write("Attack Source:", row["Attack Source"])

    st.subheader("Mitigation")

    st.warning(row["Mitigation"])