"""
Context-Aware Threat Intelligence Scoring Engine  v2
Formula: Risk = (Severity + Likelihood + Impact) × Context Factor
Includes: deep category-specific mitigation strategies,
          NIST framework mapping, priority timelines, tools list.
"""


class ContextAwareScoringEngine:

    ASSET_WEIGHTS = {
        "Server": 1.5, "Database": 1.6, "Network Device": 1.4,
        "Cloud Instance": 1.3, "Workstation": 1.1, "Mobile Device": 0.9,
    }
    USER_ROLE_WEIGHTS = {
        "Admin": 1.5, "Service Account": 1.3, "Standard User": 1.0, "Guest": 0.8,
    }
    ENVIRONMENT_WEIGHTS = {
        "External": 1.4, "DMZ": 1.3, "Cloud": 1.2, "Internal": 1.0,
    }
    RISK_THRESHOLDS = {"High": 66, "Medium": 33, "Low": 0}

    CATEGORY_MITIGATIONS = {
        "SQL Injection": {
            "immediate": [
                "Block the attacking IP at the WAF/firewall immediately",
                "Disable the vulnerable endpoint temporarily",
                "Rotate all database credentials right now",
                "Enable read-only mode on the database if possible",
            ],
            "short_term": [
                "Replace all dynamic SQL with parameterized queries / prepared statements",
                "Implement strict input validation and whitelist-based sanitization",
                "Deploy or update WAF rules for SQLi patterns",
                "Conduct full code review of all database interaction layers",
                "Apply least-privilege: DB accounts only get required permissions",
            ],
            "long_term": [
                "Integrate SAST/DAST scanning into your CI/CD pipeline",
                "Implement an ORM to abstract raw SQL entirely",
                "Schedule quarterly penetration testing for injection vulnerabilities",
                "Developer training on OWASP Top 10 — specifically A03:2021 Injection",
                "Add Database Activity Monitoring (DAM) to detect anomalous queries",
            ],
            "tools": ["OWASP ZAP", "SQLMap (defensive audit)", "ModSecurity WAF", "Snyk", "Burp Suite"],
            "nist": "NIST CSF: Protect (PR.DS-1, PR.AC-4) | OWASP A03:2021",
            "timeline": "Immediate: 0–2 hrs | Short-term: 24–72 hrs | Long-term: 30–90 days",
        },
        "Ransomware": {
            "immediate": [
                "IMMEDIATELY disconnect infected systems from network (unplug ethernet/WiFi)",
                "Do NOT pay the ransom — contact CERT-In / local cybercrime cell",
                "Preserve encrypted files and ransom note for forensic analysis",
                "Identify the ransomware strain via nomoreransom.org",
                "Alert all users to not open suspicious attachments",
            ],
            "short_term": [
                "Restore from most recent clean backup (verify integrity first)",
                "Conduct full EDR scan on ALL machines in the network",
                "Reset all credentials — assume passwords on infected systems are compromised",
                "Identify the initial attack vector (phishing / RDP / unpatched software)",
                "Patch all systems — especially RDP vulnerabilities",
            ],
            "long_term": [
                "Implement 3-2-1 backup rule: 3 copies, 2 media types, 1 offsite/offline",
                "Deploy EDR solution on all endpoints",
                "Enable application whitelisting",
                "Disable RDP if not required; use VPN + MFA for remote access",
                "Conduct regular ransomware tabletop exercises",
                "Segment the network to prevent lateral spread",
            ],
            "tools": ["Malwarebytes", "CrowdStrike Falcon", "Veeam Backup", "Microsoft Defender ATP", "No More Ransom"],
            "nist": "NIST CSF: Respond (RS.RP-1) + Recover (RC.RP-1) | NIST SP 800-184",
            "timeline": "Immediate: 0–1 hr | Short-term: 1–7 days | Long-term: 30–60 days",
        },
        "Phishing": {
            "immediate": [
                "Reset credentials of the affected user immediately",
                "Revoke and reissue tokens/sessions for the compromised account",
                "Block the phishing domain/sender at the email gateway",
                "Alert all employees about the active phishing campaign",
            ],
            "short_term": [
                "Enable MFA on ALL accounts — especially email and VPN",
                "Deploy DMARC, DKIM, and SPF email authentication records",
                "Configure email gateway to flag [EXTERNAL] emails",
                "Run phishing simulation exercises to identify vulnerable staff",
                "Implement browser URL reputation filtering",
            ],
            "long_term": [
                "Establish mandatory annual phishing awareness training",
                "Deploy AI-powered email security (Microsoft Defender for O365)",
                "Implement Zero Trust — never trust, always verify",
                "Use FIDO2 hardware security keys for privileged accounts",
                "Create a phishing report button in the email client",
            ],
            "tools": ["Microsoft Defender for O365", "Proofpoint", "KnowBe4", "Mimecast", "Google Workspace Protect"],
            "nist": "NIST CSF: Protect (PR.AT-1) + Detect (DE.CM-1) | MITRE ATT&CK T1566",
            "timeline": "Immediate: 0–4 hrs | Short-term: 24–48 hrs | Long-term: 60–90 days",
        },
        "Malware": {
            "immediate": [
                "Isolate the infected machine from the network immediately",
                "Run full offline AV scan using a bootable rescue disk",
                "Collect memory dump and system logs for forensics",
                "Block C2 IP/domain at the firewall",
            ],
            "short_term": [
                "Reimage the infected system — do not try to clean advanced malware",
                "Scan all systems that had network contact with the infected machine",
                "Audit all startup entries, scheduled tasks, and registry run keys",
                "Update all software, OS patches, and AV signatures fleet-wide",
            ],
            "long_term": [
                "Deploy EDR with behavioral detection (not signature-only)",
                "Implement application whitelisting policies",
                "Use DNS filtering (Cisco Umbrella) to block malicious domains",
                "Enable PowerShell Script Block Logging",
                "Regular vuln scanning with automated patching workflows",
            ],
            "tools": ["CrowdStrike", "SentinelOne", "Malwarebytes EDR", "Cisco Umbrella", "Sysmon + Splunk"],
            "nist": "NIST CSF: Detect (DE.CM-4) + Respond (RS.MI-2) | MITRE ATT&CK T1204",
            "timeline": "Immediate: 0–2 hrs | Short-term: 24–72 hrs | Long-term: 30–90 days",
        },
        "DDoS": {
            "immediate": [
                "Enable DDoS protection on your cloud provider (AWS Shield / Azure DDoS)",
                "Contact ISP to implement upstream traffic scrubbing",
                "Rate-limit connections at the load balancer / CDN level",
                "Null-route primary attacking IP ranges",
                "Activate your availability-incident response runbook",
            ],
            "short_term": [
                "Redirect traffic through Cloudflare / Akamai DDoS scrubbing",
                "Implement CAPTCHA / challenge pages for suspicious sources",
                "Scale out horizontally using auto-scaling groups",
                "Analyze logs to separate legitimate from attack traffic",
            ],
            "long_term": [
                "Subscribe to dedicated DDoS protection (Cloudflare Pro / AWS Shield Advanced)",
                "Architect apps to be stateless and horizontally scalable",
                "Implement anycast network diffusion",
                "Develop and test a DDoS response playbook quarterly",
                "Set up automated alerting for traffic spike anomalies",
            ],
            "tools": ["Cloudflare", "AWS Shield", "Akamai Kona", "Radware", "F5 BIG-IP"],
            "nist": "NIST CSF: Protect (PR.DS-4) + Respond (RS.MI-1) | CIS Control 13",
            "timeline": "Immediate: 0–30 min | Short-term: 1–24 hrs | Long-term: 30–60 days",
        },
        "Zero-Day Exploit": {
            "immediate": [
                "Apply vendor emergency patch / hotfix immediately if available",
                "If no patch: implement virtual patching via WAF/IPS rules",
                "Isolate affected systems and restrict network access",
                "Enable enhanced logging on affected components",
                "Monitor for IoCs published by vendor / CERT",
            ],
            "short_term": [
                "Subscribe to vendor security advisories and CVE feeds",
                "Deploy compensating controls: segmentation, access restrictions",
                "Conduct threat hunting in existing logs",
                "Engage DFIR retainer if exploitation is confirmed",
            ],
            "long_term": [
                "Implement formal vulnerability management with SLA-based patching",
                "Deploy Runtime Application Self-Protection (RASP)",
                "Use micro-segmentation to limit blast radius",
                "Subscribe to threat intelligence feeds (MISP, AlienVault OTX)",
                "Maintain a current asset inventory",
            ],
            "tools": ["Qualys VMDR", "Tenable.io", "MISP", "AlienVault OTX", "Snort/Suricata IPS"],
            "nist": "NIST CSF: Identify (ID.RA-1) + Protect (PR.IP-12) | CVSS v3",
            "timeline": "Immediate: 0–4 hrs | Short-term: 24–48 hrs | Long-term: 30–90 days",
        },
        "Brute Force": {
            "immediate": [
                "Lock the targeted account and force password reset",
                "Block attacking IPs at the firewall",
                "Enable MFA on the targeted service immediately",
                "Audit access logs — check if any attempt succeeded",
            ],
            "short_term": [
                "Implement account lockout (lock after 5 failed attempts)",
                "Enable CAPTCHA on all login forms",
                "Enforce strong password policy (12+ chars, complexity, no reuse)",
                "Deploy IP-based rate limiting on authentication endpoints",
                "Enable geo-location login alerts for unusual locations",
            ],
            "long_term": [
                "Deploy Privileged Access Management (PAM) for admin accounts",
                "Implement passwordless auth (FIDO2, Windows Hello)",
                "Enable conditional access based on risk score",
                "Integrate SIEM alerts for repeated failed login patterns",
                "Regular credential hygiene checks via HaveIBeenPwned API",
            ],
            "tools": ["Fail2Ban", "Microsoft Entra ID", "CyberArk PAM", "1Password", "Authy MFA"],
            "nist": "NIST CSF: Protect (PR.AC-7) | CIS Control 6",
            "timeline": "Immediate: 0–1 hr | Short-term: 24–48 hrs | Long-term: 30–60 days",
        },
        "Insider Threat": {
            "immediate": [
                "Revoke access of the suspected insider immediately",
                "Preserve all logs — do NOT alert the suspect (covert investigation)",
                "Engage HR and legal before taking further action",
                "Image the suspect's workstation before any changes",
            ],
            "short_term": [
                "Audit all data access and downloads for the past 30–90 days",
                "Review email forwarding rules and external cloud sharing",
                "Implement DLP policies if not already deployed",
                "Conduct access review — remove all unnecessary permissions",
            ],
            "long_term": [
                "Deploy User & Entity Behavior Analytics (UEBA)",
                "Enforce principle of least privilege across all systems",
                "Enforce separation of duties for sensitive operations",
                "Establish insider threat awareness program",
                "Quarterly access recertification campaigns",
            ],
            "tools": ["Microsoft Sentinel UEBA", "Varonis", "Forcepoint DLP", "Teramind", "ObserveIT"],
            "nist": "NIST SP 800-53 AC-2 | CERT Insider Threat Framework",
            "timeline": "Immediate: 0–2 hrs | Short-term: 24–72 hrs | Long-term: 60–90 days",
        },
        "Man-in-the-Middle": {
            "immediate": [
                "Terminate all active sessions on the affected network segment",
                "Force re-authentication of all users on the segment",
                "Disable the compromised switch port or access point",
                "Alert users to change passwords — credentials may be intercepted",
            ],
            "short_term": [
                "Enable HTTPS everywhere — enforce HSTS",
                "Implement certificate pinning for mobile and critical apps",
                "Enable Dynamic ARP Inspection (DAI) on managed switches",
                "Deploy 802.1X network access control for wired/wireless clients",
            ],
            "long_term": [
                "Migrate all internal services to TLS 1.3",
                "Implement network segmentation with encrypted VLANs",
                "Deploy PKI for internal certificate management",
                "Use mutual TLS (mTLS) for service-to-service communication",
                "Regular SSL/TLS audits using SSL Labs / testssl.sh",
            ],
            "tools": ["Wireshark (detection)", "Zeek IDS", "testssl.sh", "Let's Encrypt", "HashiCorp Vault PKI"],
            "nist": "NIST CSF: Protect (PR.DS-2) | CIS Control 12",
            "timeline": "Immediate: 0–2 hrs | Short-term: 24–48 hrs | Long-term: 30–90 days",
        },
        "Other": {
            "immediate": [
                "Isolate and contain the affected system",
                "Collect and preserve logs and evidence",
                "Notify the security team immediately",
            ],
            "short_term": [
                "Investigate root cause thoroughly",
                "Apply relevant patches and configuration fixes",
                "Review and tighten access controls",
            ],
            "long_term": [
                "Incorporate findings into security policy updates",
                "Schedule regular security audits",
                "Train staff on identified threat patterns",
            ],
            "tools": ["Splunk SIEM", "Wireshark", "Nessus", "OpenVAS"],
            "nist": "NIST CSF: Identify → Protect → Detect → Respond → Recover",
            "timeline": "Immediate: 0–4 hrs | Short-term: 24–72 hrs | Long-term: 30–90 days",
        },
    }

    ASSET_MITIGATIONS = {
        "Database": [
            "Enable database auditing — log all queries, logins, and schema changes",
            "Encrypt data at rest (AES-256) and in transit (TLS)",
            "Mask sensitive fields (PII) in non-production environments",
            "Use database firewalls to block anomalous query patterns",
        ],
        "Server": [
            "Harden OS using CIS Benchmarks",
            "Disable unused services, ports, and protocols",
            "Enable host-based IDS (OSSEC / Wazuh)",
        ],
        "Cloud Instance": [
            "Enforce least-privilege IAM — no wildcard (*) permissions",
            "Enable cloud security posture management (AWS Security Hub / Azure Defender)",
            "Tag all resources and enable anomaly/cost alerts",
        ],
        "Network Device": [
            "Change all default credentials on routers/switches/firewalls",
            "Enable syslog forwarding to central SIEM",
            "Disable Telnet — use SSH v2 only",
        ],
    }

    ENV_MITIGATIONS = {
        "External": [
            "Review all firewall rules — remove overly permissive rules",
            "Enable geo-blocking for regions with no business justification",
            "Ensure all external endpoints are in scope for vulnerability scanning",
        ],
        "DMZ": [
            "Enforce strict inbound/outbound filtering between DMZ and internal network",
            "Deploy a reverse proxy in front of all DMZ services",
        ],
        "Cloud": [
            "Enable CloudTrail / Azure Monitor audit logging",
            "Implement a Cloud Access Security Broker (CASB)",
        ],
    }

    def calculate_risk(self, severity, likelihood, impact,
                       asset_type, user_role, environment) -> dict:
        asset_w        = self.ASSET_WEIGHTS.get(asset_type, 1.0)
        role_w         = self.USER_ROLE_WEIGHTS.get(user_role, 1.0)
        env_w          = self.ENVIRONMENT_WEIGHTS.get(environment, 1.0)
        context_factor = round((asset_w + role_w + env_w) / 3, 3)
        base_score     = severity + likelihood + impact
        raw_score      = base_score * context_factor
        normalized     = min(100.0, round((raw_score / (30 * 1.6)) * 100, 2))

        if normalized >= self.RISK_THRESHOLDS["High"]:     risk_level = "High"
        elif normalized >= self.RISK_THRESHOLDS["Medium"]: risk_level = "Medium"
        else:                                              risk_level = "Low"

        return {
            "risk_score": normalized, "risk_level": risk_level,
            "context_factor": context_factor, "base_score": base_score,
            "raw_score": round(raw_score, 2),
            "asset_weight": asset_w, "role_weight": role_w, "env_weight": env_w,
        }

    def get_mitigations(self, threat_category, asset_type, environment, risk_level) -> dict:
        cat          = self.CATEGORY_MITIGATIONS.get(threat_category, self.CATEGORY_MITIGATIONS["Other"])
        asset_extras = self.ASSET_MITIGATIONS.get(asset_type, [])
        env_extras   = self.ENV_MITIGATIONS.get(environment, [])
        immediate    = ["No immediate action required — monitor and schedule fix"] if risk_level == "Low" else cat["immediate"]
        return {
            "immediate":      immediate,
            "short_term":     cat["short_term"],
            "long_term":      cat["long_term"],
            "asset_specific": asset_extras,
            "env_specific":   env_extras,
            "tools":          cat["tools"],
            "nist":           cat["nist"],
            "timeline":       cat["timeline"],
        }
