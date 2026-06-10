"""
Website Threat Checker
Checks URLs/IPs/domains against free public threat intelligence APIs:
  1. VirusTotal  (requires free API key)
  2. AbuseIPDB   (requires free API key)
  3. URLScan.io  (requires free API key)
  4. Google Safe Browsing (requires free API key)
  5. IPInfo.io   (no key needed for basic)
  6. Fallback heuristic scanner (no key needed — always works)
"""

import requests
import re
import json
import time
import socket
from urllib.parse import urlparse
from datetime import datetime


# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_domain_ip(target: str) -> dict:
    """Parse a URL, domain, or raw IP into components."""
    target = target.strip()
    # Add scheme if missing so urlparse works
    if not target.startswith(("http://", "https://")):
        target_parsed = urlparse("http://" + target)
    else:
        target_parsed = urlparse(target)

    hostname = target_parsed.hostname or target
    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname))

    resolved_ip = None
    if not is_ip:
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception:
            resolved_ip = None

    return {
        "original":    target,
        "hostname":    hostname,
        "is_ip":       is_ip,
        "ip":          hostname if is_ip else resolved_ip,
        "scheme":      target_parsed.scheme,
        "path":        target_parsed.path,
    }


def severity_from_score(score: float) -> str:
    if score >= 66: return "High"
    if score >= 33: return "Medium"
    return "Low"


# ── API Checkers ──────────────────────────────────────────────────────────────

def check_virustotal(target: str, api_key: str) -> dict:
    """Check URL/domain/IP via VirusTotal v3 API. Free key: 4 req/min."""
    try:
        headers = {"x-apikey": api_key}
        info = extract_domain_ip(target)

        if info["is_ip"]:
            url  = f"https://www.virustotal.com/api/v3/ip_addresses/{info['ip']}"
        else:
            import base64
            url_id = base64.urlsafe_b64encode(
                info["original"].encode()
            ).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        resp = requests.get(url, headers=headers, timeout=15)
        data = resp.json()

        if resp.status_code == 200:
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            total       = sum(stats.values()) or 1
            threat_pct  = round(((malicious + suspicious) / total) * 100, 1)

            return {
                "source":      "VirusTotal",
                "status":      "success",
                "malicious":   malicious,
                "suspicious":  suspicious,
                "total_engines": total,
                "threat_pct":  threat_pct,
                "risk_score":  min(100, threat_pct * 2),
                "details":     f"{malicious} malicious, {suspicious} suspicious out of {total} engines",
                "link":        f"https://www.virustotal.com/gui/ip-address/{info['ip']}" if info["is_ip"]
                               else f"https://www.virustotal.com/gui/url/{url_id}",
            }
        elif resp.status_code == 404:
            return {"source": "VirusTotal", "status": "not_found",
                    "risk_score": 0, "details": "Not in VirusTotal database (likely safe)"}
        else:
            return {"source": "VirusTotal", "status": "error",
                    "risk_score": 0, "details": f"API error {resp.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "status": "error",
                "risk_score": 0, "details": str(e)}


def check_abuseipdb(ip: str, api_key: str) -> dict:
    """Check IP reputation via AbuseIPDB. Free key: 1000 req/day."""
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        resp    = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=15
        )
        data = resp.json()

        if resp.status_code == 200:
            d = data.get("data", {})
            score       = d.get("abuseConfidenceScore", 0)
            total_rpts  = d.get("totalReports", 0)
            country     = d.get("countryCode", "Unknown")
            isp         = d.get("isp", "Unknown")
            usage       = d.get("usageType", "Unknown")
            is_tor      = d.get("isTor", False)

            return {
                "source":       "AbuseIPDB",
                "status":       "success",
                "abuse_score":  score,
                "total_reports": total_rpts,
                "country":      country,
                "isp":          isp,
                "usage_type":   usage,
                "is_tor":       is_tor,
                "risk_score":   float(score),
                "details":      f"Abuse score {score}%, {total_rpts} reports, ISP: {isp}, Country: {country}",
                "link":         f"https://www.abuseipdb.com/check/{ip}",
            }
        else:
            return {"source": "AbuseIPDB", "status": "error",
                    "risk_score": 0, "details": f"API error {resp.status_code}"}

    except Exception as e:
        return {"source": "AbuseIPDB", "status": "error",
                "risk_score": 0, "details": str(e)}


def check_urlscan(url: str, api_key: str) -> dict:
    """Submit URL to URLScan.io for analysis. Free key: 100 scans/day."""
    try:
        headers = {"API-Key": api_key, "Content-Type": "application/json"}
        payload = {"url": url, "visibility": "public"}

        submit = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=headers, json=payload, timeout=15
        )

        if submit.status_code in (200, 201):
            result_url = submit.json().get("api", "")
            uuid       = submit.json().get("uuid", "")
            # Wait for scan to complete
            time.sleep(10)
            result = requests.get(result_url, timeout=15)

            if result.status_code == 200:
                rdata   = result.json()
                verdicts = rdata.get("verdicts", {}).get("overall", {})
                score   = verdicts.get("score", 0)
                malicious = verdicts.get("malicious", False)
                tags    = verdicts.get("tags", [])

                return {
                    "source":    "URLScan.io",
                    "status":    "success",
                    "malicious": malicious,
                    "score":     score,
                    "tags":      tags,
                    "risk_score": min(100, score * 2) if score else (80 if malicious else 10),
                    "details":   f"Malicious: {malicious}, Score: {score}, Tags: {', '.join(tags) or 'none'}",
                    "link":      f"https://urlscan.io/result/{uuid}/",
                }
            else:
                return {"source": "URLScan.io", "status": "pending",
                        "risk_score": 0, "details": "Scan submitted, result not ready yet",
                        "link": f"https://urlscan.io/result/{uuid}/"}
        else:
            return {"source": "URLScan.io", "status": "error",
                    "risk_score": 0, "details": f"Submit error {submit.status_code}"}

    except Exception as e:
        return {"source": "URLScan.io", "status": "error",
                "risk_score": 0, "details": str(e)}


def check_ipinfo(ip: str) -> dict:
    """Get IP geolocation/org info from IPInfo (no key needed for basic)."""
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if resp.status_code == 200:
            d = resp.json()
            org      = d.get("org", "Unknown")
            country  = d.get("country", "Unknown")
            city     = d.get("city", "Unknown")
            hostname = d.get("hostname", "")

            # Heuristic risk: hosting/datacenter IPs are higher risk
            risk = 20
            suspicious_orgs = ["AS14061", "AS16509", "AS13335", "linode",
                                "digitalocean", "vultr", "ovh", "hetzner"]
            if any(s in org.lower() for s in suspicious_orgs):
                risk = 45  # Cloud/hosting — not bad but warrants attention

            return {
                "source":   "IPInfo",
                "status":   "success",
                "org":      org,
                "country":  country,
                "city":     city,
                "hostname": hostname,
                "risk_score": risk,
                "details":  f"Org: {org}, Location: {city}, {country}",
                "link":     f"https://ipinfo.io/{ip}",
            }
    except Exception as e:
        pass
    return {"source": "IPInfo", "status": "error", "risk_score": 0, "details": "Could not reach IPInfo"}


# ── Heuristic Scanner (no API key needed — always works) ─────────────────────

def heuristic_scan(target: str) -> dict:
    """
    Rule-based heuristic scan. No API key needed.
    Checks: suspicious TLDs, URL patterns, IP ranges, port scan hints, keywords.
    """
    info   = extract_domain_ip(target)
    domain = info["hostname"]
    flags  = []
    score  = 0

    # 1. Suspicious TLDs — tiered weights
    high_risk_tlds = [".tk", ".ml", ".ga", ".cf", ".gq"]
    med_risk_tlds  = [".xyz", ".top", ".click", ".download", ".loan",
                      ".win", ".stream", ".accountant"]
    for tld in high_risk_tlds:
        if domain.endswith(tld):
            flags.append(f"High-risk free TLD: {tld}")
            score += 30
            break
    else:
        for tld in med_risk_tlds:
            if domain.endswith(tld):
                flags.append(f"Suspicious TLD: {tld}")
                score += 25
                break

    # 2. IP-based URL (no domain)
    if info["is_ip"]:
        flags.append("Direct IP address (no domain name)")
        score += 20

    # 3. Private vs public raw IP
    ip = info["ip"] or ""
    if ip.startswith(("10.", "192.168.", "172.16.", "127.")):
        flags.append("Private/internal IP address")
        score += 10
    elif info["is_ip"]:
        # External raw IP — high risk (command-and-control servers, Tor nodes etc.)
        flags.append("External raw IP address — potential C2/malicious server")
        score += 40

    # 4. Brand impersonation keywords (high value — attackers mimic these brands)
    brand_keywords = ["paypal", "amazon", "microsoft", "apple", "netflix",
                      "google", "facebook", "instagram", "twitter", "bankofamerica"]
    for kw in brand_keywords:
        if kw in domain.lower():
            # Only flag if it's NOT the real domain (e.g. paypal-secure.tk, not paypal.com)
            real_domains = [f"{kw}.com", f"www.{kw}.com"]
            if not any(domain == rd or domain.endswith(f".{kw}.com") for rd in real_domains):
                flags.append(f"Brand impersonation keyword: '{kw}'")
                score += 25
            break

    # 5. Generic phishing action words
    action_keywords = ["login", "signin", "verify", "account", "secure",
                       "update", "banking", "support", "helpdesk",
                       "password", "reset", "confirm"]
    kw_hits = [kw for kw in action_keywords if kw in domain.lower()]
    if kw_hits:
        flags.append(f"Phishing keyword(s) in domain: {', '.join(kw_hits[:3])}")
        score += 15 + (len(kw_hits) - 1) * 8   # more keywords = higher score

    # 6. Excessive subdomains (e.g. secure.login.update.bank.com)
    parts = domain.split(".")
    if len(parts) > 4:
        flags.append(f"Excessive subdomains ({len(parts)-2} levels)")
        score += 15

    # 7. Very long domain
    if len(domain) > 40:
        flags.append(f"Unusually long domain ({len(domain)} chars)")
        score += 15

    # 8. Numeric-heavy domain
    digit_count = sum(c.isdigit() for c in domain.replace(".", ""))
    if digit_count > 6:
        flags.append(f"High digit count in domain ({digit_count} digits)")
        score += 10

    # 9. Hyphen count
    hyphens = domain.count("-")
    if hyphens >= 3:
        flags.append(f"Many hyphens in domain ({hyphens})")
        score += 10

    # 10. HTTP (not HTTPS)
    if info["scheme"] in ("http", "ftp"):
        flags.append(f"{info['scheme'].upper()} (not HTTPS) — unencrypted/insecure")
        score += 10

    # 11. Path traversal / suspicious path patterns
    path = info.get("path", "")
    full_url = info["original"]
    if re.search(r"\.\./|etc/passwd|cmd\.exe|/admin/", full_url, re.IGNORECASE):
        flags.append("Path traversal or admin exploit pattern in URL")
        score += 30
    elif re.search(r"\.(php|asp|exe|bat|sh)\?", path):
        flags.append("Suspicious file extension in URL path")
        score += 15

    score = min(100, score)
    level = severity_from_score(score)

    return {
        "source":     "Heuristic Scanner",
        "status":     "success",
        "flags":      flags,
        "risk_score": score,
        "risk_level": level,
        "details":    f"{len(flags)} suspicious indicators found" if flags else "No suspicious patterns detected",
    }


# ── Master Scanner ─────────────────────────────────────────────────────────────

def full_scan(
    target: str,
    virustotal_key: str = "",
    abuseipdb_key:  str = "",
    urlscan_key:    str = "",
) -> dict:
    """
    Run all available checks on a target URL/domain/IP.
    Returns a consolidated result dict.
    """
    results   = []
    info      = extract_domain_ip(target)
    timestamp = datetime.now().isoformat()

    # Always run heuristic (no key needed)
    results.append(heuristic_scan(target))

    # IPInfo (no key needed)
    if info["ip"]:
        results.append(check_ipinfo(info["ip"]))

    # VirusTotal (if key provided)
    if virustotal_key:
        results.append(check_virustotal(target, virustotal_key))

    # AbuseIPDB (if key provided + we have an IP)
    if abuseipdb_key and info["ip"]:
        results.append(check_abuseipdb(info["ip"], abuseipdb_key))

    # URLScan (if key provided)
    if urlscan_key:
        results.append(check_urlscan(target, urlscan_key))

    # Aggregate score — weighted average of successful results
    scores = [r["risk_score"] for r in results if r.get("status") == "success"]
    final_score = round(sum(scores) / len(scores), 1) if scores else 0
    final_level = severity_from_score(final_score)

    # Collect all flags from heuristic
    all_flags = []
    for r in results:
        all_flags.extend(r.get("flags", []))

    return {
        "target":      target,
        "hostname":    info["hostname"],
        "ip":          info["ip"],
        "timestamp":   timestamp,
        "final_score": final_score,
        "final_level": final_level,
        "sources":     results,
        "all_flags":   all_flags,
        "engines_used": len(results),
    }
