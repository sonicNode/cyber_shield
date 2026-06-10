"""
20 Test Cases for Cyber Shield Website Threat Checker
Run this file directly:  python test_cases.py
It uses the heuristic scanner (no API key needed) for all 20 cases.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from website_checker import heuristic_scan, full_scan, extract_domain_ip

# ─────────────────────────────────────────────────────────────────────────────
# 20 TEST TARGETS
# ─────────────────────────────────────────────────────────────────────────────
# Format: (target, expected_level, description)
TEST_CASES = [
    # ── SAFE / Low Risk ───────────────────────────────────────────────────────
    ("https://google.com",           "Low",   "TC01 - Google (trusted site)"),
    ("https://github.com",           "Low",   "TC02 - GitHub (trusted developer site)"),
    ("https://wikipedia.org",        "Low",   "TC03 - Wikipedia (educational)"),
    ("https://stackoverflow.com",    "Low",   "TC04 - Stack Overflow (developer forum)"),
    ("https://microsoft.com",        "Low",   "TC05 - Microsoft (trusted corporate)"),

    # ── MEDIUM Risk (suspicious but not confirmed malicious) ──────────────────
    ("http://192.168.1.105",         "Medium","TC06 - Internal IP over HTTP"),
    ("http://some-site.xyz",         "Medium","TC07 - Suspicious TLD (.xyz)"),
    ("http://login-verify.tk",       "Medium","TC08 - High-risk TLD (.tk) + phishing keyword"),
    ("https://very-long-domain-name-that-looks-suspicious-update-now.com",
                                     "Medium","TC09 - Unusually long domain name"),
    ("http://update.account.secure.login.bank.com",
                                     "Medium","TC10 - Excessive subdomains + phishing keywords"),

    # ── HIGH Risk (multiple red flags) ────────────────────────────────────────
    ("http://paypal-secure-login.tk","High",  "TC11 - Phishing: PayPal + suspicious TLD"),
    ("http://microsoft-support-helpdesk-verify.xyz",
                                     "High",  "TC12 - Multiple phishing keywords + bad TLD"),
    ("http://192.168.0.1/admin/login.php?redirect=../../../etc/passwd",
                                     "High",  "TC13 - Path traversal attempt in URL"),
    ("http://amazon-account-verify-now-update.ml",
                                     "High",  "TC14 - Amazon phishing + .ml TLD"),
    ("http://185.220.101.45",        "High",  "TC15 - Raw external IP (Tor exit node range)"),

    # ── EDGE CASES ────────────────────────────────────────────────────────────
    ("https://apple-id-signin-update.com",
                                     "Medium","TC16 - Apple phishing keyword in domain"),
    ("http://file-download.top",     "Medium","TC17 - Suspicious TLD .top over HTTP"),
    ("http://xn--80akhbyknj4f.xn--p1ai",
                                     "Low",   "TC18 - Punycode domain (IDN)"),
    ("https://secure-banking-login.verify-account-now.suspicious-long-name.gq",
                                     "High",  "TC19 - Max red flags: TLD + keywords + long"),
    ("https://netflix-password-reset.accountant",
                                     "High",  "TC20 - Netflix phishing + .accountant TLD"),
]


# ─────────────────────────────────────────────────────────────────────────────
# RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_tests():
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  CYBER SHIELD — Website Threat Checker — 20 Test Cases{RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    passed = 0
    failed = 0
    results_log = []

    for i, (target, expected, desc) in enumerate(TEST_CASES, 1):
        result = heuristic_scan(target)
        actual = result["risk_level"]
        score  = result["risk_score"]
        flags  = result["flags"]

        ok = (actual == expected)
        status_sym = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
        if ok: passed += 1
        else:  failed += 1

        # Color the level
        level_color = RED if actual == "High" else (YELLOW if actual == "Medium" else GREEN)
        level_str   = f"{level_color}{actual}{RESET}"

        print(f"  [{status_sym}] {CYAN}{desc}{RESET}")
        print(f"         Target : {target}")
        print(f"         Score  : {score}/100   Level: {level_str}   Expected: {expected}")
        if flags:
            print(f"         Flags  : {'; '.join(flags)}")
        else:
            print(f"         Flags  : {GREEN}No suspicious patterns{RESET}")
        print()

        results_log.append({
            "id": i, "desc": desc, "target": target,
            "expected": expected, "actual": actual,
            "score": score, "flags": flags, "pass": ok
        })

    # Summary
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{'='*70}")
    print(f"  Total  : 20")
    print(f"  {GREEN}Passed : {passed}{RESET}")
    print(f"  {RED}Failed : {failed}{RESET}")
    pct = round(passed / 20 * 100)
    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
    print(f"  Result : [{bar}] {pct}%")
    print(f"{'='*70}\n")

    return results_log


if __name__ == "__main__":
    run_tests()
