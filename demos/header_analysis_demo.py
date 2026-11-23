
from analyzers.header_analyzer import analyze_headers


sample_headers = """From: Security Team <security@example.com>
Reply-To: help@different-example.com
Return-Path: bounce@example.com
Authentication-Results: mail.example.com; spf=fail; dkim=pass; dmarc=fail
Subject: Account Verification
"""


result = analyze_headers(sample_headers)

print("\n========== HEADER ANALYSIS ==========")
print("Valid:", result["valid"])
print("Risk:", result["risk"])
print("Score:", result["score"])

for indicator in result["indicators"]:
    print("-", indicator)
