# Phishing URL Risk Analyzer

Enter a URL to see its estimated risk level and the reasons behind it.

A learning project built with Python and FastAPI.
## Evaluation (baseline, 2026-11-21)

- Data: 300 OpenPhish URLs + Tranco top 300 domains
- Rules: http, @, IP host, punycode, brand impersonation
- Precision: 84.4%, Recall: 38.0%
- Main false positives: brand rule uses substring match (e.g. amazonaws.com)
- Main misses: free hosting subdomains, brands not in list, typosquatting