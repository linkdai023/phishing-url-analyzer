# Phishing URL Risk Analyzer

Enter a URL to see its estimated risk level and the reasons behind it.

A learning project built with Python and FastAPI.
## Evaluation (2026-11-21)

**Data**
- Phishing: 300 URLs from the OpenPhish community feed
- Benign: Tranco top 300 domains (as `https://` homepages) + 388 legitimate
  sites on free hosting platforms, extracted from popular curated GitHub lists

**Results**

| Threshold | Recall | False positives (of 688) |
|---|---|---|
| 20 | 82.3% | 393 |
| 30 | 30.7% | 27 |

**Findings**
- 82% of missed phishing URLs are on free hosting platforms (pages.dev, blogspot.com, ...).
- A "free hosting" signal alone cannot separate phishing from legitimate sites:
  at threshold 20 every legitimate free-hosted site is flagged.
- Next step: analyze the subdomain itself (brand words, digits, login keywords).

**Limitations**
- Tranco benign URLs are homepages we built ourselves, so the HTTP rule's false
  positives cannot be measured on that part.
- The free-hosting benign set is mostly tech sites on github.io, while phishing is
  mostly on pages.dev and blogspot.com.
- The PhiUSIIL dataset was checked and rejected: all its legitimate URLs are
  HTTPS homepages with no paths.