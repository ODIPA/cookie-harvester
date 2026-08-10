# ODIPA Cookie Harvester & Analyzer

**ODIPA Open-Source Privacy Tool** · [odipa.org](https://odipa.org) · MIT License

Visits a target domain using a headless Chromium browser, harvests all cookies set during the session, classifies them by purpose (analytics, advertising, functional, strictly necessary), and outputs a structured JSON or CSV audit report designed for CCPA and GDPR cookie disclosure audits.

---

## Development Transparency

This tool was developed by ODIPA with AI-assisted development and is maintained by ODIPA, which accepts contributions, and is responsible for its accuracy and ongoing maintenance.

This tool is not part of any ODIPA commercial product or affiliate entity. It is a free, standalone open-source contribution to the privacy community.

---

## Quick Start

```bash
pip install playwright requests tldextract
playwright install chromium

python cookie_harvester.py example.com
python cookie_harvester.py example.com --format csv --output cookies.csv
python cookie_harvester.py example.com --wait 5 --scroll
```

---

## Output

**JSON** (default): Full structured report with metadata, summary, risk score, compliance notes, and per-cookie classification.

**CSV**: Flat table of cookies with name, domain, party, category, and retention.

---

## Cookie Categories

| Category | Description |
|---|---|
| Strictly Necessary | Required for site function. No consent needed under GDPR. |
| Analytics & Performance | Tracks usage. Requires prior consent under GDPR. Opt-out rights under CCPA. |
| Advertising & Targeting | Builds ad profiles. Requires prior consent under GDPR. Requires opt-out link under CCPA. |
| Functional | Personalization. Often requires consent depending on jurisdiction. |
| Unknown | Could not be classified. Manual review recommended. |

---

## Intended Use

This tool is designed for:
- **Website owners** auditing their own sites for GDPR/CCPA compliance
- **Privacy professionals** conducting authorized third-party audits
- **Researchers** studying cookie practices across the web
- **Developers** verifying that their implementations match their cookie policy disclosures

---

## Legal Implications

**Before using this tool, read this section carefully.**

### Scanning your own site
Scanning a website you own or are explicitly authorized to audit is lawful in all major jurisdictions. This is the primary intended use case.

### Scanning third-party sites
The legal status of automated scanning of third-party websites varies by jurisdiction and context:

- **United States**: The Computer Fraud and Abuse Act (CFAA) prohibits unauthorized access to computer systems. Courts have interpreted "authorization" inconsistently. *hiQ Labs v. LinkedIn* (9th Cir. 2022) offered some protection for scanning publicly accessible data, but this remains unsettled law, particularly for automated tools.
- **European Union**: GDPR Article 6 requires a lawful basis for any personal data processing. Scanning a third-party site may incidentally encounter personal data. Research and legitimate interest bases may apply but are context-dependent. Always document your legal basis before conducting third-party audits.
- **UK**: Similar considerations apply under the Computer Misuse Act 1990 and UK GDPR.

### What this tool does NOT do
- Does not collect, store, or transmit any end-user personal data
- Does not bypass authentication or access private pages
- Does not circumvent cookie consent banners to access cookies that would otherwise be blocked
- Reads only cookies set during a standard, unauthenticated browsing session

### Classification accuracy
Cookie classification uses name pattern matching and known tracker domains. It is **not legally authoritative**. Always verify classifications before including them in a compliance report or legal filing.

### Not legal advice
Output from this tool does not constitute legal advice. Do not submit results as evidence of compliance or non-compliance without review by a qualified privacy attorney. ODIPA is a nonprofit education organization, not a law firm.

---

## Options

```
positional:
  url               Target URL (e.g. example.com or https://example.com)

optional:
  --format          json (default) or csv
  --output / -o     Output file path (default: stdout)
  --wait / -w       Seconds to wait after page load for deferred cookies (default: 3)
  --scroll          Scroll page to trigger lazy-loaded scripts
  --quiet / -q      Suppress summary output
```

---

## Contributing

Issues and pull requests welcome. Classification rules and tracker patterns are the most valuable area for community contribution as the cookie ecosystem evolves.

---

---

## Disclaimer & Limitation of Liability

**By downloading, installing, or using this tool, you acknowledge that you have read this disclaimer and accept full responsibility for your use of the tool.**

### User responsibility
You are solely responsible for how you use this tool, including any consequences arising from scanning websites you do not own or are not authorized to audit. ODIPA provides this tool as-is for educational, research, and authorized audit purposes. ODIPA does not control how you deploy it.

### ODIPA is not liable for misuse
ODIPA, its board members, officers, volunteers, and contributors are not liable for:
- Any legal action taken against you by a website operator, data broker, or third party as a result of your use of this tool
- Violations of any website's Terms of Service that result from your use of this tool
- Any civil or criminal liability arising from your use of this tool in jurisdictions where such use may be restricted
- Any damages, direct, indirect, incidental, consequential, or punitive, resulting from your use of or inability to use this tool

### Third-party Terms of Service
Many websites prohibit automated access in their Terms of Service. **It is your responsibility to review and comply with the Terms of Service of any website you scan using this tool before doing so.** ODIPA does not warrant that use of this tool is permissible under any particular website's terms, and ODIPA will not defend or indemnify you in any dispute arising from a ToS violation.

### Jurisdictional variation
Laws governing automated access to websites, data collection, and privacy vary by country, state, and context. What is lawful in one jurisdiction may not be lawful in another. **You are responsible for ensuring your use of this tool complies with all applicable laws in your jurisdiction.**

### No endorsement of misuse
ODIPA's mission is to protect digital privacy. This tool is intended to help users understand and audit data practices on websites they own or are authorized to review. Any use of this tool to harass, surveil, or harm individuals or organizations is explicitly prohibited and contrary to ODIPA's mission.

## License

MIT License. Free for personal, research, and commercial use with attribution.
