```markdown
# CISA Threat Intel Scraper

A small Python script that scrapes CISA's (US Cybersecurity and Infrastructure Security Agency) public cybersecurity advisories page, pulls out the title, any CVE numbers mentioned, a short summary, and the source link, then saves it all to a CSV.

I built this to understand how security teams actually track new vulnerabilities as they're published, instead of someone manually checking CISA's site every day. It's also a step up from my earlier regex log parser project, same core skill (regex + structured extraction), applied to live web data instead of log files this time.

## What it does

1. Requests CISA's advisories page and parses the HTML with BeautifulSoup.
2. Tries a specific, reliable way to find advisory elements first. If CISA's page structure doesn't match (sites change their layout over time), it falls back to a looser, more generic search so the scraper doesn't just break completely.
3. Pulls out the title, link, and a short summary for each advisory.
4. Uses regex to find any CVE IDs mentioned (format: `CVE-YYYY-NNNNN`).
5. Removes duplicate entries and saves everything to `live_threat_feed.csv`.

## Example output

```

[1] Advanced Cyber Actors Exploiting Multiple Vulnerabilities
    CVE Tags: CVE-2026-45371, CVE-2026-38291
    URL: https://cisa.gov/...

[+] Compiled 15 live threat advisories into 'live_threat_feed.csv'
```

## How to run

```bash
pip install requests beautifulsoup4
python cisa_threat_scraper.py
```

## A real limitation, worth knowing

This is web scraping, not an official API, so it's fragile by nature. If CISA redesigns their site, this can silently break or return messy results. The two-tier search (specific first, generic fallback) is there to handle smaller layout changes, but a full redesign would need the scraper updated.

## What I'd improve next

- Switch to CISA's actual API or RSS feed if one exists, more reliable than scraping
- Add filtering by severity or specific vendor/product
- Schedule it to run automatically and alert on new CVEs, instead of running manually

## Why I built this

Security work depends on knowing about new vulnerabilities fast. This was a way to learn how that kind of monitoring actually gets automated, and to practice the regex and data extraction skills from my earlier log analyzer project on a live, real-world source instead of generated test data.
```
