import os
import re
import csv
import requests
from bs4 import BeautifulSoup

def fetch_live_threat_intel():
    """
    Scrapes live security alerts from CISA with multi-tiered structural failovers.
    """
    url = "https://www.cisa.gov/news-events/cybersecurity-advisories"
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    }
    
    print("[*] Connecting to CISA Threat Intel Portal...")
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            print(f"[!] Access blocked. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"[!] Network interface exception: {str(e)}")
        return None

    print("[*] Content payload received. Executing DOM analysis...")
    soup = BeautifulSoup(response.text, "html.parser")
    intel_pool = []

    #  Standard CMS View Blocks
    advisories = soup.find_all("div", class_=re.compile(r"(views-row|c-teaser|card)"))
    
    # FALLBACK: Anchor-driven general link analysis 
    if not advisories:
        print("[!] Tier 1 structural targets missed. Activating Tier 2 generic anchor parsing...")
        advisories = soup.find_all(["article", "h3", "div"])

    for item in advisories:
        try:
            # Look for active anchor paths inside elements
            link_el = item.find("a") if hasattr(item, "find") else None
            if not link_el or not link_el.get("href"):
                if item.name == "a" and item.get("href"):
                    link_el = item
                else:
                    continue
            
            relative_link = link_el["href"]
            # Filter for meaningful advisory  / alert endpoints
            if not any(x in relative_link for x in ["/advisories/", "/alerts/", "/news-events/"]):
                continue
                
            full_link = relative_link if relative_link.startswith("http") else f"https://www.cisa.gov{relative_link}"
            title_text = link_el.text.strip()
            
            if len(title_text) < 15: # Ignore utility fragments or buttons
                continue

            # Context extraction using surrounding node structures
            summary_text = ""
            parent = item.parent if hasattr(item, 'parent') else None
            if parent:
                summary_el = parent.find(class_=re.compile(r"summary|teaser|description"))
                if summary_el:
                    summary_text = summary_el.text.strip()

            if not summary_text:
                summary_text = item.text.strip().replace(title_text, "").strip()[:180]
                summary_text = summary_text if summary_text else "No descriptive tracking strings found."

            # Native Regex filter to isolate CVE indexes
            cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", title_text + " " + summary_text, re.IGNORECASE)
            cve_tags = ", ".join(list(set(cve_matches))).upper() if cve_matches else "No Explicit CVE Flags"

            intel_pool.append({
                "Threat Level / Title": title_text,
                "Identified CVEs": cve_tags,
                "Summary": summary_text.replace("\n", " "),
                "Source URL": full_link
            })
        except:
            continue

    # Deduplicate collection pool tracking rows
    unique_pool = {each['Source URL']: each for each in intel_pool}.values()
    return list(unique_pool)

def compile_intel_report(data, output_file="live_threat_feed.csv"):
    if not data:
        print("[!] Execution terminated: Intelligence pool resolved to null.")
        return
        
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        
    print(f"\n[+] Processing Matrix Finalized!")
    print(f"[+] Compiled {len(data)} live threat targets clean inside '{output_file}'")

if __name__ == "__main__":
    live_data = fetch_live_threat_intel()
    
    if live_data:
        print("\n=== LIVE SECURITY MONITOR DISPLAY ===")
        for idx, item in enumerate(live_data[:3], start=1):
            print(f"\n[{idx}] {item['Threat Level / Title']}")
            print(f"    🛡️ CVE Tags: {item['Identified CVEs']}")
            print(f"    🔗 URL: {item['Source URL']}")
            
        compile_intel_report(live_data)
    else:
        print("[!] Scraping engine failed to locate elements across current thresholds.")
        