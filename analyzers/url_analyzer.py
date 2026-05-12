import re
import tldextract

def extract_urls(text):
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

def analyze_url(url):
    extracted = tldextract.extract(url)
    print(f"extracted: {extracted}")

    return {
        "url": url,
        "domain": extracted.domain,
        "suffix": extracted.suffix,
        "full_domain": f"{extracted.domain}.{extracted.suffix}"
    }
