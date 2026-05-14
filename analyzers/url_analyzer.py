import re
import tldextract
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
from analyzers.iplookup import lookip

def extract_urls(text):
    # Improved regex to avoid capturing trailing quotes, brackets, etc.
    url_pattern = r'https?://[^\s"\'><\(\)\[\]]+'
    return re.findall(url_pattern, text)

def analyze_url(url):
    extracted = tldextract.extract(url)

    return {
        "url": url,
        "domain": extracted.domain,
        "suffix": extracted.suffix,
        "full_domain": f"{extracted.domain}.{extracted.suffix}"
    }

def extract_headers(file_path):

    with open(file_path, "rb") as file:

        msg = BytesParser(
            policy=policy.default
        ).parse(file)

    from_header = msg.get("From")
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    x_mailer = msg.get("X-Mailer")

    auth_results = msg.get(
        "Authentication-Results",
        ""
    )

    spf = "not found"
    dkim = "not found"
    dmarc = "not found"

    if "spf=" in auth_results.lower():
        spf = auth_results.split("spf=")[1].split()[0]

    if "dkim=" in auth_results.lower():
        dkim = auth_results.split("dkim=")[1].split()[0]

    if "dmarc=" in auth_results.lower():
        dmarc = auth_results.split("dmarc=")[1].split()[0]

    received_headers = msg.get_all("Received", [])

    ip_match = None
    loc = None

    for header in received_headers:

        match = re.search(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
            header
        )

        if match:
            ip_match = match.group()
            loc = lookip(ip_match)
            break
        

    return [
        {
            "field": "From",
            "value": from_header or "—",
            "status": "clean" if from_header else "— not found"
        },

        {
            "field": "Reply-To",
            "value": reply_to or "—",
            "status": "suspicious" if reply_to else "— not found"
        },

        {
            "field": "Return-Path",
            "value": return_path or "—",
            "status": "present" if return_path else "— not found"
        },

        {
            "field": "SPF",
            "value": spf,
            "status": (
                "pass"
                if spf == "pass"
                else "failed"
            )
        },

        {
            "field": "DKIM",
            "value": dkim,
            "status": (
                "pass"
                if dkim == "pass"
                else "failed"
            )
        },

        {
            "field": "DMARC",
            "value": dmarc,
            "status": (
                "pass"
                if dmarc == "pass"
                else "failed"
            )
        },

        {
            "field": "Originating IP",
            "value": ip_match or "not confidently extracted",
            "status": (
                "extracted"
                if ip_match
                else "— not found"
            )
        },

        {
            "field": "Location",
            "value": loc or "not confidently extracted",
            "status": (
                "extracted"
                if loc
                else "— not found"
            )
        },

        {
            "field": "X-Mailer",
            "value": x_mailer or "—",
            "status": (
                "present"
                if x_mailer
                else "— not found"
            )
        }
    ]

def extract_html(email_content):
    msg = BytesParser(
        policy=policy.default
    ).parsebytes(email_content.encode())

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                return part.get_content()
    else:
        if msg.get_content_type() == 'text/html':
            return msg.get_content()

    # Fallback: check if the content looks like HTML
    lowered = email_content.lower()
    if (
        "<html" in lowered
        or "<table" in lowered
        or "<body" in lowered
        or "<meta" in lowered
    ):
        return email_content

    return ""

def analyze_html(html_content):

    soup = BeautifulSoup(
        html_content,
        "html.parser"
    )

    findings = []

    images = soup.find_all("img")

    for img in images:

        width = str(
            img.get("width", "")
        ).lower()

        height = str(
            img.get("height", "")
        ).lower()

        style = str(
            img.get("style", "")
        ).lower()

        hidden = (
            "visibility:hidden" in style
            or "display:none" in style
            or "opacity:0" in style
        )

        tiny = (
            width in ["1", "1px"]
            or height in ["1", "1px"]
        )

        if tiny or hidden:

            findings.append(
                {
                    "type": "Tracking Pixel",
                    "severity": "HIGH",
                    "value": img.get("src", "unknown")
                }
            )

    links = soup.find_all("a")

    for link in links:

        href = link.get("href", "")

        if href.startswith("mailto:"):

            findings.append(
                {
                    "type": "Mailto Link",
                    "severity": "MEDIUM",
                    "value": href
                }
            )

    return findings