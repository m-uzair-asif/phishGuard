def calculate_threat_score(url, findings, headers):
    """
    Calculates a threat score from 0 to 100 based on various indicators.
    """
    score = 0
    
    # URL indicators
    suspicious_keywords = ["secure", "update", "verify", "login", "account", "banking", "confirm"]
    if any(k in url.lower() for k in suspicious_keywords):
        score += 30
        
    if "bit.ly" in url.lower() or "t.co" in url.lower() or "tinyurl" in url.lower():
        score += 20
        
    # HTML Findings indicators
    for finding in findings:
        if finding["type"] == "Tracking Pixel":
            score += 15
        if finding["severity"] == "HIGH":
            score += 25
        elif finding["severity"] == "MEDIUM":
            score += 10
            
    # Header indicators
    for header in headers:
        if header["field"] in ["SPF", "DKIM", "DMARC"] and header["value"] in ["none", "fail", "softfail"]:
            score += 10
        if header["field"] == "Reply-To" and header["status"] == "suspicious":
            score += 15
            
    return min(score, 100)

def get_risk_label(score):
    if score >= 70:
        return "[bold red]MALICIOUS[/bold red]"
    elif score >= 40:
        return "[bold yellow]SUSPICIOUS[/bold yellow]"
    else:
        return "[bold green]CLEAN[/bold green]"
