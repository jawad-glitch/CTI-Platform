import re

PATTERNS = {
    "ipv4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "domain": r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|pw|cc|biz|info|gov|edu)\b',
    "url": r'https?://[^\s<>"{}|\\^`\[\]]+',
    "md5": r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "cve": r'CVE-\d{4}-\d{4,7}',
}

PRIVATE_IPS = [
    r'^10\.', r'^192\.168\.', r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
    r'^127\.', r'^0\.', r'^255\.'
]

def is_private_ip(ip: str) -> bool:
    return any(re.match(pattern, ip) for pattern in PRIVATE_IPS)

def extract_iocs(text: str) -> list[dict]:
    if not text:
        return []

    found = []
    seen = set()

    for ioc_type, pattern in PATTERNS.items():
        matches = re.findall(pattern, text)
        for match in matches:
            if ioc_type == "ipv4" and is_private_ip(match):
                continue
            if ioc_type == "ipv4" and match.endswith(".0"):
                continue
            key = (ioc_type, match)
            if key not in seen:
                seen.add(key)
                found.append({"type": ioc_type, "value": match})

    return found
