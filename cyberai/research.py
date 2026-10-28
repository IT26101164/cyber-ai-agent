"""Constrained research fetcher. It does not execute retrieved content."""
from urllib.parse import urlparse
import re
import requests

ALLOWED_HOSTS = {
    "docs.python.org", "docs.ollama.com", "ollama.com", "owasp.org",
    "cheatsheetseries.owasp.org", "csrc.nist.gov", "nvlpubs.nist.gov",
}
MAX_RESPONSE_BYTES = 1_000_000

def fetch_public_page(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Research URLs must use HTTPS.")
    host = parsed.hostname.lower().rstrip(".")
    if host not in ALLOWED_HOSTS:
        raise ValueError("Host not allowlisted. Add a trusted documentation domain in cyberai/research.py.")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("Credentials and non-standard ports are not allowed.")
    try:
        response = requests.get(
            url, headers={"User-Agent": "CyberAI-Research/0.1"},
            timeout=(5, 15), allow_redirects=False, stream=True,
        )
        if 300 <= response.status_code < 400:
            raise ValueError("Redirects are disabled; open the final trusted HTTPS URL directly.")
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "").lower()
        if not any(kind in content_type for kind in ("text/html", "text/plain", "application/pdf")):
            raise ValueError("Only HTML, plain text, and PDF pages are accepted.")
        chunks = []
        size = 0
        for chunk in response.iter_content(chunk_size=16384):
            size += len(chunk)
            if size > MAX_RESPONSE_BYTES:
                raise ValueError("Page exceeds the 1 MB research limit.")
            chunks.append(chunk)
        text = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
        text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
        text = re.sub(r"(?s)<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return {"url": url, "content_type": content_type, "text": text[:20000]}
    except requests.RequestException as exc:
        raise RuntimeError("Research fetch failed. Check URL and connection.") from exc
