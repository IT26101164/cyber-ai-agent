import pytest
from cyberai.research import fetch_public_page

@pytest.mark.parametrize("url", [
    "http://owasp.org/",
    "https://example.com/",
    "https://user:pass@owasp.org/",
    "https://owasp.org:8443/",
])
def test_rejects_untrusted_research_urls(url):
    with pytest.raises(ValueError):
        fetch_public_page(url)
