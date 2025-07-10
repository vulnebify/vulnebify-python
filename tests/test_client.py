import os
import pytest

from vulnebify import Vulnebify
from vulnebify.models import *
from vulnebify.errors import VulnebifyApiError
from vulnebify.cli import get_api_key

vulnebify = Vulnebify(get_api_key())


def test_notauthorized_client():
    vulnebify = Vulnebify("key_123")

    with pytest.raises(VulnebifyApiError) as e:
        vulnebify.domain.get("vulnebify.com")

    assert e.value.status_code == 401
    assert e.value.response["error"]["code"] == "api_key_not_found"


def test_get_host():
    host: Host = vulnebify.host.get("1.1.1.1")

    assert "one.one.one.one" in host.hostnames


def test_get_domain():
    domain: RootDomain = vulnebify.domain.get("vulnebify.com")

    subdomains = [sub.domain for sub in domain.subdomains]

    assert "docs.vulnebify.com" in subdomains
