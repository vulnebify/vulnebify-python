import requests
import requests.adapters
import requests.auth
import requests.status_codes

import uuid

from urllib3.util.retry import Retry
from typing import List

from .errors import *
from .models import *


class Idempotency:
    @staticmethod
    def key() -> str:
        return f"ik_{uuid.uuid4().hex}"


class VulnebifyHttpClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        proxy_url: str | None = None,
    ):
        self.__base_url = base_url.rstrip("/")
        self.__username = username
        self.__password = password
        self.__proxy_url = proxy_url
        self.__session = None

    def get(self, path: str, **kwargs) -> str:
        try:
            self.__ensure_session_initialized()

            response = self.__session.get(f"{self.__base_url}{path}", **kwargs)

            if response.status_code != 200:
                raise VulnebifyApiError(response.status_code, response.text)

            return response.text
        except VulnebifyApiError:
            raise
        except Exception as e:
            raise VulnebifyClientError(e)

    def post(self, path: str, json=None, idempotency_key=None, **kwargs) -> str:
        try:
            self.__ensure_session_initialized()

            headers = kwargs.pop("headers", {})

            headers["Idempotency-Key"] = idempotency_key or Idempotency.key()

            response = self.__session.post(
                f"{self.__base_url}{path}", json=json, headers=headers, **kwargs
            )

            if response.status_code != 200:
                raise VulnebifyApiError(response.status_code, response.text)

            return response.text
        except VulnebifyApiError:
            raise
        except Exception as e:
            raise VulnebifyClientError(e)

    def __create_session(self):
        session = requests.Session()
        session.auth = requests.auth.HTTPBasicAuth(self.__username, self.__password)

        if self.__proxy_url:
            session.proxies.update(
                {
                    "http": self.__proxy_url,
                    "https": self.__proxy_url,
                }
            )

        retries = Retry(
            total=5,
            backoff_factor=1.0,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS", "POST"],
            raise_on_status=False,
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retries)

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def __enter__(self):
        self.__session = self.__create_session()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.__session.close()
        self.__session = None

    def __ensure_session_initialized(self):
        if self.__session:
            return

        raise RuntimeError(
            "Session not initialized. Initialize 'client = VulnebifyHttpClient(...)' and use 'with client as c:'."
        )


class VulnebifyKey:
    def __init__(self, client: VulnebifyHttpClient):
        self.__client = client

    def generate(self):
        with self.__client as client:
            response = client.post(f"/key")

            return KeyResponse.model_validate_json(response)

    def active(self) -> bool:
        with self.__client as client:
            try:
                _ = client.get(f"/key")
                return True
            except VulnebifyApiError as e:
                if e.status_code == 401:
                    return False
                raise


class VulnebifyDomain:
    def __init__(self, client: VulnebifyHttpClient):
        self.__client = client

    def get(self, domain: str):
        with self.__client as client:
            response = client.get(f"/domain/{domain}")

            return response


class VulnebifyHost:
    def __init__(self, client: VulnebifyHttpClient):
        self.__client = client

    def get(self, host: str):
        with self.__client as client:
            response = client.get(f"/host/{host}")

            return response


class VulnebifyScan:
    def __init__(self, client: VulnebifyHttpClient):
        self.__client = client

    def list(self) -> ScanListResponse:
        with self.__client as client:
            response = client.get(f"/scan")
            return ScanListResponse.model_validate_json(response)

    def run(
        self,
        scopes: List[str],
        ports: List[str | int],
        scanners: List[str],
        idempotency_key: str | None = None,
    ) -> ScanResponse:
        with self.__client as client:
            request = ScanRequest(
                scopes=scopes,
                ports=ports,
                scanners=scanners,
            ).model_dump()

            response = client.post(f"/scan/", request, idempotency_key=idempotency_key)

            return ScanResponse.model_validate_json(response)

    def get(self, scan_id: str) -> ScanResponse:
        with self.__client as client:
            response = client.get(f"/scan/{scan_id}")

            return ScanResponse.model_validate_json(response)

    def summary(self, scan_id: str) -> ScanSummaryResponse:
        with self.__client as client:
            response = client.get(f"/scan/{scan_id}/summary")

            return ScanSummaryResponse.model_validate_json(response)

    def report(self, scan_id: str) -> ScanReportResponse:
        with self.__client as client:
            response = client.get(f"/scan/{scan_id}/report")

            return ScanReportResponse.model_validate_json(response)

    def cancel(self, scan_id: str):
        with self.__client as client:
            client.post(f"/scan/{scan_id}/cancel")


class Vulnebify:
    def __init__(
        self,
        api_key: str,
        api_url: str = "https://api.vulnebify.com/v1",
        proxy_url: str | None = None,
    ):
        client = VulnebifyHttpClient(api_url, api_key, "", proxy_url)

        self.domain = VulnebifyDomain(client)
        self.key = VulnebifyKey(client)
        self.host = VulnebifyHost(client)
        self.scan = VulnebifyScan(client)
