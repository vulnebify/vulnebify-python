import json

from typing import Dict, Any


class VulnebifyError(Exception):
    def __init__(self, message: str):
        self.message = message


class VulnebifyClientError(VulnebifyError):
    def __init__(self, message: str):
        super().__init__(message)


class VulnebifyApiError(VulnebifyError):
    def __init__(self, status_code: int, response: str):
        self.status_code = status_code

        try:
            self.response: Dict[str, Any] = json.loads(response)
        except:
            self.response: Dict[str, Any] = {
                "error": {"code": "processing_error", "message": response}
            }

        self.message = f"Oh no! API '{status_code}' error."
