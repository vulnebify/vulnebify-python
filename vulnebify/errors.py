import json

from typing import Dict, Any


class VulnebifyError(Exception):
    def __init__(self, message: str):
        self.message = f"🛑 Oh no! Error: {message}"


class VulnebifyApiError(VulnebifyError):
    def __init__(self, status_code: int, response: str):
        self.status_code = status_code

        try:
            self.response: Dict[str, Any] = json.loads(response)
        except:
            self.response: Dict[str, Any] = {
                "error": {"code": "processing_error", "message": response}
            }

        self.message = f"🛑 Oh no! API '{status_code}' error. Response: '{self.response}'. Create issue: https://github.com/vulnebify/vulnebify-python/issues"


class VulnebifyClientError(VulnebifyError):
    def __init__(self, message: str):
        self.response: Dict[str, Any] = {
            "error": {"code": "processing_error", "message": message}
        }

        self.message = f"🛑 Oh no! CLI error. Error: '{self.response}'. Create issue: https://github.com/vulnebify/vulnebify-python/issues"
