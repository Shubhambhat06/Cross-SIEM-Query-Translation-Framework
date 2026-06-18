import requests
from typing import Any

from src.connectors.base import BaseConnector


class SplunkConnector(BaseConnector):

    def __init__(
        self,
        host: str,
        username: str,
        password: str
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password

        self.session = requests.Session()

    def connect(self) -> None:
        """
        Splunk uses Basic Auth for REST API access.
        We just verify credentials by hitting server info.
        """

        response = self.session.get(
            f"{self.host}/services/server/info",
            auth=(self.username, self.password),
            verify=False,
            timeout=30,
        )

        response.raise_for_status()

    def execute(self, query: str) -> Any:
        """
        Execute SPL and stream results.
        """

        url = f"{self.host}/services/search/jobs/export"

        payload = {
            "search": query,
            "output_mode": "json",
        }

        response = self.session.post(
            url,
            data=payload,
            auth=(self.username, self.password),
            verify=False,
            timeout=120,
        )

        response.raise_for_status()

        return response.text

    def health_check(self) -> bool:

        try:
            response = self.session.get(
                f"{self.host}/services/server/info",
                auth=(self.username, self.password),
                verify=False,
                timeout=10,
            )

            return response.status_code == 200

        except Exception:
            return False