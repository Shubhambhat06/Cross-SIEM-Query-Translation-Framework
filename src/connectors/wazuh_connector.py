import requests
from typing import Any

from src.connectors.base import BaseConnector


class WazuhConnector(BaseConnector):

    def __init__(
        self,
        host: str,
        username: str,
        password: str
    ):
        self.host = host.rstrip("/")
        self.username = username
        self.password = password

        self.token = None

    def connect(self) -> None:

        url = (
            f"{self.host}"
            "/security/user/authenticate?raw=true"
        )

        response = requests.post(
            url,
            auth=(self.username, self.password),
            verify=False,
            timeout=30,
        )

        response.raise_for_status()

        self.token = response.text.strip()

    def execute(self, endpoint: str) -> Any:

        if not self.token:
            self.connect()

        headers = {
            "Authorization": f"Bearer {self.token}"
        }

        response = requests.get(
            f"{self.host}{endpoint}",
            headers=headers,
            verify=False,
            timeout=60,
        )

        response.raise_for_status()

        return response.json()

    def health_check(self) -> bool:

        try:

            if not self.token:
                self.connect()

            headers = {
                "Authorization": f"Bearer {self.token}"
            }

            response = requests.get(
                f"{self.host}/manager/status",
                headers=headers,
                verify=False,
                timeout=10,
            )

            return response.status_code == 200

        except Exception:
            return False