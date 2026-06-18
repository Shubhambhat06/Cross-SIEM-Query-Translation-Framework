from src.connectors.splunk_connector import SplunkConnector
from src.connectors.wazuh_connector import WazuhConnector


class ConnectorFactory:

    @staticmethod
    def create(
        platform: str,
        config: dict
    ):

        platform = platform.lower()

        if platform == "splunk":
            return SplunkConnector(**config)

        if platform == "wazuh":
            return WazuhConnector(**config)

        raise ValueError(
            f"Unsupported platform: {platform}"
        )