from src.connectors.splunk_connector import SplunkConnector
from src.connectors.wazuh_connector import WazuhConnector
from src.connectors.elastic_connector import ElasticConnector


class ConnectorFactory:

    @staticmethod
    def create(
        platform: str,
        config: dict
    ):

        platform = platform.lower()

        if platform == "splunk":
            return SplunkConnector(**config)

        if platform == "elastic":
            return ElasticConnector()

        if platform == "wazuh":
            return WazuhConnector(**config)

        raise ValueError(
            f"Unsupported platform: {platform}"
        )