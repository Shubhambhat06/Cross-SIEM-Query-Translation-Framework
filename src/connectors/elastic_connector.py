from elasticsearch import Elasticsearch

from src.translators.esql_converter import (
    ElasticQueryConverter
)


class ElasticConnector:

    def __init__(
        self,
        config: dict | None = None
    ):

        config = config or {}

        self.host = config.get(
            "host",
            ""
        )

        self.api_key = config.get(
            "api_key",
            ""
        )

        self.client: Elasticsearch | None = None

    def connect(
        self
    ) -> None:

        print("\n=== ELASTIC DEBUG ===")
        print(
            "HOST =",
            repr(self.host)
        )

        print(
            "API KEY LEN =",
            len(self.api_key)
        )

        if not self.host:
            raise ValueError(
                "Elastic host is empty. "
                "Set ELASTIC_URL."
            )

        if not self.api_key:
            raise ValueError(
                "Elastic API key is empty. "
                "Set ELASTIC_API_KEY."
            )

        self.client = Elasticsearch(
            self.host,
            api_key=self.api_key
        )

        print("CLIENT CREATED")

        info = self.client.info()

        print("CONNECTED")
        print(info)

    def execute(
        self,
        query: str
    ) -> dict:

        if self.client is None:
            raise RuntimeError(
                "Elastic connector is not connected."
            )

        conversion = (
            ElasticQueryConverter.convert(
                query
            )
        )

        if conversion.warnings:

            print(
                "\n=== ES|QL CONVERSION WARNINGS ==="
            )

            for warning in conversion.warnings:
                print(
                    f"- {warning}"
                )

        esql_query = conversion.esql

        print(
            "\n=== EXECUTING ES|QL ==="
        )

        print(esql_query)

        response = self.client.esql.query(
            query=esql_query
        )

        return response.body