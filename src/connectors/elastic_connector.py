from elasticsearch import Elasticsearch

from src.utils.config import settings
from src.translators.esql_converter import (
    ElasticQueryConverter
)


class ElasticConnector:

    def __init__(self):

        self.client: Elasticsearch | None = None

    def connect(
        self
    ) -> None:

        print("\n=== ELASTIC DEBUG ===")
        print("HOST =", repr(settings.es_host))

        try:
            print(
                "API KEY LEN =",
                len(settings.es_api_key)
            )
        except Exception as exc:
            print(
                "API KEY ERROR =",
                exc
            )

        self.client = Elasticsearch(
            settings.es_host,
            api_key=settings.es_api_key
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
                "ElasticConnector not connected"
            )

        esql_query = (
            ElasticQueryConverter.to_esql(
                query
            )
        )

        print("\n=== ESQL QUERY ===")
        print(esql_query)

        result = self.client.esql.query(
            query=esql_query
        )

        print("\n=== ESQL RESULT ===")
        print(result)

        if "columns" in result:
            print("\n=== COLUMNS ===")
            for col in result["columns"]:
                print(col["name"])

        if "values" in result:
            print("\n=== ROWS ===")
            for row in result["values"]:
                print(row)

        return result

    def execute_esql(
        self,
        esql_query: str
    ) -> dict:

        if self.client is None:
            raise RuntimeError(
                "ElasticConnector not connected"
            )

        result = self.client.esql.query(
            query=esql_query
        )

        print("\n=== ESQL RESULT ===")
        print(result)

        return result

    def ping(
        self
    ) -> bool:

        if self.client is None:
            return False

        return self.client.ping()

    def info(
        self
    ) -> dict:

        if self.client is None:
            raise RuntimeError(
                "ElasticConnector not connected"
            )

        return self.client.info()