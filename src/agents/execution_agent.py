from dataclasses import dataclass
from time import perf_counter
from typing import Any

from src.connectors.factory import ConnectorFactory


@dataclass
class ExecutionResult:

    platform: str
    query: str

    success: bool

    results: Any = None

    execution_time: float = 0.0

    error: str | None = None


class ExecutionAgent:

    def __init__(
        self,
        connector_configs: dict
    ):
        self.connector_configs = connector_configs

    def execute(
        self,
        platform: str,
        query: str
    ) -> ExecutionResult:

        start = perf_counter()
        print(f"\nEXECUTING {platform.upper()}...")
        try:

            connector = ConnectorFactory.create(
                platform,
                self.connector_configs.get(
                    platform,
                    {}
                )
            )

            connector.connect()

            results = connector.execute(
                query
            )
            print(f"EXECUTION SUCCESS: {platform}")
            return ExecutionResult(
                platform=platform,
                query=query,
                success=True,
                results=results,
                execution_time=(
                    perf_counter() - start
                )
            )

        except Exception as exc:
            print(f"EXECUTION FAILED: {platform}")
            print(exc)
            return ExecutionResult(
                platform=platform,
                query=query,
                success=False,
                error=str(exc),
                execution_time=(
                    perf_counter() - start
                )
            )

    def execute_all(
        self,
        translations: dict[str, str]
    ) -> dict[str, ExecutionResult]:

        results = {}

        executable_platforms = {
            "wazuh",
            "elastic"
        }

        for platform, query in translations.items():

            if not query:
                continue

            if platform not in executable_platforms:
                continue

            results[platform] = self.execute(
                platform,
                query
            )

        return results