from abc import ABC, abstractmethod
from typing import Any


class BaseConnector(ABC):

    @abstractmethod
    def connect(self) -> None:
        pass

    @abstractmethod
    def execute(self, query: str) -> Any:
        pass

    @abstractmethod
    def health_check(self) -> bool:
        pass