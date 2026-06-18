from pathlib import Path
from dataclasses import dataclass
import subprocess


@dataclass
class DeploymentResult:
    success: bool
    rule_id: str | None = None
    error: str | None = None


class RuleDeploymentAgent:

    def __init__(
        self,
        rules_file: str = "generated_rules/local_rules.xml"
    ):
        self.rules_file = Path(rules_file)
        self.rules_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        if not self.rules_file.exists():
            self.rules_file.write_text(
                "<group name=\"generated_rules\">\n</group>\n"
            )

    def deploy(
        self,
        rule_xml: str
    ) -> DeploymentResult:

        try:

            content = self.rules_file.read_text()

            if "</group>" not in content:
                raise ValueError(
                    "local_rules.xml malformed"
                )

            content = content.replace(
                "</group>",
                f"{rule_xml}\n</group>"
            )

            self.rules_file.write_text(
                content
            )

            subprocess.run(
                [
                    "sudo",
                    "systemctl",
                    "restart",
                    "wazuh-manager"
                ],
                check=True
            )

            return DeploymentResult(
                success=True
            )

        except Exception as exc:

            return DeploymentResult(
                success=False,
                error=str(exc)
            )