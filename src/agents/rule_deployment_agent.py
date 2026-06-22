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
        rules_file: str = "/var/ossec/etc/rules/local_rules.xml"
    ):
        self.rules_file = Path(rules_file)
        

        

    def deploy(
        self,
        rule_xml: str
    ) -> DeploymentResult:

        try:

            content = subprocess.check_output(
                    [
                        "sudo",
                        "cat",
                        str(self.rules_file)
                    ],
                    text=True
                )

            if "</group>" not in content:
                raise ValueError(
                    "local_rules.xml malformed"
                )

            last_group = content.rfind("</group>")

            if last_group == -1:
                raise ValueError(
                    "No closing </group> found"
                )

            content = (
                content[:last_group]
                + "\n"
                + rule_xml
                + "\n"
                + content[last_group:]
            )

            temp_file = Path(
                "/tmp/nlsiem_rules.xml"
            )

            temp_file.write_text(
                content
            )

            subprocess.run(
                [
                    "sudo",
                    "cp",
                    str(temp_file),
                    str(self.rules_file)
                ],
                check=True
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