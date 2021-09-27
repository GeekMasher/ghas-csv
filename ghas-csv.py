import os
import csv
import logging
import argparse
from dataclasses import dataclass, asdict
import requests
from requests.api import get


logger = logging.getLogger("GHAS-CSV")

parser = argparse.ArgumentParser("GHAS-CSV")
parser.add_argument("--debug", action="store_true", help="Enable Debugging")

group_github = parser.add_argument_group("GitHub")
group_github.add_argument(
    "-r", "--repository", required=True, help="Repository full name (org/repo)"
)
group_github.add_argument(
    "-t",
    "--token",
    default=os.environ.get("GITHUB_TOKEN"),
    help="GitHub PAT (default: $GITHUB_TOKEN)",
)
# Optional
group_github.add_argument(
    "--ref", help="Git Reference / Branch (refs/heads/<branch name>)"
)
group_github.add_argument("--state", help="Alert state")
group_github.add_argument("--tool-name", help="Tool name")

group_csv = parser.add_argument_group("CSV")
group_csv.add_argument("-o", "--output", default="alerts.csv")
group_csv.add_argument("--delimiter", default=",")


@dataclass
class Alert:
    number: int
    created: str

    rule: str = "N/A"
    description: str = "N/A"
    severity: str = "N/A"
    tool: str = "N/A"

    state: str = "N/A"


def getAlerts(
    repository: str,
    token: str,
    ref: str = None,
    state: str = None,
    tool_name: str = None,
    instance: str = "https://api.github.com",
):
    """Get Alerts from GHAS (cloud)
    https://docs.github.com/en/rest/reference/code-scanning#list-code-scanning-alerts-for-a-repository
    """
    logger.info(f"Getting Alerts from repository: {repository}")

    owner, repo = repository.split("/", 1)
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": "token " + token,
    }
    per_page = 100
    params = {"per_page": per_page}
    # If state is passed in
    if state:
        params["state"] = state
    if ref:
        params["ref"] = ref
    if ref:
        params["tool_name"] = tool_name

    url = f"{instance}/repos/{owner}/{repo}/code-scanning/alerts"

    alerts = []

    page_counter = 1
    while True:
        params["page"] = page_counter

        response = requests.get(url, headers=headers, params=params)

        data = response.json()

        if response.status_code != 200:
            msg = data.get("message")
            logger.error(f"Requesting endpoint error: {msg}")
            raise Exception(msg)

        for alert in data:
            alerts.append(
                Alert(
                    number=alert.get("number"),
                    created=alert.get("created_at"),
                    rule=alert.get("rule", {}).get("id"),
                    severity=alert.get("rule", {}).get("severity"),
                    description=alert.get("rule", {}).get("description"),
                    tool=alert.get("tool", {}).get("name"),
                    state=alert.get("state"),
                )
            )

        if len(response.json()) < per_page:
            break

        page_counter += 1

    return alerts


if __name__ == "__main__":
    arguments = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if arguments.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    #  Get Alerts
    alerts = getAlerts(
        arguments.repository,
        arguments.token,
        ref=arguments.ref,
        state=arguments.state,
        tool_name=arguments.tool_name,
    )
    logger.info(f"Total Alerts: {len(alerts)}")

    #  Export headers
    csv_headers = [
        "number",
        "rule",
        "severity",
        "tool",
        "created",
    ]
    csv_placeholders = {
        "number": "ID",
        "state": "State",
        "rule": "Rule / Query ID",
        "description": "Description",
        "severity": "Severity / Criticality",
        "tool": "Tool Name",
        "created": "Time Created",
    }

    logger.info(f"Writing CSV to: {arguments.output}")

    with open(arguments.output, "w") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers, extrasaction="ignore")
        #  Header
        writer.writerow(csv_placeholders)

        for alert in alerts:
            writer.writerow(asdict(alert))
