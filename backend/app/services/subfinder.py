import subprocess
import json
import os
from dotenv import load_dotenv

load_dotenv()


def run_subfinder(domain: str) -> list[dict]:
    """Run Subfinder via Docker and return discovered subdomains."""

    api_key = os.getenv("PDCP_API_KEY", "")

    cmd = [
        "docker", "run", "--rm",
        "-e", f"PDCP_API_KEY={api_key}",
        "projectdiscovery/subfinder",
        "-d", domain,
        "-silent",
        "-json"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    subdomains = []
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                data = json.loads(line)
                subdomains.append({
                    "subdomain": data.get("host", ""),
                    "ip_address": data.get("ip", None)
                })
            except json.JSONDecodeError:
                continue

    return subdomains