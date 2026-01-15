from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from datetime import datetime
import subprocess
import json
import os
from dotenv import load_dotenv

from ..models.database import get_db
from ..models.scan import Scan, Subdomain

load_dotenv()
router = APIRouter()

class ScanRequest(BaseModel):
    domain: str

class SubdomainResponse(BaseModel):
    subdomain: str
    ip_address: str | None
    discovered_at: datetime

    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: str
    domain: str
    status: str
    progress: int
    created_at: datetime
    subdomains_count: int

    class Config:
        from_attributes = True


# ============== SCANNER FUNCTIONS ==============

def run_subfinder(domain: str) -> list[str]:
    """Run Subfinder to discover subdomains."""

    api_key = os.getenv("PDCP_API_KEY", "")

    cmd = [
        "docker", "run", "--rm",
        "-e", f"PDCP_API_KEY={api_key}",
        "projectdiscovery/subfinder",
        "-d", domain,
        "-silent"
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    subdomains = [line for line in result.stdout.strip().split("\n") if line]
    return subdomains


def run_httpx(subdomains: list[str]) -> list[dict]:
    """Run httpx to get IPs and status codes."""

    if not subdomains:
        return []

    input_data = "\n".join(subdomains)

    cmd = [
        "docker", "run", "--rm", "-i",
        "projectdiscovery/httpx",
        "-silent",
        "-json",
        "-ip"
    ]

    result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)

    results = []
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                data = json.loads(line)

                # Get IP from host_ip or first A record
                ip = data.get("host_ip")
                if not ip and data.get("a"):
                    ip = data["a"][0]

                results.append({
                    "subdomain": data.get("input", ""),
                    "ip_address": ip,
                    "status_code": data.get("status_code"),
                    "url": data.get("url", "")
                })
            except json.JSONDecodeError:
                continue

    return results

def scan_domain(domain: str) -> list[dict]:
    """Full scan: Subfinder → httpx."""

    # Step 1: Discover subdomains
    subdomains = run_subfinder(domain)

    # Step 2: Probe for IPs and status
    results = run_httpx(subdomains)

    # Include subdomains that httpx didn't reach
    probed = {r["subdomain"] for r in results}
    for sub in subdomains:
        if sub not in probed:
            results.append({
                "subdomain": sub,
                "ip_address": None,
                "status_code": None,
                "url": None
            })

    return results


# ============== API ROUTES ==============

@router.post("/scan", response_model=ScanResponse)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """Start a new scan for a domain."""

    # Create scan record
    scan = Scan(domain=request.domain, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run full scan (Subfinder + httpx)
    results = scan_domain(request.domain)

    # Save subdomains
    for item in results:
        subdomain = Subdomain(
            scan_id=scan.id,
            subdomain=item["subdomain"],
            ip_address=item["ip_address"]
        )
        db.add(subdomain)

    # Update scan status
    scan.status = "completed"
    scan.progress = 100
    scan.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)

    return ScanResponse(
        id=str(scan.id),
        domain=scan.domain,
        status=scan.status,
        progress=scan.progress,
        created_at=scan.created_at,
        subdomains_count=len(results)
    )


@router.get("/scan/{scan_id}/subdomains", response_model=List[SubdomainResponse])
def get_subdomains(scan_id: str, db: Session = Depends(get_db)):
    """Get all subdomains for a scan."""

    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan_id).all()
    return subdomains