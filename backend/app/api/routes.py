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


# pydantic models

class ScanRequest(BaseModel):
    domain: str

class SubdomainResponse(BaseModel):
    subdomain: str
    ip_address: str | None
    host_status: int  # 0=dead, 1=alive, 2=unknown
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
    alive_count: int
    dead_count: int

    class Config:
        from_attributes = True


# scanner functions

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
                ip = data.get("host_ip")
                if not ip and data.get("a"):
                    ip = data["a"][0]

                status_code = data.get("status_code")

                # Determine host_status: 1=alive, 0=dead
                # Alive: 2xx, 3xx, 4xx (server responded)
                # Dead: 5xx or no response
                if status_code:
                    if status_code >= 500:
                        host_status = 0  # Dead (server error)
                    else:
                        host_status = 1  # Alive (responded)
                else:
                    host_status = 0  # Dead (no response)

                results.append({
                    "subdomain": data.get("input", ""),
                    "ip_address": ip,
                    "host_status": host_status,
                    "status_code": status_code,
                    "url": data.get("url", "")
                })
            except json.JSONDecodeError:
                continue

    return results


def scan_domain(domain: str) -> list[dict]:
    """Full scan: Subfinder and httpx."""

    # Step 1: Discover subdomains
    subdomains = run_subfinder(domain)

    # Step 2: Probe for IPs and status
    httpx_results = run_httpx(subdomains)

    # Include subdomains that httpx didn't reach (unknown status)
    probed = {r["subdomain"] for r in httpx_results}
    for sub in subdomains:
        if sub not in probed:
            httpx_results.append({
                "subdomain": sub,
                "ip_address": None,
                "host_status": 2,  # Unknown
                "status_code": None,
                "url": None
            })

    return httpx_results


# API routes

@router.post("/scan", response_model=ScanResponse)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """Start a new scan for a domain."""

    # Create scan record
    scan = Scan(domain=request.domain, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run full scan
    results = scan_domain(request.domain)

    # Count stats
    alive_count = sum(1 for r in results if r["host_status"] == 1)
    dead_count = sum(1 for r in results if r["host_status"] == 0)

    # Save subdomains
    for item in results:
        subdomain = Subdomain(
            scan_id=scan.id,
            subdomain=item["subdomain"],
            ip_address=item["ip_address"],
            host_status=item["host_status"]
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
        subdomains_count=len(results),
        alive_count=alive_count,
        dead_count=dead_count
    )


@router.get("/scan/{scan_id}/subdomains", response_model=List[SubdomainResponse])
def get_subdomains(scan_id: str, db: Session = Depends(get_db)):
    """Get all subdomains for a scan."""

    subdomains = db.query(Subdomain).filter(Subdomain.scan_id == scan_id).all()
    return subdomains


@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    """List all scans."""

    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [
        {
            "id": str(scan.id),
            "domain": scan.domain,
            "status": scan.status,
            "progress": scan.progress,
            "created_at": scan.created_at
        }
        for scan in scans
    ]