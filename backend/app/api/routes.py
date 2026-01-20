from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
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


# ============== PYDANTIC MODELS ==============

class ScanRequest(BaseModel):
    domain: str


class SubdomainResponse(BaseModel):
    row_num: int
    subdomain: str
    ip_address: str | None
    host_status: int
    asn: str | None
    asn_org: str | None
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
    print(f"[DEBUG] Subfinder found {len(subdomains)} subdomains")
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

                # Determine host_status
                if status_code:
                    if status_code >= 500:
                        host_status = 0
                    else:
                        host_status = 1
                else:
                    host_status = 0

                results.append({
                    "subdomain": data.get("input", ""),
                    "ip_address": ip,
                    "host_status": host_status,
                    "status_code": status_code,
                    "url": data.get("url", "")
                })
            except json.JSONDecodeError:
                continue

    print(f"[DEBUG] httpx probed {len(results)} hosts")
    return results


def run_asnmap(ips: list[str]) -> dict:
    """Run ASNmap to get ASN info for IPs."""
    if not ips:
        print("[DEBUG] No IPs to lookup for ASN")
        return {}

    api_key = os.getenv("PDCP_API_KEY", "")
    input_data = "\n".join(ips)

    print(f"[DEBUG] Looking up ASN for {len(ips)} IPs: {ips[:5]}...")

    cmd = [
        "docker", "run", "--rm", "-i",
        "-e", f"PDCP_API_KEY={api_key}",
        "projectdiscovery/asnmap",
        "-silent",
        "-json"
    ]

    result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)

    print(f"[DEBUG] ASNmap stdout: {result.stdout[:500]}")
    print(f"[DEBUG] ASNmap stderr: {result.stderr[:500]}")

    asn_map = {}
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                data = json.loads(line)
                print(f"[DEBUG] ASN data: {data}")
                ip = data.get("input", "")
                asn_map[ip] = {
                    "asn": str(data.get("as_number", "")),
                    "asn_org": data.get("as_name", ""),
                    "country": data.get("country", "")
                }
            except json.JSONDecodeError as e:
                print(f"[DEBUG] JSON decode error: {e}")
                continue

    print(f"[DEBUG] ASN map result: {asn_map}")
    return asn_map


def scan_domain(domain: str) -> dict:
    """Full scan: Subfinder → httpx → ASNmap."""

    # Step 1: Discover subdomains
    subdomains = run_subfinder(domain)

    # Step 2: Probe for IPs and status
    httpx_results = run_httpx(subdomains)

    # Step 3: Get ASN info for discovered IPs
    ips = list(set([r["ip_address"] for r in httpx_results if r["ip_address"]]))
    asn_map = run_asnmap(ips)

    # Combine results - INCLUDE host_status
    combined_subdomains = []
    for result in httpx_results:
        ip = result["ip_address"]
        asn_info = asn_map.get(ip, {})
        combined_subdomains.append({
            "subdomain": result["subdomain"],
            "ip_address": ip,
            "host_status": result["host_status"],  # <-- This was missing!
            "asn": asn_info.get("asn"),
            "asn_org": asn_info.get("asn_org"),
        })

    # Include subdomains that httpx didn't reach
    probed = {r["subdomain"] for r in httpx_results}
    for sub in subdomains:
        if sub not in probed:
            combined_subdomains.append({
                "subdomain": sub,
                "ip_address": None,
                "host_status": 2,  # Unknown
                "asn": None,
                "asn_org": None,
            })

    return {
        "subdomains": combined_subdomains
    }


# ============== API ROUTES ==============

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
    alive_count = sum(1 for r in results["subdomains"] if r["host_status"] == 1)
    dead_count = sum(1 for r in results["subdomains"] if r["host_status"] == 0)

    # Save subdomains
    for item in results["subdomains"]:
        subdomain = Subdomain(
            scan_id=scan.id,
            subdomain=item["subdomain"],
            ip_address=item["ip_address"],
            host_status=item["host_status"],
            asn=item["asn"],
            asn_org=item["asn_org"]
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
        subdomains_count=len(results["subdomains"]),
        alive_count=alive_count,
        dead_count=dead_count
    )




@router.get("/scan/{scan_id}/subdomains")
def get_subdomains(scan_id: str, db: Session = Depends(get_db)):
    """Get all subdomains for a scan with row numbers."""

    query = db.execute(text("""
        SELECT 
            ROW_NUMBER() OVER (ORDER BY discovered_at) as row_num,
            id, subdomain, ip_address, host_status, asn, asn_org, discovered_at
        FROM subdomains
        WHERE scan_id = :scan_id
        ORDER BY discovered_at
    """), {"scan_id": scan_id})

    results = []
    for row in query:
        results.append({
            "row_num": row.row_num,
            "id": str(row.id),
            "subdomain": row.subdomain,
            "ip_address": row.ip_address,
            "host_status": row.host_status,
            "asn": row.asn,
            "asn_org": row.asn_org,
            "discovered_at": row.discovered_at
        })

    return results


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