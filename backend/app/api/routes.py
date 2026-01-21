from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import text
from typing import List
from pydantic import BaseModel
from datetime import datetime
from urllib.parse import urlparse
import subprocess
import json
import os
from dotenv import load_dotenv

from ..models.database import get_db
from ..models.scan import Scan, Subdomain, Endpoint

load_dotenv()
router = APIRouter()

# ============== SENSITIVE PATH DETECTION ==============

SENSITIVE_PATTERNS = {
    "/admin": "Admin panel",
    "/.env": "Environment file",
    "/.git": "Git repository",
    "/backup": "Backup file",
    "/config": "Configuration file",
    "/api/": "API endpoint",
    "/debug": "Debug endpoint",
    "/phpinfo": "PHP info",
    "/wp-admin": "WordPress admin",
    "/wp-login": "WordPress login",
    "/.htaccess": "Apache config",
    "/server-status": "Server status",
    "/.aws": "AWS credentials",
    "/swagger": "API documentation",
    "/graphql": "GraphQL endpoint",
    "/.docker": "Docker config",
    "/actuator": "Spring actuator",
    "/elmah": "Error logs",
    "/trace": "Debug trace",
    "/console": "Console access"
}


def check_sensitive(url: str) -> tuple[bool, str | None]:
    """Check if URL matches sensitive patterns."""
    url_lower = url.lower()
    for pattern, reason in SENSITIVE_PATTERNS.items():
        if pattern in url_lower:
            return True, reason
    return False, None


def extract_path(url: str) -> str:
    """Extract path from URL."""
    try:
        parsed = urlparse(url)
        return parsed.path or "/"
    except:
        return "/"


# ============== PYDANTIC MODELS ==============

class ScanRequest(BaseModel):
    domain: str


class SubdomainResponse(BaseModel):
    row_num: int
    id: str
    subdomain: str
    ip_address: str | None
    host_status: int
    asn: str | None
    asn_org: str | None
    discovered_at: datetime


class EndpointResponse(BaseModel):
    row_num: int
    id: str
    url: str
    path: str | None
    method: str
    status_code: int | None
    is_sensitive: bool
    sensitivity_reason: str | None
    discovered_at: datetime


class ScanResponse(BaseModel):
    id: str
    domain: str
    status: str
    progress: int
    created_at: datetime
    subdomains_count: int
    alive_count: int
    dead_count: int
    endpoints_count: int
    sensitive_count: int

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
        return {}

    api_key = os.getenv("PDCP_API_KEY", "")
    input_data = "\n".join(ips)

    print(f"[DEBUG] Looking up ASN for {len(ips)} IPs")

    cmd = [
        "docker", "run", "--rm", "-i",
        "-e", f"PDCP_API_KEY={api_key}",
        "projectdiscovery/asnmap",
        "-silent",
        "-json"
    ]

    result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)

    asn_map = {}
    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                data = json.loads(line)
                ip = data.get("input", "")
                asn_map[ip] = {
                    "asn": data.get("as_number", ""),
                    "asn_org": data.get("as_name", ""),
                    "country": data.get("as_country", "")
                }
            except json.JSONDecodeError:
                continue

    print(f"[DEBUG] ASNmap resolved {len(asn_map)} IPs")
    return asn_map


def run_katana(urls: list[str], max_urls: int = 10) -> list[dict]:
    """Run Katana to crawl endpoints."""
    if not urls:
        return []

    # Limit URLs to avoid long scans
    urls_to_scan = urls[:max_urls]
    input_data = "\n".join(urls_to_scan)

    print(f"[DEBUG] Running Katana on {len(urls_to_scan)} URLs")

    cmd = [
        "docker", "run", "--rm", "-i",
        "projectdiscovery/katana",
        "-silent",
        "-json",
        "-depth", "2",
        "-jc"
    ]

    result = subprocess.run(cmd, input=input_data, capture_output=True, text=True)

    endpoints = []
    seen_urls = set()

    for line in result.stdout.strip().split("\n"):
        if line:
            try:
                data = json.loads(line)

                # Handle different JSON structures
                url = data.get("request", {}).get("endpoint", "") or data.get("endpoint", "")

                if not url:
                    continue

                if url in seen_urls:
                    continue

                seen_urls.add(url)

                # Check if sensitive
                is_sensitive, reason = check_sensitive(url)

                # Get status code
                status_code = data.get("response", {}).get("status_code") or data.get("status_code")

                # Get method
                method = data.get("request", {}).get("method", "GET") or data.get("method", "GET")

                endpoints.append({
                    "url": url,
                    "path": extract_path(url),
                    "method": method,
                    "status_code": status_code,
                    "is_sensitive": is_sensitive,
                    "sensitivity_reason": reason
                })

            except json.JSONDecodeError:
                continue

    print(
        f"[DEBUG] Katana found {len(endpoints)} endpoints, {sum(1 for e in endpoints if e['is_sensitive'])} sensitive")
    return endpoints


def scan_domain(domain: str) -> dict:
    """Full scan: Subfinder → httpx → ASNmap → Katana."""

    # Step 1: Discover subdomains
    subdomains = run_subfinder(domain)

    # Step 2: Probe for IPs and status
    httpx_results = run_httpx(subdomains)

    # Step 3: Get ASN info for discovered IPs
    ips = list(set([r["ip_address"] for r in httpx_results if r["ip_address"]]))
    asn_map = run_asnmap(ips)

    # Step 4: Crawl endpoints with Katana (only alive hosts)
    alive_urls = [r["url"] for r in httpx_results if r["url"] and r["host_status"] == 1]
    endpoints = run_katana(alive_urls)

    # Combine subdomain results
    combined_subdomains = []
    for result in httpx_results:
        ip = result["ip_address"]
        asn_info = asn_map.get(ip, {})
        combined_subdomains.append({
            "subdomain": result["subdomain"],
            "ip_address": ip,
            "host_status": result["host_status"],
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
                "host_status": 2,
                "asn": None,
                "asn_org": None,
            })

    return {
        "subdomains": combined_subdomains,
        "endpoints": endpoints
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
    sensitive_count = sum(1 for e in results["endpoints"] if e["is_sensitive"])

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

    # Save endpoints
    for item in results["endpoints"]:
        endpoint = Endpoint(
            scan_id=scan.id,
            url=item["url"],
            path=item["path"],
            method=item["method"],
            status_code=item["status_code"],
            is_sensitive=item["is_sensitive"],
            sensitivity_reason=item["sensitivity_reason"]
        )
        db.add(endpoint)

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
        dead_count=dead_count,
        endpoints_count=len(results["endpoints"]),
        sensitive_count=sensitive_count
    )


@router.get("/scan/{scan_id}/subdomains", response_model=List[SubdomainResponse])
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


@router.get("/scan/{scan_id}/endpoints", response_model=List[EndpointResponse])
def get_endpoints(scan_id: str, db: Session = Depends(get_db)):
    """Get all endpoints for a scan with row numbers."""

    query = db.execute(text("""
        SELECT 
            ROW_NUMBER() OVER (ORDER BY is_sensitive DESC, discovered_at) as row_num,
            id, url, path, method, status_code, is_sensitive, sensitivity_reason, discovered_at
        FROM endpoints
        WHERE scan_id = :scan_id
        ORDER BY is_sensitive DESC, discovered_at
    """), {"scan_id": scan_id})

    results = []
    for row in query:
        results.append({
            "row_num": row.row_num,
            "id": str(row.id),
            "url": row.url,
            "path": row.path,
            "method": row.method,
            "status_code": row.status_code,
            "is_sensitive": row.is_sensitive,
            "sensitivity_reason": row.sensitivity_reason,
            "discovered_at": row.discovered_at
        })

    return results


@router.get("/scan/{scan_id}/sensitive")
def get_sensitive_endpoints(scan_id: str, db: Session = Depends(get_db)):
    """Get only sensitive endpoints for a scan."""

    query = db.execute(text("""
        SELECT url, path, sensitivity_reason, status_code
        FROM endpoints
        WHERE scan_id = :scan_id AND is_sensitive = TRUE
        ORDER BY sensitivity_reason
    """), {"scan_id": scan_id})

    return [
        {
            "url": row.url,
            "path": row.path,
            "reason": row.sensitivity_reason,
            "status_code": row.status_code
        }
        for row in query
    ]


@router.get("/scans")
def list_scans(db: Session = Depends(get_db)):
    """List all scans with stats."""

    query = db.execute(text("""
        SELECT 
            s.id, s.domain, s.status, s.progress, s.created_at,
            COUNT(DISTINCT sub.id) as subdomains_count,
            COUNT(DISTINCT e.id) as endpoints_count,
            SUM(CASE WHEN e.is_sensitive THEN 1 ELSE 0 END) as sensitive_count
        FROM scans s
        LEFT JOIN subdomains sub ON s.id = sub.scan_id
        LEFT JOIN endpoints e ON s.id = e.scan_id
        GROUP BY s.id, s.domain, s.status, s.progress, s.created_at
        ORDER BY s.created_at DESC
    """))

    return [
        {
            "id": str(row.id),
            "domain": row.domain,
            "status": row.status,
            "progress": row.progress,
            "created_at": row.created_at,
            "subdomains_count": row.subdomains_count,
            "endpoints_count": row.endpoints_count,
            "sensitive_count": row.sensitive_count or 0
        }
        for row in query
    ]