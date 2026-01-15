from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from pydantic import BaseModel
from datetime import datetime
from ..models.database import get_db
from ..models.scan import Scan, Subdomain
from ..services.subfinder import run_subfinder

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

@router.post("/scan", response_model=ScanResponse)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """Start a new scan for a domain."""

    # Create scan record
    scan = Scan(domain=request.domain, status="running")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run Subfinder
    results = run_subfinder(request.domain)

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