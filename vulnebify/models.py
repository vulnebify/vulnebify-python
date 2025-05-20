from pydantic import BaseModel

from datetime import datetime
from typing import List, Dict, Set, Tuple

from enum import Enum


class KeyResponse(BaseModel):
    api_key: str
    api_key_hash: str

    active: bool


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    FINISHED = "finished"
    CANCELED = "canceled"


class ScanRequest(BaseModel):
    scopes: List[str]  #
    ports: List[str | int] = []
    scanners: List[str] = []


class ScanRunResponse(BaseModel):
    scan_id: str


class ScanResponse(BaseModel):
    scan_id: str

    scopes: List[str]

    status: ScanStatus

    started_at: datetime
    ended_at: datetime | None


class ScanListItemResponse(BaseModel):
    scan_id: str

    scopes: List[str]

    status: ScanStatus

    started_at: datetime
    ended_at: datetime | None


class ScanListResponse(BaseModel):
    total: int
    items: List[ScanListItemResponse]


class ScanSubdomainsReport(BaseModel):
    domain: str
    hosts: List[str]


class ScanPortsReport(BaseModel):
    host: str
    ports: List[int]


class ScanCvesReport(BaseModel):
    host: str
    cves: List[str]


class ScanProtectorsReport(BaseModel):
    protector: str
    hosts: List[str]


class ScanCertificateReport(BaseModel):
    md5: str
    not_after: datetime


class ScanCertificatesReport(BaseModel):
    host: str
    certificates: List[ScanCertificateReport]


class ScanReportResponse(BaseModel):
    scan_id: str

    started_at: datetime
    ended_at: datetime | None

    scopes: List[str] = []

    related_domains: Set[str] = {}

    subdomains: List[ScanSubdomainsReport] = []

    ports: List[ScanPortsReport] = []

    cves: List[ScanCvesReport] = []

    protectors: List[ScanProtectorsReport] = []

    expiring_certificates: List[ScanCertificatesReport] = []


class ScanHostAmount(BaseModel):
    host: str
    amount: int


class ScanProtectorAmount(BaseModel):
    protector: str
    amount: int


class ScanSummaryResponse(BaseModel):
    scan_id: str

    started_at: datetime
    ended_at: datetime | None

    scopes: List[str]

    related_domains: Set[str] = {}

    suspicious_subdomains: Set[str] = {}

    subdomains_amount: List[ScanHostAmount] = []

    suspicious_ports: List[ScanPortsReport] = []

    cves_amount: List[ScanHostAmount] = []

    protectors_amount: List[ScanProtectorAmount] = []

    expiring_certificates_amount: List[ScanHostAmount] = []
