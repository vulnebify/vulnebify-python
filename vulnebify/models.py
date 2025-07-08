from pydantic import BaseModel

from datetime import datetime
from typing import Dict, List, Any

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


class ScanLogType(str, Enum):
    DOMAIN_SCANNED = "domain_scanned"
    HOST_SCANNED = "host_scanned"


class Label(str, Enum):
    CLOUDFLARE = "cloudflare"


class Fingerprints(BaseModel):
    sha256: str
    sha1: str
    md5: str


class DnsRecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    SRV = "SRV"
    NS = "NS"
    PTR = "PTR"
    SOA = "SOA"
    SPF = "SPF"
    DNSKEY = "DNSKEY"


class DnsRecord(BaseModel):
    type: DnsRecordType
    value: str


class Domain(BaseModel):
    domain: str
    dns: List[DnsRecord] = []


class Label(str, Enum):
    CLOUDFLARE = "cloudflare"


class TlsSubject(BaseModel):
    common_name: str | None = None
    organization_name: str | None = None
    country_name: str | None = None
    state_or_province_name: str | None = None
    locality_name: str | None = None


class RtspResource(BaseModel):
    url: str
    screenshot: str | None = None


class Protocol(str, Enum):
    HTTP = "http"
    RTSP = "rtsp"
    SSH = "ssh"
    FTP = "ftp"
    SMTP = "smtp"
    POP3 = "pop3"
    IMAP = "imap"
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    REDIS = "redis"
    VNC = "vnc"
    TELNET = "telnet"
    UNKNOWN = "unknown"


class Transport(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class ScanRequest(BaseModel):
    scopes: List[str]
    ports: List[str | int] = []
    scanners: List[str] = []


class ScanRunResponse(BaseModel):
    scan_id: str


class ScanLogResponse(BaseModel):
    type: ScanLogType
    entry: Any


class ScanProgressResponse(BaseModel):
    initiated_tasks: int = 0
    completed_tasks: int = 0


class ScanReportResponse(BaseModel):
    type: str
    slug: str


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus

    started_at: datetime
    ended_at: datetime | None

    scopes: List[str]
    ports: List[str | int] = []
    scanners: List[str] = []

    progress: ScanProgressResponse

    logs: List[ScanLogResponse]
    reports: List[ScanReportResponse]


class ScanListItemResponse(BaseModel):
    scan_id: str

    scopes: List[str]

    status: ScanStatus

    started_at: datetime
    ended_at: datetime | None


class ScanListResponse(BaseModel):
    total: int
    items: List[ScanListItemResponse]


class ScannerListItemResponse(BaseModel):
    id: str
    description: str
    depends_on: List[str]


class ScannerListResponse(BaseModel):
    total: int
    items: List[ScannerListItemResponse]


class Coordinates(BaseModel):
    latitude: str
    longitude: str


class Location(BaseModel):
    country: str
    country_code: str
    city: str
    region: str

    coordinates: Coordinates


class AutonomousSystem(BaseModel):
    asn: int | None
    name: str


class Tls(BaseModel):
    subject: TlsSubject
    issuer: TlsSubject
    not_before: datetime | None
    not_after: datetime | None
    serial_number: str
    subject_alt_name: List[str | Any]
    version: int | None
    fingerprints: Fingerprints


class Http(BaseModel):
    status_code: int
    body: str
    headers: Dict[str, Any]
    fingerprints: Fingerprints


class Rtsp(BaseModel):
    resources: List[RtspResource]


class Port(BaseModel):
    port: int
    banner: str | None
    protocol: Protocol | None
    transport: Transport

    tls: Tls | None
    http: Http | None
    rtsp: Rtsp | None


class HostResponse(BaseModel):
    ip_str: str
    ip_int: int

    first_scanned_at: datetime | None
    last_scanned_at: datetime | None

    location: Location | None
    autonomous_system: AutonomousSystem | None

    hostnames: List[str]
    cves: List[str]

    labels: List[Label]

    ports: List[Port]


class DomainResponse(BaseModel):
    domain: str

    first_scanned_at: datetime | None = None
    last_scanned_at: datetime | None = None

    dns: List[DnsRecord]
    subdomains: List[Domain]
