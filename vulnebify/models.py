from pydantic import BaseModel

from datetime import datetime
from typing import Dict, List, Any

from enum import Enum


class GeneratedKey(BaseModel):
    api_key: str
    api_key_hash: str

    active: bool


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    FINALIZING = "finalizing"
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
    S7 = "s7"
    MODBUS = "modbus"
    EIP = "eip"
    UNKNOWN = "unknown"


class Transport(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class ScanRun(BaseModel):
    scan_id: str


class ScanProgress(BaseModel):
    initiated_tasks: int = 0
    completed_tasks: int = 0


class ScanHostRef(BaseModel):
    ip_str: str

    inserted_at: datetime


class ScanReportRef(BaseModel):
    type: str
    slug: str


class Scan(BaseModel):
    scan_id: str
    status: ScanStatus

    started_at: datetime
    ended_at: datetime | None

    scopes: List[str]
    ports: List[str | int] = []
    scanners: List[str] = []

    progress: ScanProgress

    hosts: List[ScanHostRef]
    reports: List[ScanReportRef]

    def last_scanned_at(self) -> datetime:
        if not self.hosts:
            return datetime.min

        return self.hosts[-1].inserted_at

    def last_scanned_ips(self, last_scanned_at: datetime = datetime.min) -> List[str]:
        ips = []

        for host in self.hosts:
            if host.inserted_at > last_scanned_at:
                ips.append(host.ip_str)

        return ips


class ScanListItem(BaseModel):
    scan_id: str

    scopes: List[str]

    status: ScanStatus

    started_at: datetime
    ended_at: datetime | None


class ScanList(BaseModel):
    total: int
    items: List[ScanListItem]


class ScannerListItem(BaseModel):
    id: str
    description: str
    depends_on: List[str]


class ScannerList(BaseModel):
    total: int
    items: List[ScannerListItem]


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


class Service(BaseModel):
    port: int
    banner: str | None
    protocol: Protocol | None
    transport: Transport

    tls: Tls | None
    http: Http | None
    rtsp: Rtsp | None


class Host(BaseModel):
    ip_str: str
    ip_int: int

    first_scanned_at: datetime | None
    last_scanned_at: datetime | None

    location: Location | None
    autonomous_system: AutonomousSystem | None

    hostnames: List[str]
    cves: List[str]

    labels: List[Label]

    services: List[Service]


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


class RootDomain(BaseModel):
    domain: str

    first_scanned_at: datetime | None = None
    last_scanned_at: datetime | None = None

    dns: List[DnsRecord]
    subdomains: List[Domain]
