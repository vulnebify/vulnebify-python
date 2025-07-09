import json

from abc import ABC, abstractmethod

from .models import *
from .errors import VulnebifyError, VulnebifyApiError


class OutputType(str, Enum):
    HUMAN = "human"
    JSON = "json"


class Output(ABC):
    @abstractmethod
    def print_checkout_progress(self, timeout_sec: int, taken_sec: int) -> int:
        raise NotImplementedError()

    @abstractmethod
    def print_message(self, message: str):
        raise NotImplementedError()

    @abstractmethod
    def print_host(self, host: HostResponse):
        raise NotImplementedError()

    @abstractmethod
    def print_domain(self, domain: DomainResponse):
        raise NotImplementedError()

    @abstractmethod
    def print_scan_list(self, scans: ScanListResponse):
        raise NotImplementedError()

    @abstractmethod
    def print_scan(self, scan: ScanResponse):
        raise NotImplementedError()

    @abstractmethod
    def print_scan_progress(self, scan: ScanResponse):
        raise NotImplementedError()

    @abstractmethod
    def print_scan_cancel(self, scan_id: str):
        raise NotImplementedError()

    @abstractmethod
    def print_scanner_list(self, scanners: ScannerListResponse):
        raise NotImplementedError()

    @abstractmethod
    def print_error(self, error: VulnebifyError):
        raise NotImplementedError()

    @abstractmethod
    def print_unexpected_error(self, error: Exception):
        raise NotImplementedError()


class HumanOutput(Output):
    def print_checkout_progress(self, timeout_sec: int, taken_sec: int) -> int:
        output_lines = [
            f"🔄 Still waiting for checkout... ({timeout_sec - taken_sec}s remaining)"
        ]
        for line in output_lines:
            print(line)
        return len(output_lines)

    def print_message(self, message: str):
        print(message)

    def print_host(self, host: HostResponse):
        print(f"IP: {host.ip_str}")

        if host.location or host.autonomous_system:
            print("")

        if host.location:
            location = [host.location.country, host.location.region, host.location.city]
            joined_location = ", ".join([l for l in location if l])
            print(f"Location: {joined_location}")

        if host.autonomous_system:
            print(
                f"Organization: {host.autonomous_system.name} (ASN: {host.autonomous_system.asn})"
            )

        if host.hostnames or host.cves:
            print("")

        if host.hostnames:
            hostnames = ", ".join(host.hostnames)
            print(f"Hostnames: {hostnames}")

        if host.cves:
            cves = ", ".join(host.cves)
            print(f"CVEs: {cves}")

        if host.ports:
            print("")
            print(f"=== Ports ===")
            for port in host.ports:
                print(
                    f"{port.protocol.value.upper()} {port.port}/{port.transport.value.upper()}"
                )
                lines = port.banner.splitlines()
                for line in lines:
                    print(f"    {line}")
                print("")

    def print_domain(self, domain: DomainResponse):
        print(f"Domain: {domain.domain}")

        if domain.dns:
            print("")
            records = ", ".join([f"{r.value} ({r.type.value})" for r in domain.dns])
            print(f"DNS: {records}")

        if domain.subdomains:
            print("")
            for subdomain in domain.subdomains:
                records = ", ".join(
                    [f"{r.value} ({r.type.value})" for r in subdomain.dns]
                )
                if records:
                    print(f"{subdomain.domain}: {records}")
                else:
                    print(f"{subdomain.domain}")

    def print_scan_list(self, scans: ScanListResponse):
        print(f"=== Scans ({scans.total}) ===")

        if not scans.items:
            print("No scans. Run the command to make one:")
            print("vulnebify run scan SCOPES -p PORTS")

        for scan in scans.items:
            scopes = scan.scopes[0]

            if len(scan.scopes) > 1:
                scopes += f" and {len(scan.scopes) - 1} more"

            started_at = scan.started_at.strftime("%Y-%m-%d %H:%M:%S")
            print(f"{scan.scan_id} - {started_at} - {scopes} - {scan.status.value}")

    def print_scan(self, scan: ScanResponse):
        print(f"Scan ID: {scan.scan_id} ({scan.status.value})")
        print("")

        started_at = scan.started_at.strftime("%Y-%m-%d %H:%M:%S")
        if scan.ended_at:
            ended_at = scan.ended_at.strftime("%Y-%m-%d %H:%M:%S")
            duration = (scan.ended_at - scan.started_at).total_seconds()
            print(f"Duration: {started_at} - {ended_at} ({int(duration)} seconds)")
        else:
            print(f"Duration: {started_at} - running")

        scopes = ",".join(scan.scopes)
        ports = ",".join(scan.ports)
        scanners = ",".join(scan.scanners)

        if scanners:
            print(
                f"Scopes: {scopes} on {ports.upper()} port(s) with {scanners} scanner(s)"
            )
        else:
            print(f"Scopes: {scopes} on {ports.upper()} port(s)")

        print("")

        if scan.logs:
            print(f"=== Logs ===")
            for log in scan.logs:
                print(f"Scanned: {log.entry}")

        if scan.reports:
            print("")
            print(f"=== Reports ===")
            for report in scan.reports:
                print(f"Report ({report.type}): {report.slug}")

    def print_scan_progress(self, scan: ScanResponse) -> int:
        output_lines = [f"🔄 Scan status: {scan.status.value}"]

        if scan.progress.initiated_tasks:
            initiated = scan.progress.initiated_tasks
            completed = scan.progress.completed_tasks
            progress_pct = (completed / initiated) * 100
            formatted_progress_pct = f"{progress_pct:.2f}"

            message = f" Progress: {initiated}/{completed} task(s) -> {formatted_progress_pct}%"

            output_lines[0] += message

        if scan.logs:
            pass

        if scan.status == ScanStatus.QUEUED:
            output_lines = [f"🔄 Scan status: {scan.status.value}"]
        if scan.status == ScanStatus.FINISHED:
            output_lines = [f"✅ Scan status: {scan.status.value}"]
        if scan.status == ScanStatus.CANCELED:
            output_lines = [f"🛑 Scan status: {scan.status.value}"]

        for line in output_lines:
            print(line)

        return len(output_lines)

    def print_scan_cancel(self, scan_id: str):
        print(f"✅ Scan {scan_id} successfully canceled!")

    def print_scanner_list(self, scanners: ScannerListResponse):
        print(f"=== Scanners ({scanners.total}) ===")
        for scanner in scanners.items:
            print(f"{scanner.id} - {scanner.description}")

    def print_error(self, error: VulnebifyError):
        message = error.message

        if isinstance(error, VulnebifyApiError):
            if "error" in error.response and "code" in error.response["error"]:
                error_code = error.response["error"]["code"]
                message += f" Code: {error_code}."
            if "error" in error.response and "message" in error.response["error"]:
                error_message = error.response["error"]["message"]
                message += f" Message: {error_message}"

        print(message)

    def print_unexpected_error(self, error: Exception):
        print("🛑 Oh no! Unexpected error:")
        print(str(error))
        print("Create issue: https://github.com/vulnebify/vulnebify-python/issues")


class JsonOutput(Output):
    def print_checkout_progress(self, _: int, taken_sec: int) -> int:
        out = json.dumps(
            {
                "status": "running",
                "progress": {
                    "taken_sec": taken_sec,
                },
            },
            indent=2,
        )
        print(out)
        return len(out.splitlines())

    def print_message(self, message: str):
        out = json.dumps({"message": message}, indent=2, ensure_ascii=False)
        print(out)

    def print_host(self, host: HostResponse):
        print(host.model_dump_json(indent=2))

    def print_domain(self, domain: DomainResponse):
        print(domain.model_dump_json(indent=2))

    def print_scan_list(self, scans: ScanListResponse):
        print(scans.model_dump_json(indent=2))

    def print_scan(self, scan: ScanResponse):
        print(scan.model_dump_json(indent=2))

    def print_scan_progress(self, scan: ScanResponse) -> int:
        out = json.dumps(
            {
                "status": scan.status,
                "progress": {
                    "initiated_tasks": scan.progress.initiated_tasks,
                    "completed_tasks": scan.progress.completed_tasks,
                },
            },
            indent=2,
        )
        print(out)
        return len(out.splitlines())

    def print_scan_cancel(self, scan_id: str):
        out = json.dumps(
            {"scan_id": scan_id, "status": ScanStatus.CANCELED.value},
            indent=2,
        )
        print(out)

    def print_scanner_list(self, scanners: ScannerListResponse):
        print(scanners.model_dump_json(indent=2))

    def print_error(self, error: VulnebifyError):
        obj = {"message": error.message}

        if isinstance(error, VulnebifyApiError):
            obj["status_code"] = error.status_code
            obj["response"] = error.response

        out = json.dumps(obj, indent=2, ensure_ascii=False)
        print(out)

    def print_unexpected_error(self, error: Exception):
        message = f"Oh no! Unexpected error: {str(error)}"
        suggestion = (
            "Create issue: https://github.com/vulnebify/vulnebify-python/issues"
        )
        out = json.dumps({"message": message, "suggestion": suggestion}, indent=2)
        print(out)
