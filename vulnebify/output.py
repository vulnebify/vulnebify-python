import json
import sys

from abc import ABC, abstractmethod

from vulnebify.models import *
from vulnebify.errors import VulnebifyError, VulnebifyApiError


class OutputType(str, Enum):
    HUMAN = "human"
    JSON = "json"


class Output(ABC):
    @abstractmethod
    def print_active_api_key(self, api_key: str):
        raise NotImplementedError()

    @abstractmethod
    def print_inactive_api_key(self, api_key: str, api_key_hash: str):
        raise NotImplementedError()

    @abstractmethod
    def print_host(self, host: Host):
        raise NotImplementedError()

    @abstractmethod
    def print_domain(self, domain: RootDomain):
        raise NotImplementedError()

    @abstractmethod
    def print_scan_list(self, scans: ScanList):
        raise NotImplementedError()

    @abstractmethod
    def print_scan(self, scan: Scan):
        raise NotImplementedError()

    @abstractmethod
    def print_scan_initiating(
        self,
        scopes: List[str],
        ports: List[int | str],
        scanners: List[str],
    ):
        raise NotImplementedError()

    @abstractmethod
    def print_scan_initiated(self, scan_id: str):
        raise NotImplementedError()

    @abstractmethod
    def print_scan_progress(self, scan: Scan, last_seen: datetime) -> datetime:
        raise NotImplementedError()

    @abstractmethod
    def print_scan_cancel(self, scan_id: str):
        raise NotImplementedError()

    @abstractmethod
    def print_scanner_list(self, scanners: ScannerList):
        raise NotImplementedError()

    @abstractmethod
    def print_error(self, error: VulnebifyError):
        raise NotImplementedError()

    @abstractmethod
    def print_unexpected_error(self, error: Exception):
        raise NotImplementedError()

    @abstractmethod
    def print_exit(self):
        raise NotImplementedError()


class HumanOutput(Output):
    def print_active_api_key(self, _: str):
        message = """⚠️  Use Vulnebify responsibly. Only scan systems you own or have explicit permission to test.
Violation may lead to legal consequences. See terms and conditions: https://vulnebify.com/terms

✅ API key saved successfully!"""
        print(message)

    def print_inactive_api_key(self, api_key_hash: str):
        message = f"""
To activate your API key, visit the following URL in your browser:
🔗 https://vulnebify.com/login/?api_key_hash={api_key_hash}
"""
        print(message)

    def print_host(self, host: Host):
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

        if host.services:
            print("")
            print(f"=== Ports ===")
            for port in host.services:
                print(
                    f"{port.protocol.value.upper()} {port.port}/{port.transport.value.upper()}"
                )
                lines = port.banner.splitlines()
                for line in lines:
                    print(f"    {line}")
                print("")

    def print_domain(self, domain: RootDomain):
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

    def print_scan_list(self, scans: ScanList):
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

    def print_scan(self, scan: Scan):
        print(f"Scan ID: {scan.scan_id} ({scan.status.value})")
        print("")

        started_at = scan.started_at.strftime("%Y-%m-%d %H:%M:%S")
        if scan.ended_at:
            ended_at = scan.ended_at.strftime("%Y-%m-%d %H:%M:%S")
            duration = (scan.ended_at - scan.started_at).total_seconds()
            print(f"Duration: {started_at} - {ended_at} ({int(duration)} seconds)")
        else:
            print(f"Duration: {started_at} - running")

        scopes = ", ".join(scan.scopes)
        ports = ", ".join(scan.ports)
        scanners = ", ".join(scan.scanners)

        if scanners:
            print(
                f"Scopes: {scopes} on {ports.upper()} port(s) with {scanners} scanner(s)"
            )
        else:
            print(f"Scopes: {scopes} on {ports.upper()} port(s)")

        print("")

        if scan.hosts:
            print(f"=== Hosts ===")
            for host in scan.hosts:
                print(f"Scanned: {host.ip_str}")

        if scan.reports:
            print("")
            print(f"=== Reports ===")
            for report in scan.reports:
                print(f"Report ({report.type}): {report.slug}")

    def print_scan_initiating(
        self,
        scopes: List[str],
        ports: List[int | str],
        scanners: List[str],
    ):
        scopes = ", ".join(scopes)
        ports = ", ".join(ports)
        scanners = ", ".join(scanners)

        if scanners:
            print(
                f"🚀 Initiating scan for: {scopes} on {ports.upper()} port(s) with {scanners} scanner(s)"
            )
        else:
            print(f"🚀 Initiating scan for: {scopes} on {ports.upper()} port(s)")

    def print_scan_initiated(self, scan_id: str):
        message = f"""🆔 Scan started with ID: {scan_id}

You can check the details any time by running:
vulnebify get scan {scan_id}

🔗 Or by visiting the link: https://vulnebify.com/scan/{scan_id}
"""
        print(message)

    def print_scan_progress(self, scan: Scan, last_scanned_at: datetime) -> datetime:
        output_lines = []

        if scan.status == ScanStatus.QUEUED:
            output_lines = [f"🔄 Scan status: {scan.status.value}"]
        if scan.status == ScanStatus.RUNNING:
            ips = scan.last_scanned_ips(last_scanned_at)
            last_scanned_at = scan.last_scanned_at()

            output_lines += [f"Discovered open port(s) on {ip}" for ip in ips]

            initiated = scan.progress.initiated_tasks
            completed = scan.progress.completed_tasks
            progress_pct = (completed / initiated) * 100
            formatted_progress_pct = f"{progress_pct:.2f}"

            message = f"🔄 Scan running...Progress: {initiated}/{completed} task(s) -> {formatted_progress_pct}%"

            output_lines.append(message)
        if scan.status == ScanStatus.FINISHED:
            ips = scan.last_scanned_ips()
            duration = (scan.ended_at - scan.started_at).total_seconds()

            message = f"✅ Scan finished! Processed: {len(ips)} host(s) during {int(duration)} second(s)"

            output_lines.append(message)
        if scan.status == ScanStatus.CANCELED:
            output_lines.append(f"🛑 Scan canceled.")

        # Refresh status line (ending one)
        sys.stdout.write("\033[F\033[K")

        for line in output_lines:
            print(line)

        return last_scanned_at

    def print_scan_cancel(self, scan_id: str):
        print(f"✅ Scan {scan_id} successfully canceled!")

    def print_scanner_list(self, scanners: ScannerList):
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

    def print_exit(self):
        print("👋 Gracefully exiting. Goodbye!")


class JsonOutput(Output):
    def print_active_api_key(self, api_key: str):
        out = json.dumps(
            {
                "api_key_last4": api_key[:4] + "*" * (len(api_key) - 8) + api_key[-4:],
                "caution": "⚠️  Use Vulnebify responsibly. Only scan systems you own or have explicit permission to test. Violation may lead to legal consequences.",
                "terms_url": "https://vulnebify.com/terms",
            },
            ensure_ascii=False,
        )
        print(out)

    def print_inactive_api_key(self, api_key_hash: str):
        out = json.dumps(
            {
                "activation_url": f"https://vulnebify.com/login/?api_key_hash={api_key_hash}",
            },
        )
        print(out)

    def print_host(self, host: Host):
        print(host.model_dump_json(indent=2))

    def print_domain(self, domain: RootDomain):
        print(domain.model_dump_json(indent=2))

    def print_scan_list(self, scans: ScanList):
        print(scans.model_dump_json(indent=2))

    def print_scan(self, scan: Scan):
        print(scan.model_dump_json(indent=2))

    def print_scan_initiating(
        self,
        scopes: List[str],
        ports: List[int | str],
        scanners: List[str],
    ):
        pass

    def print_scan_initiated(self, scan_id: str):
        out = json.dumps(
            {
                "scan_id": scan_id,
                "status": ScanStatus.QUEUED.value,
                "hosts": [],
                "progress": {
                    "initiated_tasks": 0,
                    "completed_tasks": 0,
                },
            },
            indent=2,
        )
        print(out)

    def print_scan_progress(self, scan: Scan, last_scanned_at: datetime) -> datetime:
        ips = scan.last_scanned_ips(last_scanned_at)
        last_scanned_at = scan.last_scanned_at()

        out = json.dumps(
            {
                "scan_id": scan.scan_id,
                "status": scan.status,
                "hosts": ips,
                "progress": {
                    "initiated_tasks": scan.progress.initiated_tasks,
                    "completed_tasks": scan.progress.completed_tasks,
                },
            },
            indent=2,
        )
        print(out)
        return last_scanned_at

    def print_scan_cancel(self, scan_id: str):
        out = json.dumps(
            {"scan_id": scan_id, "status": ScanStatus.CANCELED.value},
            indent=2,
        )
        print(out)

    def print_scanner_list(self, scanners: ScannerList):
        print(scanners.model_dump_json(indent=2))

    def print_error(self, error: VulnebifyError):
        obj = {"error": error.message}

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
        out = json.dumps({"error": message, "suggestion": suggestion}, indent=2)
        print(out)

    def print_exit(self):
        out = json.dumps(
            {"bye": "👋 Gracefully exiting. Goodbye!"}, indent=2, ensure_ascii=False
        )
        print(out)
