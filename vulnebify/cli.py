import argparse
import os
import time
import sys
import json
import getpass

from typing import List

from .client import Vulnebify
from .models import ScanResponse, ScanStatus
from .errors import VulnebifyError

CONFIG_PATH = os.path.expanduser("~/.vulnebifyrc")
VULNEBIFY_API_KEY = "VULNEBIFY_API_KEY"
VULNEBIFY_API_URL = "VULNEBIFY_API_URL"

_vulnebify: Vulnebify | None = Vulnebify


def parse_scopes(args):
    if args.file:
        with open(args.file) as f:
            return [line.strip() for line in f if line.strip()]
    return args.scopes or []


def get_api_key():
    api_key = os.getenv(VULNEBIFY_API_KEY)

    if api_key:
        return api_key

    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
            return config.get("api_key")

    return None


def save_api_key(api_key: str):
    with open(CONFIG_PATH, "w") as f:
        json.dump({"api_key": api_key}, f)

        # fmt: off
        print("""⚠️  Use Vulnebify responsibly. Only scan systems you own or have explicit permission to test.
Violation may lead to legal consequences. See terms and conditions: https://vulnebify.com/terms"""
        )
        print("")
        print("✅ API key saved successfully!")
        # fmt: on


def input_api_key(api_key: str | None):
    return (
        api_key
        or os.getenv(VULNEBIFY_API_KEY)
        or getpass.getpass(
            "🔒 Provide API key (key_*) to secure input. Press ENTER if you don't have one yet 🔑: "
        )
    )


def login(api_key: str | None, api_url: str):
    api_key = input_api_key(api_key)

    if api_key:
        vulnebify = Vulnebify(api_key, api_url)

        if vulnebify.key.active():
            print("")
            save_api_key(api_key)
        else:
            print(
                "🛑 API key is not active. Run 'vulnebify login' again. Check --api-key argument, VULNEBIFY_API_KEY environment variable, or input value."
            )

        return

    vulnebify = Vulnebify(None, api_url)  # None - without auth

    response = vulnebify.key.generate()

    if response.active:
        save_api_key(api_key)
        return

    print("To retrieve your API key, visit the following URL in your browser:")
    print("")
    print(f"  🔗 https://vulnebify.com/checkout?api_key_hash={response.api_key_hash}")
    print("")
    print("Never share your API key. It grants full access to your Vulnebify account.")

    vulnebify = Vulnebify(response.api_key, api_url)
    retry = 0
    previous_output_lines = 0

    while not vulnebify.key.active() and retry <= 300:

        if previous_output_lines > 0:
            sys.stdout.write(
                "\033[F" * previous_output_lines + "\033[K" * previous_output_lines
            )
            sys.stdout.flush()

        output_lines = [f"🔄 Still waiting for checkout... ({300 - retry}s remaining)"]
        for line in output_lines:
            print(line)

        previous_output_lines = len(output_lines)

        retry += 1
        time.sleep(1)

    print("")
    save_api_key(response.api_key)


def get_host(ip_address: str):
    response = _vulnebify.host.get(ip_address)
    print(json.dumps(json.loads(response), indent=2))


def get_domain(domain: str):
    response = _vulnebify.domain.get(domain)
    print(response)


def run_scan(
    scopes: List[str],
    ports: List[int | str],
    scanners: List[str],
    wait: bool,
):
    if not scopes:
        print("⚠️  You must provide at least one domain, IP, or CIDR to scan")
        return

    print(f"🚀 Initiating scan for: {', '.join(scopes)}")

    scan_id = _vulnebify.scan.run(scopes, ports, scanners)
    print(f"🆔 Scan started with ID: {scan_id}\n")
    print(f"You can check the details any time by running:")
    print(f"vulnebify get scan {scan_id}")
    print("")
    print(f"🔗 Or by visiting the link: https://vulnebify.com/scan/{scan_id}")

    if not wait:
        return

    print("")
    previous_output_lines = 0
    scan: ScanResponse = None
    while True:
        scan = _vulnebify.scan.get(scan_id)

        if previous_output_lines > 0:
            sys.stdout.write(
                "\033[F" * previous_output_lines + "\033[K" * previous_output_lines
            )
            sys.stdout.flush()

        output_lines = [f"🔄 Scan status: {scan.status.value}"]

        if scan.status == ScanStatus.QUEUED:
            output_lines = [f"🔄 Scan status: {scan.status.value} (position 0)"]
        if scan.status == ScanStatus.FINISHED:
            output_lines = [f"✅ Scan status: {scan.status.value}"]
        if scan.status == ScanStatus.CANCELED:
            output_lines = [f"🛑 Scan status: {scan.status.value}"]

        for line in output_lines:
            print(line)

        previous_output_lines = len(output_lines)

        if scan.status in [ScanStatus.FINISHED, ScanStatus.CANCELED]:
            break

        time.sleep(1)


def get_scan(scan_id: str, is_summary: bool, is_report: bool):
    if is_summary:
        summary = _vulnebify.scan.summary(scan_id)
        print(summary.model_dump_json(indent=2))
    elif is_report:
        report = _vulnebify.scan.report(scan_id)
        print(report.model_dump_json(indent=2))
    else:
        scan = _vulnebify.scan.get(scan_id)
        print(scan.model_dump_json(indent=2))


def list_scans():
    scans = _vulnebify.scan.list()
    print(f"📋 Total number of scans: {scans.total}")
    print("")
    for idx, scan in enumerate(scans.items):
        print(
            f"{idx+1}. {scan.scan_id} - ({",".join(scan.scopes)}) - {scan.status.value}"
        )


def print_title(parser: argparse.ArgumentParser):
    print(
        r"""
__     __ _   _  _      _   _  _____  ____   ___  _____ __   __
\ \   / /| | | || |    | \ | || ____|| __ ) |_ _||  ___|\ \ / /
 \ \ / / | | | || |    |  \| ||  _|  |  _ \  | | | |_    \ V / 
  \ V /  | |_| || |___ | |\  || |___ | |_) | | | |  _|    | |  
   \_/    \___/ |_____||_| \_||_____||____/ |___||_|      |_|            
"""
    )
    print("")
    print("A cyber defense platform. See more: https://about.vulnebify.com/")
    print("")
    parser.print_help()


def cli():
    # fmt: off
    parser = argparse.ArgumentParser(prog="vulnebify")
    parser.add_argument("-a", "--api-url", default="https://api.vulnebify.com/v1", help="API url (default: https://api.vulnebify.com/v1)")
    parser.set_defaults(func=lambda _: print_title(parser))
    subparsers = parser.add_subparsers(dest="action")
    
    # LOGIN group
    login_parser = subparsers.add_parser("login", help="Login to the API")
    login_parser.add_argument("-k", "--api-key", help="API key for authentication. Prefer using the interactive prompt for security. Only use this flag in CI/CD or trusted environments. You can also set the VULNEBIFY_API_KEY environment variable.")
    login_parser.set_defaults(func=lambda args: login(args.api_key, args.api_url))

    # RUN group
    run_parser = subparsers.add_parser("run", help="Run scan")
    run_parser.set_defaults(func=lambda _: print_title(run_parser))
    run_subparsers = run_parser.add_subparsers(dest="tool")

    # run group -> run scan
    run_scans_parser = run_subparsers.add_parser("scans", aliases=["scan"], help="Run a scan")
    
    run_scans_parser.add_argument("scopes", nargs="*", help="Scopes to scan (e.g. domain, IP)")
    run_scans_parser.add_argument("-f", "--file", help="Path to file with one scope per line")
    
    run_scans_parser.add_argument("-p", "--ports", nargs="*", help="Ports to scan (default: top100)")
    run_scans_parser.add_argument("-s", "--scanners", nargs="*", help="Scanners to use (default: basic)")
    run_scans_parser.add_argument("-w", "--wait", action="store_true", help="Wait for scan to finish (default: false)")
    run_scans_parser.set_defaults(func=lambda args: run_scan(parse_scopes(args), args.ports or ["top100"], args.scanners or ["basic"], args.wait))

    # LIST group
    list_parser = subparsers.add_parser("list", aliases=["ls"], help="List previous scans")
    list_parser.set_defaults(func=lambda _: print_title(list_parser))
    list_subparsers = list_parser.add_subparsers(help="List operations")

    # list group -> list scans
    list_scans_parser = list_subparsers.add_parser("scans", aliases=["scan"], help="List scans")
    list_scans_parser.set_defaults(func=lambda _: list_scans())

    # GET group
    get_parser = subparsers.add_parser("get", help="Get previous scan")
    get_parser.set_defaults(func=lambda _: print_title(get_parser))
    get_subparsers = get_parser.add_subparsers(help="Get operations")

    # get group -> get scan
    get_scans_parser = get_subparsers.add_parser("scans", aliases=["scan"], help="Get scan")
    get_scans_parser.add_argument("scan_id", help="Scan ID")
    
    get_scans_parser_group = get_scans_parser.add_mutually_exclusive_group()
    get_scans_parser_group.add_argument("--summary", action="store_true", help="Show short summary only")
    get_scans_parser_group.add_argument("--report", action="store_true", help="Show full report")
    
    get_scans_parser.set_defaults(func=lambda args: get_scan(args.scan_id, args.summary, args.report))

    # get group -> get host
    get_hosts_parser = get_subparsers.add_parser("hosts", aliases=["host"], help="Get host")
    get_hosts_parser.add_argument("address", help="Host IPv4 / IPv6 address")
    get_hosts_parser.set_defaults(func=lambda args: get_host(args.address))

    # get group -> get domain
    get_domains_parser = get_subparsers.add_parser("domains", aliases=["domain"], help="Get domain")
    get_domains_parser.add_argument("address", help="Domain address")
    get_domains_parser.set_defaults(func=lambda args: get_domain(args.address))

    args = parser.parse_args()
    
    if args.action is not "login":
        api_key = get_api_key()
        
        if not api_key:
            print("⚠️  Please log in first using 'vulnebify login'")
            return
        
        api_url = args.api_url or os.environ.get(VULNEBIFY_API_URL)
        
        global _vulnebify
        _vulnebify = Vulnebify(api_key, api_url)
        
    args.func(args)
    # fmt: on


def main():
    try:
        cli()
    except VulnebifyError as e:
        print(e.message)
    except KeyboardInterrupt:
        print("👋 Gracefully exiting. Goodbye!")
    print("")


if __name__ == "__main__":
    main()
