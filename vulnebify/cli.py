import argparse
import os
import time
import sys
import json
import getpass

from typing import List

from .client import Vulnebify
from .models import ScanStatus
from .errors import VulnebifyError

CONFIG_PATH = os.path.expanduser("~/.vulnebifyrc")
ENV_VAR_NAME = "VULNEBIFY_API_KEY"


def get_api_key():
    api_key = os.getenv(ENV_VAR_NAME)

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
        or os.getenv(ENV_VAR_NAME)
        or getpass.getpass(
            "🔒 Provide API key (key_*) to secure input. Press ENTER if you don't have one yet 🔑: "
        )
    )


def login(api_key: str | None):
    api_key = input_api_key(api_key)

    try:
        if api_key:
            vulnebify = Vulnebify(api_key)

            if vulnebify.key.active():
                print("")
                save_api_key(api_key)
            else:
                print(
                    "🛑 API key is not active. Run 'vulnebify login' again. Check --api-key argument, VULNEBIFY_API_KEY environment variable, or input value."
                )

            return

        vulnebify = Vulnebify(None)  # None - without auth

        response = vulnebify.key.generate()

        if response.active:
            save_api_key(api_key)
            return

        print("To retrieve your API key, visit the following URL in your browser:")
        print("")
        print(f"  https://vulnebify.com/checkout?api_key_hash={response.api_key_hash}")
        print("")
        print(
            "Never share your API key. It grants full access to your Vulnebify account."
        )

        vulnebify = Vulnebify(response.api_key)
        retry = 0
        previous_output_lines = 0

        while not vulnebify.key.active() and retry <= 300:

            if previous_output_lines > 0:
                sys.stdout.write(
                    "\033[F" * previous_output_lines + "\033[K" * previous_output_lines
                )
                sys.stdout.flush()

            output_lines = [
                f"🔄 Still waiting for checkout... ({300 - retry}s remaining)"
            ]
            for line in output_lines:
                print(line)

            previous_output_lines = len(output_lines)

            retry += 1
            time.sleep(1)

        print("")
        save_api_key(response.api_key)

    except VulnebifyError as e:
        print(e.message)


def get_host(ip_address: str):
    api_key = get_api_key()
    if not api_key:
        print("⚠️  Please log in first using 'vulnebify login'")
        return

    vulnebify = Vulnebify(api_key)
    try:
        response = vulnebify.host.get(ip_address)
        print(json.dumps(json.loads(response), indent=2))
    except VulnebifyError as e:
        print(e.message)


def get_domain(domain: str):
    api_key = get_api_key()
    if not api_key:
        print("⚠️  Please log in first using 'vulnebify login'")
        return

    vulnebify = Vulnebify(api_key)
    try:
        response = vulnebify.domain.get(domain)
        print(response)
    except VulnebifyError as e:
        print(e.message)


def run_scan(scopes: List[str], ports: List[int | str], scanners: List[str]):
    api_key = get_api_key()
    if not api_key:
        print("⚠️  Please log in first using 'vulnebify login'")
        return

    if not scopes:
        print("⚠️  You must provide at least one domain, IP, or CIDR to scan")
        return

    print(f"🚀 Initiating scan for: {', '.join(scopes)}")

    vulnebify = Vulnebify(api_key)
    try:
        scan = vulnebify.scan.run(scopes, ports, scanners)
        print(f"🆔 Scan started with ID: {scan.scan_id}\n")

        previous_output_lines = 0
        while True:
            scan = vulnebify.scan.get(scan.scan_id)

            if previous_output_lines > 0:
                sys.stdout.write(
                    "\033[F" * previous_output_lines + "\033[K" * previous_output_lines
                )
                sys.stdout.flush()

            output_lines = [f"🔄 Scan status: {scan.status.value}"]
            for line in output_lines:
                print(line)

            previous_output_lines = len(output_lines)

            if scan.status in [ScanStatus.FINISHED, ScanStatus.CANCELED]:
                print(f"\n✅ Scan finished with status: {scan.status.value}")
                break
            time.sleep(1)
    except VulnebifyError as e:
        print(e.message)


def get_scan(scan_id: str, summary: bool, report: bool):
    api_key = get_api_key()
    if not api_key:
        print("⚠️  Please log in first using 'vulnebify login'")
        return

    vulnebify = Vulnebify(api_key)
    try:
        if summary:
            summary = vulnebify.scan.summary(scan_id)
            print(summary.model_dump_json(indent=2))
        elif report:
            report = vulnebify.scan.report(scan_id)
            print(report.model_dump_json(indent=2))
        else:
            scan = vulnebify.scan.get(scan_id)
            print(scan.model_dump_json(indent=2))

    except VulnebifyError as e:
        print(e.message)


def list_scans():
    api_key = get_api_key()
    if not api_key:
        print("⚠️  Please log in first using 'vulnebify login'")
        return

    vulnebify = Vulnebify(api_key)
    try:
        scans = vulnebify.scan.list()
        print(f"📋 Total number of scans: {scans.total}")
        print("")
        for idx, scan in enumerate(scans.items):
            print(
                f"{idx+1}. {scan.scan_id} - ({",".join(scan.scopes)}) - {scan.status.value}"
            )
    except VulnebifyError as e:
        print(e.message)


def cli():
    # fmt: off
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
    print("A cyber defense platform. See more: https://vulnebify.com/")
    print("")
    parser = argparse.ArgumentParser(prog="vulnebify", description="Vulnebify CLI")
    parser.set_defaults(func=lambda _: parser.print_help())
    subparsers = parser.add_subparsers(dest="action")
    
    # LOGIN group
    login_parser = subparsers.add_parser("login")
    login_parser.add_argument("-k", "--api-key", help="API key for authentication. Prefer using the interactive prompt for security. Only use this flag in CI/CD or trusted environments. You can also set the VULNEBIFY_API_KEY environment variable.")
    login_parser.set_defaults(func=lambda args: login(args.api_key))

    # RUN group
    run_parser = subparsers.add_parser("run", help="Run scan")
    run_parser.set_defaults(func=lambda _: run_parser.print_help())
    run_subparsers = run_parser.add_subparsers(dest="tool")

    # run group -> run scan
    run_scans_parser = run_subparsers.add_parser("scans", aliases=["scan"], help="Run a scan")
    run_scans_parser.add_argument("scopes", nargs="+", help="Scopes to scan")
    run_scans_parser.add_argument("-p", "--ports", nargs="*", help="Ports to scan")
    run_scans_parser.add_argument("-s", "--scanners", nargs="*", help="Scanners to use")
    run_scans_parser.set_defaults(func=lambda args: run_scan(args.scopes, args.ports or [], args.scanners or []))

    # LIST group
    list_parser = subparsers.add_parser("list", aliases=["ls"], help="List previous scans")
    list_parser.set_defaults(func=lambda _: list_parser.print_help())
    list_subparsers = list_parser.add_subparsers(help="List operations")

    # list group -> list scans
    list_scans_parser = list_subparsers.add_parser("scans", aliases=["scan"], help="List scans")
    list_scans_parser.set_defaults(func=lambda _: list_scans())

    # GET group
    get_parser = subparsers.add_parser("get", help="Describe previous scans")
    get_parser.set_defaults(func=lambda _: get_parser.print_help())
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
    args.func(args)
    # fmt: on


def main():
    try:
        cli()
        print("")
    except KeyboardInterrupt:
        print("👋 Gracefully exiting. Goodbye!")


if __name__ == "__main__":
    main()
