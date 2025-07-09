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
from .output import OutputType, Output, HumanOutput, JsonOutput

CONFIG_PATH = os.path.expanduser("~/.vulnebifyrc")
VULNEBIFY_API_KEY = "VULNEBIFY_API_KEY"
VULNEBIFY_API_URL = "VULNEBIFY_API_URL"

_vulnebify: Vulnebify | None = None
_output: Output = HumanOutput()

CHECKOUT_TIMEOUT_SEC = 3600


def parse_scopes(args):
    # From file
    if args.file:
        with open(args.file) as f:
            return [line.strip() for line in f if line.strip()]

    # From stdin (pipe)
    if not sys.stdin.isatty():
        return [line.strip() for line in sys.stdin if line.strip()]

    # From positional args
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

        message = """⚠️  Use Vulnebify responsibly. Only scan systems you own or have explicit permission to test.
Violation may lead to legal consequences. See terms and conditions: https://vulnebify.com/terms

✅ API key saved successfully!"""

        _output.print_message(message)


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
            save_api_key(api_key)
        else:
            message = "🛑 API key is not active. Run 'vulnebify login' again. Check --api-key argument, VULNEBIFY_API_KEY environment variable, or input value."
            raise VulnebifyError(message)

        return

    vulnebify = Vulnebify(None, api_url)  # None - without auth

    response = vulnebify.key.generate()

    if response.active:
        save_api_key(api_key)
        return

    message = f"""To retrieve your API key, visit the following URL in your browser:

🔗 https://vulnebify.com/checkout?api_key_hash={response.api_key_hash}

Never share your API key. It grants full access to your Vulnebify account.
"""
    _output.print_message(message)

    vulnebify = Vulnebify(response.api_key, api_url)
    retry = 0
    previous_output_lines = 0

    while not vulnebify.key.active() and retry <= CHECKOUT_TIMEOUT_SEC:
        if previous_output_lines > 0:
            sys.stdout.write(
                "\033[F" * previous_output_lines + "\033[K" * previous_output_lines
            )
            sys.stdout.flush()

        previous_output_lines = _output.print_checkout_progress(
            CHECKOUT_TIMEOUT_SEC, retry
        )

        retry += 1
        time.sleep(1)

    save_api_key(response.api_key)


def run_scan(
    scopes: List[str],
    ports: List[int | str],
    scanners: List[str],
    wait: bool,
):
    if not scopes:
        message = "⚠️  You must provide at least one domain, IP, or CIDR to scan"
        raise VulnebifyError(message)

    _output.print_message(f"🚀 Initiating scan for: {', '.join(scopes)}")

    scan_id = _vulnebify.scan.run(scopes, ports, scanners)
    message = f"""🆔 Scan started with ID: {scan_id}

You can check the details any time by running:
vulnebify get scan {scan_id}

🔗 Or by visiting the link: https://vulnebify.com/scan/{scan_id}
"""
    _output.print_message(message)

    if not wait:
        return

    previous_output_lines = 0
    scan: ScanResponse = None
    while True:
        scan = _vulnebify.scan.get(scan_id)

        if previous_output_lines > 0:
            sys.stdout.write(
                "\033[F" * previous_output_lines + "\033[K" * previous_output_lines
            )
            sys.stdout.flush()

        previous_output_lines = _output.print_scan_progress(scan)

        if scan.status in [ScanStatus.FINISHED, ScanStatus.CANCELED]:
            break

        time.sleep(1)


def cancel_scan(scan_id: str):
    _vulnebify.scan.cancel(scan_id)
    _output.print_scan_cancel(scan_id)


def get_scan(scan_id: str):
    scan = _vulnebify.scan.get(scan_id)
    _output.print_scan(scan)


def list_scans():
    scans = _vulnebify.scan.list()
    _output.print_scan_list(scans)


def list_scanners():
    scanners = _vulnebify.scanner.list()
    _output.print_scanner_list(scanners)


def get_host(address: str):
    host = _vulnebify.host.get(address)
    _output.print_host(host)


def get_domain(address: str):
    domain = _vulnebify.domain.get(address)
    _output.print_domain(domain)


def print_title(parser: argparse.ArgumentParser):
    print(
        r"""
__     __ _   _  _      _   _  _____  ____   ___  _____ __   __
\ \   / /| | | || |    | \ | || ____|| __ ) |_ _||  ___|\ \ / /
 \ \ / / | | | || |    |  \| ||  _|  |  _ \  | | | |_    \ V / 
  \ V /  | |_| || |___ | |\  || |___ | |_) | | | |  _|    | |  
   \_/    \___/ |_____||_| \_||_____||____/ |___||_|      |_|            


A cyber defense platform. See more: https://about.vulnebify.com/
"""
    )
    parser.print_help()


def cli():
    # fmt: off
    
    # Shared
    output_parser = argparse.ArgumentParser(add_help=False)
    output_parser.add_argument("-o", "--output", type=OutputType, choices=["human", "json"], default=OutputType.HUMAN, help="Output format (default: human)")
    
    # Core 
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
    run_scans_parser = run_subparsers.add_parser("scans", aliases=["scan"], parents=[output_parser], help="Run a scan")
    
    run_scans_parser.add_argument("scopes", nargs="*", help="Scopes to scan (domain, IP, CIDR)")
    run_scans_parser.add_argument("-f", "--file", help="Path to file with one scope per line")
    
    run_scans_parser.add_argument("-p", "--ports", nargs="*", help="Ports to scan (default: top100)")
    run_scans_parser.add_argument("-s", "--scanners", nargs="*", help="Scanners to use (default: empty)")
    run_scans_parser.add_argument("-w", "--wait", action="store_true", help="Wait for scan to finish (default: false)")
    run_scans_parser.set_defaults(func=lambda args: run_scan(parse_scopes(args), args.ports or ["top100"], args.scanners or [], args.wait))

    # CANCEL group
    cancel_parser = subparsers.add_parser("cancel", help="Cancel scan")
    cancel_parser.set_defaults(func=lambda _: print_title(cancel_parser))
    cancel_subparsers = cancel_parser.add_subparsers(dest="tool")

    # cancel group -> cancel scan
    cancel_scans_parser = cancel_subparsers.add_parser("scans", aliases=["scan"], parents=[output_parser], help="Cancel a scan")
    cancel_scans_parser.add_argument("scan_id", help="Scan ID")
    cancel_scans_parser.set_defaults(func=lambda args: cancel_scan(args.scan_id))
    
    # LIST group
    list_parser = subparsers.add_parser("list", aliases=["ls"], help="List scans, available scanners")
    list_parser.set_defaults(func=lambda _: print_title(list_parser))
    list_subparsers = list_parser.add_subparsers(help="List operations")

    # list group -> list scans
    list_scans_parser = list_subparsers.add_parser("scans", aliases=["scan"], parents=[output_parser], help="List scans")
    list_scans_parser.set_defaults(func=lambda _: list_scans())
    
    # list group -> list scanners
    list_scanners_parser = list_subparsers.add_parser("scanners", aliases=["scanner"], parents=[output_parser], help="List scanners")
    list_scanners_parser.set_defaults(func=lambda _: list_scanners())

    # GET group
    get_parser = subparsers.add_parser("get", help="Get scan, host or domain")
    get_parser.set_defaults(func=lambda _: print_title(get_parser))
    get_subparsers = get_parser.add_subparsers(help="Get operations")

    # get group -> get scan
    get_scans_parser = get_subparsers.add_parser("scans", aliases=["scan"], parents=[output_parser], help="Get scan")
    get_scans_parser.add_argument("scan_id", help="Scan ID")
    get_scans_parser.set_defaults(func=lambda args: get_scan(args.scan_id))

    # get group -> get host
    get_hosts_parser = get_subparsers.add_parser("hosts", aliases=["host"], parents=[output_parser], help="Get host")
    get_hosts_parser.add_argument("address", help="Host IPv4 / IPv6 address")
    get_hosts_parser.set_defaults(func=lambda args: get_host(args.address))

    # get group -> get domain
    get_domains_parser = get_subparsers.add_parser("domains", aliases=["domain"], parents=[output_parser], help="Get domain")
    get_domains_parser.add_argument("address", help="Domain address")
    get_domains_parser.set_defaults(func=lambda args: get_domain(args.address))

    args = parser.parse_args()
    
    if hasattr(args, "output"):
        global _output
        if args.output == OutputType.HUMAN:
            _output = HumanOutput()
        elif args.output == OutputType.JSON:
            _output = JsonOutput()
        else:
            raise NotImplementedError(f"Output `{args.output}` is not supported.")

    if args.action is not "login":
        api_key = get_api_key()
        
        if not api_key:
            raise VulnebifyError("⚠️  Please log in first using 'vulnebify login'")
        
        api_url = args.api_url or os.environ.get(VULNEBIFY_API_URL)
        
        global _vulnebify
        _vulnebify = Vulnebify(api_key, api_url)
        
    args.func(args)
    # fmt: on


def main():
    try:
        cli()
    except VulnebifyError as e:
        _output.print_error(e)
    except KeyboardInterrupt:
        _output.print_message("👋 Gracefully exiting. Goodbye!")
    except Exception as e:
        _output.print_unexpected_error(e)


if __name__ == "__main__":
    main()
