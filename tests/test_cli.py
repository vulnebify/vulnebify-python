import subprocess
import tempfile
import os

from tests.utils import parse_json_output


def test_help_output():
    result = subprocess.run(["vulnebify", "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert (
        "usage: vulnebify [-h] [-a API_URL] {login,run,cancel,list,ls,get} ..."
        in result.stdout
    )


def test_run_scan_domain():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "scanme.nmap.org", "-p", "80"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Scan started with ID" in result.stdout


def test_run_scan_domain_with_subdomain_scanner():
    result = subprocess.run(
        [
            "vulnebify",
            "run",
            "scan",
            "vulnebify.com",
            "--wait",
            "--scanners",
            "subdomain",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0

    json = parse_json_output(result.stdout)
    assert len(json) > 0

    scan_id = json[0]["scan_id"]
    assert scan_id is not None

    result = subprocess.run(
        ["vulnebify", "get", "scan", scan_id, "--output", "json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    json = parse_json_output(result.stdout)
    assert len(json) > 0


def test_run_scan_ip():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "1.1.1.1", "-p", "80"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Scan started with ID" in result.stdout


def test_run_scan_ip_with_wait():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "1.1.1.1", "--wait"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Discovered open port(s) on 1.1.1.1"
    assert "✅ Scan status: finished" in result.stdout


def test_run_scan_ip_from_stdin():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "-p", "80"],
        input="1.1.1.1",
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Scan started with ID" in result.stdout


def test_run_scan_ip_from_file():
    with tempfile.NamedTemporaryFile(
        delete=False, mode="w", suffix=".txt"
    ) as temp_file:
        temp_file.write("1.1.1.1\n")
        temp_file_path = temp_file.name

    try:
        result = subprocess.run(
            ["vulnebify", "run", "scan", "--file", temp_file_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Scan started with ID" in result.stdout
    finally:
        os.remove(temp_file_path)


def test_run_scan_cidr():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "1.1.1.1/31", "-p", "80"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "Scan started with ID" in result.stdout


def test_cancel_scan():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "1.1.1.1/31", "-o", "json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    json = parse_json_output(result.stdout)
    assert len(json) > 0

    scan_id = json[0]["scan_id"]

    result = subprocess.run(
        ["vulnebify", "cancel", "scan", scan_id],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert f"✅ Scan {scan_id} successfully canceled!\n" == result.stdout


def test_run_scan_bad_scope():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "KEK", "-p", "80"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan_scope_invalid" in result.stdout


def test_run_scan_bad_ports():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "1.1.1.1", "-p", "80333333"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan_port_invalid" in result.stdout


def test_run_scan_bad_scanners():
    result = subprocess.run(
        ["vulnebify", "run", "scan", "1.1.1.1", "-p", "8080", "-s", "superscanner"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "scan_scanner_invalid." in result.stdout


def test_get_host():
    result = subprocess.run(
        ["vulnebify", "get", "host", "1.1.1.1", "-o", "json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    json = parse_json_output(result.stdout)
    assert len(json) > 0


def test_get_domain():
    result = subprocess.run(
        ["vulnebify", "get", "domain", "vulnebify.com", "-o", "json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    json = parse_json_output(result.stdout)
    assert len(json) > 0


def test_list_scans():
    result = subprocess.run(
        ["vulnebify", "ls", "scans", "-o", "json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    json = parse_json_output(result.stdout)
    assert len(json) > 0


def test_list_scanners():
    result = subprocess.run(
        ["vulnebify", "ls", "scanners", "-o", "json"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    json = parse_json_output(result.stdout)
    assert len(json) > 0
