# Vulnebify CLI

⚡️ A fast, portable CLI to scan assets, view results, and integrate the Vulnebify API into your workflows with real-time, structured output.

[![Run Tests](https://github.com/vulnebify/vulnebify-python/actions/workflows/run_tests.yaml/badge.svg)](https://github.com/vulnebify/vulnebify-python/actions/workflows/run_tests.yaml)
[![Publish Release](https://github.com/vulnebify/vulnebify-python/actions/workflows/publish_release.yaml/badge.svg)](https://github.com/vulnebify/vulnebify-python/actions/workflows/publish_release.yaml)

🔹[Profile entire country within minutes](https://asciinema.org/a/727291)

🔹[Scan 65k ports in 7 seconds](https://asciinema.org/a/727292)

🔹[Enumarate subdomains and discovery open ports](https://asciinema.org/a/727289)

[![asciicast](https://asciinema.org/a/727288.svg)](https://asciinema.org/a/727288)

**Vulnebify** conducts safe, non-intrusive scans focused strictly on public metadata, following a transparent and ethical approach that respects system boundaries and privacy.

## Quick start

### Install

```bash
pip install vulnebify
```

### Login

```bash
vulnebify login
```

### Run a scan
```bash
vulnebify run scan 45.33.32.156
```

### View results

via CLI
```bash
vulnebify get scan SCAN_ID
```

via UI
```bash
https://vulnebify.com/scan/SCAN_ID
```

## Installation

### From PyPI

```bash
pip install vulnebify
```

### From Release

Download the latest precompiled binary from the [Releases](https://github.com/vulnebify/vulnebify-python/releases) page:

```bash
chmod +x vulnebify && ./vulnebify
```

### From Sources

```bash
git clone https://github.com/vulnebify/vulnebify-python.git && cd vulnebify-python && python3 -m venv .venv && source .venv/bin/activate && pip install .
```

## Commands

### `login`

| Command                             | Description                                                                                                                                                                                     |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vulnebify login`                   | Login to the Vulnebify API.                                                                                                                                                                               |
| `vulnebify login --api-key API_KEY` | API key for authentication. Prefer using the interactive prompt for security. Only use this flag in CI/CD or trusted environments. You can also set the `VULNEBIFY_API_KEY` environment variable. |

✅ The API key will be stored at `~/.vulnebifyrc` after successful login.

### `run scan`

| Command                                                                       | Description                                                                                                         |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `vulnebify run scan 45.33.32.156`                                             | Run scan for a IP scanning scope.                                                                                   |
| `vulnebify run scan 45.33.32.156 --output json`                               | Run scan for a IP scanning scope with `json` output. Default: `human`.                                              |
| `vulnebify run scan 45.33.32.156  --wait`                                     | Run scan for a IP scanning scope and block until the scan finishes.                                                 |
| `vulnebify run scan vulnebify.com --ports TOP1000`                            | Run scan for a IP scanning scope to check `TOP1000` ports. Default: `TOP100`.                                       |
| `vulnebify run scan vulnebify.com --scanners subdomain`                       | Run scan for a domain scanning scope and enumerate subdomains with `subdomain` scanner.                             |
| `vulnebify run scan 193.176.180.0/22 -p 554 --scanners rtsp`                  | Run scan for a CIDR scanning scope to check a single `554` port with detailed checks for RTSP using `rtsp` scanner. |
| `vulnebify run scan 45.33.32.156 vulnebify.com 193.176.180.0/22 -p 8000-9000` | Run scan for multiple scanning scopes to check `8000-9000` port range.                                              |

📥 Piping is supported too:
```bash
echo 193.176.180.0/22 | vulnebify run scan -p 80 443 --wait -o json | jq .hosts[]
```

### `get scan|host|domain`

| Command                                                 | Description                                                       |
| ------------------------------------------------------- | ----------------------------------------------------------------- |
| `vulnebify get scan s_061a2fb6ade31d8e8sf82b5e36290a51` | Get previously executed scan.                                     |
| `vulnebify get host 45.33.32.156 --output json`         | Get previously scanned host with `json` output. Default: `human`. |

### `ls scan|scanners`

| Command                              | Description                     |
| ------------------------------------ | ------------------------------- |
| `vulnebify list scans`               | List previously executed scans. |
| `vulnebify list scanners`            | List available scanners.        |
| `vulnebify get domain vulnebify.com` | Get previously scanned domain   |

### `cancel scan`

| Command                                                    | Description          |
| ---------------------------------------------------------- | -------------------- |
| `vulnebify cancel scan s_061a2fb6ade31d8e8sf82b5e36290a51` | Cancels running scan |

## Learn more

- [About Vulnebify](https://about.vulnebify.com)
- [API documentation](https://docs.vulnebify.com)

---
