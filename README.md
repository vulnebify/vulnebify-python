# Vulnebify CLI

⚡️ A powerful, cross-platform command-line tool for interacting with the Vulnebify API — perform security scans, inspect hosts and domains, and retrieve results with real-time updates and machine-friendly output formats.

## 🔧 Installation

Install via pip:

```bash
pip install vulnebify
```

## 🚀 Usage

### 🔐 Login

```bash
vulnebify login
# OR
vulnebify login --api-key key_XXXXX
# OR
export VULNEBIFY_API_KEY=key_XXXXX
```

### 🔍 Run a scan

```bash
vulnebify run scan vulnebify.com -p 80 443
vulnebify run scan 1.1.1.1 vulnebify.com 193.176.180.0/22 -p 8000-9000
vulnebify run scan -f ips.txt -p top100 -s rtsp
```

Add `--wait` to block until the scan finishes:

```bash
vulnebify run scan vulnebify.com --wait
```

Piping support:

```bash
echo 193.176.180.0/22 | vulnebify run scan -p 80 554 --wait -o json | jq .hosts[]
```

### 📥 Get results

```bash
vulnebify get scan s_061a2fb6ade31d8e8sf82b5e36290a51
vulnebify get host 1.1.1.1
vulnebify get domain vulnebify.com
```

### 📃 List resources

```bash
vulnebify list scans
vulnebify list scanners
```

## 📁 Configuration

Stored at `~/.vulnebifyrc` after successful login.

## 🧪 Testing

```bash
pytest tests/
```

## 📦 Packaging

```bash
python -m build
```

## 📚 Learn more

- [About Vulnebify](https://about.vulnebify.com)
- [API documentation](https://docs.vulnebify.com)

---

© 2025 Vulnebify. All rights reserved.