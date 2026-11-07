# SMBResolver

A modular Python CLI tool for SMB network scanning, hostname resolution, and version/signing detection. Uses pure Python socket/struct implementations — no external dependencies.

## Features

- **Multi-target scanning**: Single IPs, ranges (10.0.0.1-10.0.0.50), CIDR notation (/24 or smaller)
- **Hostname resolution**: NetBIOS Node Status queries with reverse DNS fallback
- **SMB version detection**: Identifies SMBv1, SMBv2.x, and SMBv3 variants
- **Signing status**: Reports whether SMB signing is required/enabled/disabled
- **Progress bar**: Real-time scan progress visualization
- **Plugin architecture**: Each capability is a separate plugin file — easy to extend

## Requirements

- Python 3.11+
- No external dependencies (pure stdlib)

## Installation

```bash
# Clone or download the project
cd SMBResolver

# Create virtual environment (optional but recommended)
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# No pip install needed — uses only Python standard library
```

## Quick Start

### Scan a single host

```bash
python run.py --targets 192.168.1.100
```

### Scan an IP range

```bash
python run.py --targets 192.168.1.1-192.168.1.50
```

### Scan a subnet (CIDR)

```bash
python run.py --targets 192.168.1.0/24
```

### Load targets from file

```bash
python run.py --file hosts.txt
```

### Custom threads and timeout

```bash
python run.py --targets 192.168.1.0/24 --threads 50 --timeout 3
```

### Export results to JSON or CSV

```bash
python run.py --targets 192.168.1.0/24 --output results.json
python run.py --targets 192.168.1.0/24 --output results.csv
```

## Example Output

```
Scanning 5 target(s) with 20 threads...
------------------------------------------------------------
[########################################] 100.0% (5/5)
------------------------------------------------------------
IP           Hostname           SMB Version  Signing  Status 
-----------  -----------------  -----------  -------  -------
192.168.1.1  -                  SMBv2+       enabled  OK
192.168.1.2  server01.example   SMBv3        required OK

Summary: 5 hosts scanned, 4 reachable, 1 timeouts, 0 errors
```

## Plugin System

Each capability is implemented as a plugin in the `smbresolver/plugins/` directory. Plugins are auto-discovered at startup and executed in order (filename prefix controls ordering).

### Available Plugins

| Plugin | Description | Requires Auth |
|--------|-------------|---------------|
| reachability | TCP port 445/139 connectivity check | No |
| hostname | NetBIOS + reverse DNS resolution | No |
| smb_version | SMB protocol version detection | No |
| smb_signing | SMB signing status detection | No |

### Adding a New Plugin

Create a new file in `smbresolver/plugins/` with a numeric prefix for ordering (e.g., `06_my_plugin.py`):

```python
from .base import Plugin

class MyPlugin(Plugin):
    @property
    def name(self) -> str:
        return "my_feature"

    @property
    def description(self) -> str:
        return "Does something useful"

    @property
    def requires_auth(self) -> bool:
        return False  # Set True if needs credentials

    def run(self, host: str, ctx: dict) -> dict:
        # Your logic here
        # Access previous plugin results via ctx
        hostname = ctx.get("hostname")
        return {"my_field": "result"}
```

The plugin will be automatically discovered and available in scans. Use `ctx` to access scan context (credentials, previous plugin results).

## Configuration

Optional `config.yaml` file for defaults:

```yaml
scan:
  threads: 20
  timeout: 5
logging:
  level: info
  file: smbresolver.log
```

## Troubleshooting

- **Timeout errors**: Increase `--timeout` value or check network connectivity
- **Hostname resolution fails**: Ensure UDP port 137 is not blocked; some devices may not register NetBIOS names
- **SMB version shows "SMBv2+"**: Exact version detection requires successful SMB negotiation, which some hosts reject

## Security & Legal Notice

This tool performs network scanning. Use only on networks you own or have explicit permission to test. Unauthorized scanning may violate local laws or organizational policies.

## License

MIT License