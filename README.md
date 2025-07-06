# WireGuard Peer Tool

[![PyPI version](https://badge.fury.io/py/wireguard-peer-tool.svg)](https://badge.fury.io/py/wireguard-peer-tool)
[![Python Versions](https://img.shields.io/pypi/pyversions/wireguard-peer-tool)](https://pypi.org/project/wireguard-peer-tool/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modern, secure Python-based command-line tool for managing WireGuard VPN servers with advanced features including database encryption, automated client configuration generation, and comprehensive peer management.

## Features

- **Database Encryption**: Optional master password protection for all sensitive data
- **Automated Client Packages**: Generate password-protected ZIP files with configs, QR codes, and keys
- **Smart IP Management**: Automatic IP assignment with conflict detection
- **Live Configuration Updates**: Regenerate WireGuard configs without service disruption
- **Export/Import**: CSV and JSON support for peer data management
- **Repair Tools**: Fix and regenerate damaged client packages
- **Detailed Peer Information**: View comprehensive peer details and ZIP passwords
- **Modern CLI**: Intuitive command structure with helpful error messages

## Quick Start

### Installation

Install from PyPI (recommended):

```bash
pip install wireguard-peer-tool
```

Or install from source:

```bash
git clone https://github.com/dacoburn/wireguard-peer-tool.git
cd wireguard-peer-tool
pip install -e .
```

### System Requirements

- **Operating System**: Linux (Ubuntu 18.04+, Debian 10+, CentOS 7+, etc.)
- **Python**: 3.8 or higher
- **WireGuard**: Must be installed and configured
- **Permissions**: Root/sudo access for WireGuard operations

### Install WireGuard
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install wireguard wireguard-tools

# RHEL/CentOS/Fedora
sudo dnf install wireguard-tools

# Arch Linux
sudo pacman -S wireguard-tools
```

### Basic Usage

1. **Initialize with existing WireGuard config:**
   ```bash
   wg-peer-tool init
   ```

2. **Add a new peer:**
   ```bash
   sudo wg-peer-tool add-peer alice
   ```

3. **List all peers:**
   ```bash
   wg-peer-tool list-peers
   ```

4. **View peer details and ZIP password:**
   ```bash
   wg-peer-tool show-peer alice
   ```

5. **View all ZIP passwords:**
   ```bash
   wg-peer-tool peer-zip-info
   ```

## Commands

### Server Management
```bash
# Initialize from existing config
wg-peer-tool init

# Update server settings
sudo wg-peer-tool update-config --dns 8.8.8.8 --client-root /etc/wireguard/clients

# Regenerate WireGuard configuration
sudo wg-peer-tool regenerate-wg-conf

# Restart WireGuard service
sudo wg-peer-tool restart-wireguard
```

### Peer Management
```bash
# Add new peer
sudo wg-peer-tool add-peer <name>

# Remove peer
sudo wg-peer-tool remove-peer <name>

# List all peers
wg-peer-tool list-peers

# Show detailed peer info
wg-peer-tool show-peer <name>

# View ZIP passwords for all peers
wg-peer-tool peer-zip-info
```

### Data Management
```bash
# Export peers to CSV
wg-peer-tool export-peers --format csv --output peers.csv

# Export peers to JSON
wg-peer-tool export-peers --format json --output peers.json

# Import peers from config
sudo wg-peer-tool import-peers

# Repair all peer ZIP packages
sudo wg-peer-tool repair-peer-zips
```

### Utility
```bash
# Show version
wg-peer-tool version

# Get help for any command
wg-peer-tool <command> --help
```

## Security Features

### Database Encryption
Enable encryption during initialization to protect sensitive data:
- Private keys
- Public keys  
- IP addresses
- ZIP passwords

```bash
wg-peer-tool init
# Choose 'y' when prompted for encryption
# Enter a strong master password
```

### Client Package Security
Each peer gets a password-protected ZIP containing:
- **`peer.conf`**: WireGuard client configuration
- **`peer.png`**: QR code for mobile apps
- **`peer.key`**: Private key file
- **`peer.pub`**: Public key file

ZIP passwords are automatically generated and stored encrypted in the database.

## File Structure

```
/etc/wireguard/
├── wg0.conf                    # Server configuration
└── clients/                   # Client configurations
    ├── alice/
    │   ├── alice.conf
    │   ├── alice.png
    │   ├── alice.key
    │   ├── alice.pub
    │   └── alice.zip          # Password-protected package
    └── bob/
        ├── bob.conf
        ├── bob.png
        ├── bob.key
        ├── bob.pub
        └── bob.zip
```

## Advanced Usage

### Custom Configuration Paths
```bash
# Use custom client directory during init
wg-peer-tool init
# Enter custom path when prompted for "Client config output path"
# Default: /etc/wireguard/clients

# Update client directory later
sudo wg-peer-tool update-config --client-root /custom/path
```

### Automation-Friendly Commands
Most read-only commands don't require sudo and can be used in scripts:
```bash
# Get peer count
wg-peer-tool list-peers | grep -c "^[^-]"

# Check if peer exists
wg-peer-tool show-peer alice >/dev/null 2>&1 && echo "Peer exists"

# Export for backup
wg-peer-tool export-peers --format json --output "backup-$(date +%Y%m%d).json"
```

### Repair and Maintenance
```bash
# Fix damaged or incomplete peer packages
sudo wg-peer-tool repair-peer-zips

# Regenerate WireGuard config from database
sudo wg-peer-tool regenerate-wg-conf
```

## Configuration Examples

### Basic Server Config (`/etc/wireguard/wg0.conf`)
```ini
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
# alice
PublicKey = ALICE_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32

[Peer]
# bob
PublicKey = BOB_PUBLIC_KEY
AllowedIPs = 10.0.0.3/32
```

### Client Config (automatically generated)
```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = your-server.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

## Troubleshooting

### Permission Issues
```bash
# Ensure WireGuard tools are accessible
sudo wg show

# Check config file permissions
sudo ls -la /etc/wireguard/

# Run with sudo for write operations
sudo wg-peer-tool add-peer alice
```

### Database Issues
```bash
# Check database location
ls -la wg_manager.db

# Reset database (WARNING: destroys all data)
rm wg_manager.db
wg-peer-tool init
```

### WireGuard Service Issues
```bash
# Check service status
sudo systemctl status wg-quick@wg0

# Restart manually
sudo wg-quick down wg0
sudo wg-quick up wg0

# Or use the tool
sudo wg-peer-tool restart-wireguard
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

### Development Setup
```bash
git clone https://github.com/dacoburn/wireguard-peer-tool.git
cd wireguard-peer-tool
pip install -e ".[dev]"
pre-commit install
```

### Running Tests
```bash
pytest
pytest --cov=wireguard_manager tests/
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Links

- **PyPI**: https://pypi.org/project/wireguard-peer-tool/
- **Documentation**: https://github.com/dacoburn/wireguard-peer-tool#readme
- **Bug Reports**: https://github.com/dacoburn/wireguard-peer-tool/issues
- **Source Code**: https://github.com/dacoburn/wireguard-peer-tool

## Acknowledgments

- [WireGuard](https://www.wireguard.com/) for the amazing VPN protocol
- The Python community for excellent tooling and libraries
- Contributors and users who help improve this project

---

**Important**: Always backup your WireGuard configuration before using this tool in production environments.