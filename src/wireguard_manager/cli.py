#!/usr/bin/env python3
"""
WireGuard Manager CLI
A modern, secure Python-based command-line tool for managing WireGuard VPN servers.
"""

import os
import sys
import argparse
import getpass
import subprocess
from pathlib import Path
import base64
import json
import ipaddress
import csv
import shutil
from typing import Union, Optional, Dict, Any, Tuple, List

from wireguard_manager._version import __version__
from wireguard_manager.db import DB, ServerConfig, PeerData
from wireguard_manager.helper import Helper


DB_PATH = "wg_manager.db"
DEFAULT_DNS = "1.1.1.1"
DEFAULT_CLIENT_DIR = "/etc/wireguard/clients"
db: DB = DB(DB_PATH)

MASTER_PASSWORD: Optional[str] = None
MASTER_SALT: Optional[bytes] = None


def get_master_password_and_salt() -> Tuple[Optional[str], Optional[bytes]]:
    """Get master password and salt from user or database, caching for session"""
    global MASTER_PASSWORD, MASTER_SALT
    if MASTER_PASSWORD is not None and MASTER_SALT is not None:
        return MASTER_PASSWORD, MASTER_SALT
    config = db.get_server_config()
    if not config:
        return None, None
    is_encrypted = config.get("data_encrypted")
    if not is_encrypted:
        return None, None
    salt_b64 = config.get("encryption_salt")
    salt = base64.b64decode(salt_b64) if salt_b64 else None
    password = getpass.getpass("Enter master password: ")
    MASTER_PASSWORD = password
    MASTER_SALT = salt
    return MASTER_PASSWORD, MASTER_SALT


def encrypt_peer_data(
    peer_data: Dict[str, Any],
    master_password: str,
    salt: bytes
) -> Dict[str, Any]:
    """Encrypt all sensitive peer data"""
    encrypted_data: Dict[str, Any] = {}
    for key, value in peer_data.items():
        if key in ['public_key', 'private_key', 'ip_address', 'zip_password']:
            encrypted_data[key] = Helper.encrypt_database_field(
                str(value), master_password, salt
            )
        else:
            encrypted_data[key] = value
    return encrypted_data


def decrypt_peer_data(peer_row: dict, master_password: Union[str, None] = None) -> dict:
    """Decrypt peer data from database row (expects dict)"""
    if master_password is None:
        return dict(peer_row) if not isinstance(peer_row, dict) else peer_row

    # Convert sqlite3.Row to dict if needed
    peer = dict(peer_row) if not isinstance(peer_row, dict) else peer_row.copy()
    # Decrypt sensitive fields: public_key, private_key, ip_address, zip_password
    for key in ["public_key", "private_key", "ip_address", "zip_password"]:
        if key in peer and peer[key]:
            val = peer[key]
            decrypted = Helper.decrypt_database_field(val, master_password)
            peer[key] = decrypted
    return peer


def get_server_private_key() -> str:
    """Get decrypted server private key"""
    config = db.get_server_config()
    if not config:
        print("Server not initialized. Run 'init' first.")
        sys.exit(1)

    private_key = config.get("private_key")
    is_encrypted = config.get("data_encrypted")

    if is_encrypted:
        master_password, _ = get_master_password_and_salt()
        if master_password:
            private_key = Helper.decrypt_database_field(private_key, master_password)

    if private_key is None:
        print("Error: Private key is missing or None.")
        sys.exit(1)
    return private_key


def decrypt_server_config(config_row: dict) -> dict:
    """Decrypt server config if encryption is enabled. Always returns a dict."""
    if not config_row:
        return {}
    if not isinstance(config_row, dict):
        raise TypeError(f"Server config must be a dict. Got: {type(config_row)}")

    is_encrypted = config_row.get("data_encrypted")
    if not is_encrypted:
        return config_row

    master_password, _ = get_master_password_and_salt()
    if not master_password:
        return config_row

    config = config_row.copy()
    for key in ["private_key", "public_key"]:
        if key in config and config[key]:
            try:
                config[key] = Helper.decrypt_database_field(config[key], master_password)
            except (ValueError, KeyError, json.JSONDecodeError):
                print("Error: Invalid master password or corrupted data")
                sys.exit(1)
    return config


def auto_regenerate_wg_config():
    """Auto-regenerate WireGuard config after peer changes"""
    config = db.get_server_config()
    if not config:
        return
    
    config_path = config.get("config_path")
    if config_path and os.path.exists(config_path):
        print(f"Auto-regenerating WireGuard config: {config_path}")
        generate_wg_conf_content(config_path)


def generate_wg_conf_content(output_path: Optional[str] = None) -> None:
    """Generate WireGuard configuration file content from database"""
    config = db.get_server_config()
    if not config:
        print("Server not initialized. Run 'init' first.")
        sys.exit(1)

    # Decrypt config if needed
    config = decrypt_server_config(config)

    if output_path is None:
        output_path = config.get("config_path")
    if not output_path:
        print("Error: No output path specified and no config path in database")
        sys.exit(1)

    # Build WireGuard config content
    content = f"""[Interface]
PrivateKey = {config['private_key']}
Address = {config['address']}
ListenPort = {config.get('listen_port', 51820)}
"""

    # Add PostUp and PostDown if they exist
    if config.get('post_up'):
        content += f"PostUp = {config['post_up']}\n"
    if config.get('post_down'):
        content += f"PostDown = {config['post_down']}\n"

    # Add peers
    peers = db.get_all_peers()
    master_password, _ = get_master_password_and_salt()
    
    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        content += f"""
[Peer]
# {peer['name']}
PublicKey = {peer['public_key']}
AllowedIPs = {peer['ip_address']}/32
"""

    # Write to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"WireGuard configuration written to: {output_path}")
    except Exception as e:
        print(f"Error writing configuration file: {e}")
        sys.exit(1)


def init(args: argparse.Namespace) -> None:
    """Initialize WireGuard manager from existing config file"""
    config_path = input("Enter path to existing WireGuard config file: ").strip()
    
    if not os.path.exists(config_path):
        print(f"Error: Config file '{config_path}' does not exist")
        sys.exit(1)

    # Read and parse config
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)

    # Parse config using Helper
    try:
        parsed_config = Helper.parse_wireguard_config(content)
    except Exception as e:
        print(f"Error parsing WireGuard config: {e}")
        sys.exit(1)

    # Get server section
    server_section = parsed_config.get("Interface", {})
    if not server_section:
        print("Error: No [Interface] section found in config")
        sys.exit(1)

    # Extract server config
    private_key = server_section.get("PrivateKey")
    address = server_section.get("Address")
    listen_port = server_section.get("ListenPort", "51820")

    if not private_key or not address:
        print("Error: Missing PrivateKey or Address in [Interface] section")
        sys.exit(1)

    # Generate public key from private key
    try:
        public_key_result = subprocess.run(
            ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=False
        )
        if public_key_result.returncode != 0:
            print("Error generating public key from private key")
            sys.exit(1)
        public_key = public_key_result.stdout.strip()
    except Exception as e:
        print(f"Error generating public key: {e}")
        sys.exit(1)

    # Ask for encryption
    use_encryption = input("Enable database encryption? (y/N): ").strip().lower() == 'y'
    master_password = None
    salt = None

    if use_encryption:
        password1 = getpass.getpass("Enter master password: ")
        password2 = getpass.getpass("Confirm master password: ")
        if password1 != password2:
            print("Error: Passwords don't match")
            sys.exit(1)
        master_password = password1
        salt = Helper.generate_salt()

    # Prepare server config
    server_config = {
        "private_key": private_key,
        "public_key": public_key,
        "address": address,
        "listen_port": int(listen_port),
        "config_path": config_path,
        "dns_server": dns_server,
        "client_config_root": client_root,
        "post_up": server_section.get("PostUp"),
        "post_down": server_section.get("PostDown"),
        "data_encrypted": use_encryption,
        "encryption_salt": base64.b64encode(salt).decode() if salt else None
    }

    # Encrypt sensitive fields if encryption is enabled
    if use_encryption and master_password and salt:
        for key in ["private_key", "public_key"]:
            if key in server_config and server_config[key]:
                server_config[key] = Helper.encrypt_database_field(
                    server_config[key], master_password, salt
                )

    # Save to database
    try:
        db.save_server_config(server_config)
        print("Server configuration initialized successfully")
    except Exception as e:
        print(f"Error saving server config: {e}")
        sys.exit(1)

    # Import existing peers
    peers_section = parsed_config.get("Peer", [])
    if peers_section:
        print(f"Found {len(peers_section)} existing peers. Importing...")
        for i, peer_config in enumerate(peers_section):
            peer_name = peer_config.get("name", f"peer_{i+1}")
            public_key = peer_config.get("PublicKey")
            allowed_ips = peer_config.get("AllowedIPs")
            
            if public_key and allowed_ips:
                # Extract IP (remove /32 suffix)
                ip_address = allowed_ips.split('/')[0]
                
                # Generate private key for this peer (we don't have it from config)
                private_key, _ = generate_keypair()
                
                # Generate ZIP password
                zip_password = Helper.generate_zip_password()
                
                peer_data = {
                    "name": peer_name,
                    "public_key": public_key,
                    "private_key": private_key,  # Note: This is newly generated
                    "ip_address": ip_address,
                    "zip_password": zip_password
                }

                # Encrypt peer data if encryption is enabled
                if use_encryption and master_password and salt:
                    peer_data = encrypt_peer_data(peer_data, master_password, salt)

                try:
                    db.add_peer(peer_data)
                    print(f"Imported peer: {peer_name} ({ip_address})")
                except Exception as e:
                    print(f"Error importing peer {peer_name}: {e}")

    print("Initialization complete!")


def get_next_ip() -> str:
    """Get next available IP address for a new peer"""
    config = db.get_server_config()
    if not config:
        print("Server not initialized. Run 'init' first.")
        sys.exit(1)
    if not isinstance(config, dict):
        raise TypeError(f"db.get_server_config() must return dict or None, got {type(config)}")

    # Decrypt config if needed
    config = decrypt_server_config(config)
    server_address = config.get("address")
    if not server_address:
        print("Error: 'address' is missing in the server configuration.")
        sys.exit(1)
    network = ipaddress.ip_network(server_address, strict=False)

    peer_rows = db.get_ips()
    # Decrypt peer IPs if needed
    master_password, _ = get_master_password_and_salt()
    used_ips: List[str] = []
    
    for peer_row in peer_rows:
        peer = decrypt_peer_data(peer_row, master_password)
        used_ips.append(peer["ip_address"])

    for ip in network.hosts():
        if str(ip) not in used_ips and str(ip) != str(network.network_address + 1):
            return str(ip)

    print("Error: No available IP addresses in the subnet")
    sys.exit(1)


def generate_keypair() -> Tuple[str, str]:
    """Generate WireGuard private and public key pair"""
    # Generate private key
    private_key_result = subprocess.run(
        ["wg", "genkey"], capture_output=True, text=True, check=False
    )
    if private_key_result.returncode != 0:
        print("Error generating private key")
        sys.exit(1)

    private_key = private_key_result.stdout.strip()

    # Generate public key
    public_key_result = subprocess.run(
        ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=False
    )
    if public_key_result.returncode != 0:
        print("Error generating public key")
        sys.exit(1)

    public_key = public_key_result.stdout.strip()

    return private_key, public_key


def decrypt_server_config(config_row: dict) -> dict:
    """Decrypt server config if encryption is enabled. Always returns a dict."""
    if not config_row:
        return {}
    if not isinstance(config_row, dict):
        raise TypeError(f"Server config must be a dict. Got: {type(config_row)}")

    is_encrypted = config_row.get("data_encrypted")
    if not is_encrypted:
        return config_row

    master_password, _ = get_master_password_and_salt()
    if not master_password:
        return config_row

    config = config_row.copy()
    for key in ["private_key", "public_key"]:
        if key in config and config[key]:
            try:
                config[key] = Helper.decrypt_database_field(config[key], master_password)
            except (ValueError, KeyError, json.JSONDecodeError):
                print("Error: Invalid master password or corrupted data")
                sys.exit(1)
    return config


def auto_regenerate_wg_config():
    """Auto-regenerate WireGuard config after peer changes"""
    config = db.get_server_config()
    if not config:
        return
    
    config_path = config.get("config_path")
    if config_path and os.path.exists(config_path):
        print(f"Auto-regenerating WireGuard config: {config_path}")
        generate_wg_conf_content(config_path)


def generate_wg_conf_content(output_path: Optional[str] = None) -> None:
    """Generate WireGuard configuration file content from database"""
    config = db.get_server_config()
    if not config:
        print("Server not initialized. Run 'init' first.")
        sys.exit(1)

    # Decrypt config if needed
    config = decrypt_server_config(config)

    if output_path is None:
        output_path = config.get("config_path")
    if not output_path:
        print("Error: No output path specified and no config path in database")
        sys.exit(1)

    # Build WireGuard config content
    content = f"""[Interface]
PrivateKey = {config['private_key']}
Address = {config['address']}
ListenPort = {config.get('listen_port', 51820)}
"""

    # Add PostUp and PostDown if they exist
    if config.get('post_up'):
        content += f"PostUp = {config['post_up']}\n"
    if config.get('post_down'):
        content += f"PostDown = {config['post_down']}\n"

    # Add peers
    peers = db.get_all_peers()
    master_password, _ = get_master_password_and_salt()
    
    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        content += f"""
[Peer]
# {peer['name']}
PublicKey = {peer['public_key']}
AllowedIPs = {peer['ip_address']}/32
"""

    # Write to file
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"WireGuard configuration written to: {output_path}")
    except Exception as e:
        print(f"Error writing configuration file: {e}")
        sys.exit(1)


def init(args: argparse.Namespace) -> None:
    """Initialize WireGuard manager from existing config file"""
    config_path = input("Enter path to existing WireGuard config file: ").strip()
    
    if not os.path.exists(config_path):
        print(f"Error: Config file '{config_path}' does not exist")
        sys.exit(1)

    # Read and parse config
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading config file: {e}")
        sys.exit(1)

    # Parse config using Helper
    try:
        parsed_config = Helper.parse_wireguard_config(content)
    except Exception as e:
        print(f"Error parsing WireGuard config: {e}")
        sys.exit(1)

    # Get server section
    server_section = parsed_config.get("Interface", {})
    if not server_section:
        print("Error: No [Interface] section found in config")
        sys.exit(1)

    # Extract server config
    private_key = server_section.get("PrivateKey")
    address = server_section.get("Address")
    listen_port = server_section.get("ListenPort", "51820")

    if not private_key or not address:
        print("Error: Missing PrivateKey or Address in [Interface] section")
        sys.exit(1)

    # Generate public key from private key
    try:
        public_key_result = subprocess.run(
            ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=False
        )
        if public_key_result.returncode != 0:
            print("Error generating public key from private key")
            sys.exit(1)
        public_key = public_key_result.stdout.strip()
    except Exception as e:
        print(f"Error generating public key: {e}")
        sys.exit(1)

    # Ask for encryption
    use_encryption = input("Enable database encryption? (y/N): ").strip().lower() == 'y'
    master_password = None
    salt = None

    if use_encryption:
        password1 = getpass.getpass("Enter master password: ")
        password2 = getpass.getpass("Confirm master password: ")
        if password1 != password2:
            print("Error: Passwords don't match")
            sys.exit(1)
        master_password = password1
        salt = Helper.generate_salt()

    # Get DNS server
    dns_server = input(f"DNS server for clients [{DEFAULT_DNS}]: ").strip() or DEFAULT_DNS
    
    # Get client directory
    client_root = input(f"Client config output directory [{DEFAULT_CLIENT_DIR}]: ").strip() or DEFAULT_CLIENT_DIR

    # Prepare server config
    server_config = {
        "private_key": private_key,
        "public_key": public_key,
        "address": address,
        "listen_port": int(listen_port),
        "config_path": config_path,
        "dns_server": dns_server,
        "client_config_root": client_root,
        "post_up": server_section.get("PostUp"),
        "post_down": server_section.get("PostDown"),
        "data_encrypted": use_encryption,
        "encryption_salt": base64.b64encode(salt).decode() if salt else None
    }

    # Encrypt sensitive fields if encryption is enabled
    if use_encryption and master_password and salt:
        for key in ["private_key", "public_key"]:
            if key in server_config and server_config[key]:
                server_config[key] = Helper.encrypt_database_field(
                    server_config[key], master_password, salt
                )

    # Save to database
    try:
        db.save_server_config(server_config)
        print("Server configuration initialized successfully")
    except Exception as e:
        print(f"Error saving server config: {e}")
        sys.exit(1)

    # Import existing peers
    peers_section = parsed_config.get("Peer", [])
    if peers_section:
        print(f"Found {len(peers_section)} existing peers. Importing...")
        for i, peer_config in enumerate(peers_section):
            peer_name = peer_config.get("name", f"peer_{i+1}")
            public_key = peer_config.get("PublicKey")
            allowed_ips = peer_config.get("AllowedIPs")
            
            if public_key and allowed_ips:
                # Extract IP (remove /32 suffix)
                ip_address = allowed_ips.split('/')[0]
                
                # Generate private key for this peer (we don't have it from config)
                private_key, _ = generate_keypair()
                
                # Generate ZIP password
                zip_password = Helper.generate_zip_password()
                
                peer_data = {
                    "name": peer_name,
                    "public_key": public_key,
                    "private_key": private_key,  # Note: This is newly generated
                    "ip_address": ip_address,
                    "zip_password": zip_password
                }

                # Encrypt peer data if encryption is enabled
                if use_encryption and master_password and salt:
                    peer_data = encrypt_peer_data(peer_data, master_password, salt)

                try:
                    db.add_peer(peer_data)
                    print(f"Imported peer: {peer_name} ({ip_address})")
                except Exception as e:
                    print(f"Error importing peer {peer_name}: {e}")

    print("Initialization complete!")


def add_peer(args: argparse.Namespace) -> None:
    """Add a new peer"""
    peer_name = args.name
    
    # Check if peer already exists
    existing_peer = db.get_peer_by_name(peer_name)
    if existing_peer:
        print(f"Error: Peer '{peer_name}' already exists")
        sys.exit(1)

    # Get server config
    config = db.get_server_config()
    if not config:
        print("Server not initialized. Run 'init' first.")
        sys.exit(1)

    # Generate keys
    private_key, public_key = generate_keypair()
    
    # Get next available IP
    ip_address = get_next_ip()
    
    # Generate ZIP password
    zip_password = Helper.generate_zip_password()

    # Prepare peer data
    peer_data = {
        "name": peer_name,
        "public_key": public_key,
        "private_key": private_key,
        "ip_address": ip_address,
        "zip_password": zip_password
    }

    # Encrypt if needed
    master_password, salt = get_master_password_and_salt()
    if master_password and salt:
        peer_data = encrypt_peer_data(peer_data, master_password, salt)

    # Add to database
    try:
        db.add_peer(peer_data)
        print(f"Peer '{peer_name}' added successfully")
        print(f"IP Address: {ip_address}")
        print(f"Public Key: {public_key}")
    except Exception as e:
        print(f"Error adding peer: {e}")
        sys.exit(1)

    # Generate client config
    try:
        Helper.generate_client_config(peer_name, db)
        print(f"Client configuration and ZIP package created for '{peer_name}'")
    except Exception as e:
        print(f"Error generating client config: {e}")
        sys.exit(1)

    # Auto-regenerate WireGuard config
    auto_regenerate_wg_config()


def remove_peer(args: argparse.Namespace) -> None:
    """Remove a peer"""
    peer_name = args.name
    
    # Check if peer exists
    peer_row = db.get_peer_by_name(peer_name)
    if not peer_row:
        print(f"Error: Peer '{peer_name}' not found")
        sys.exit(1)

    # Remove from database
    try:
        db.remove_peer(peer_name)
        print(f"Peer '{peer_name}' removed successfully")
    except Exception as e:
        print(f"Error removing peer: {e}")
        sys.exit(1)

    # Remove client files
    config = db.get_server_config()
    if config:
        client_root = config.get("client_config_root", DEFAULT_CLIENT_DIR)
        client_dir = Path(client_root) / peer_name
        if client_dir.exists():
            try:
                shutil.rmtree(client_dir)
                print(f"Client files removed: {client_dir}")
            except Exception as e:
                print(f"Warning: Could not remove client files: {e}")

    # Auto-regenerate WireGuard config
    auto_regenerate_wg_config()


def list_peers(_args: argparse.Namespace) -> None:
    """List all peers"""
    peers = db.get_all_peers()
    if not peers:
        print("No peers found")
        return

    master_password, _ = get_master_password_and_salt()
    
    print(f"{'Name':<20} {'IP Address':<15} {'Public Key':<44} {'ZIP'}")
    print("-" * 85)
    
    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        zip_status = "✓" if Helper.check_peer_zip_exists(peer["name"], db) else "✗"
        print(f"{peer['name']:<20} {peer['ip_address']:<15} {peer['public_key']:<44} {zip_status}")


def show_peer(args: argparse.Namespace) -> None:
    """Show detailed peer information"""
    peer_name = args.name
    
    peer_row = db.get_peer_by_name(peer_name)
    if not peer_row:
        print(f"Error: Peer '{peer_name}' not found")
        sys.exit(1)

    master_password, _ = get_master_password_and_salt()
    peer = decrypt_peer_data(peer_row, master_password)
    
    print(f"Peer Details: {peer_name}")
    print("-" * 40)
    print(f"Name: {peer['name']}")
    print(f"IP Address: {peer['ip_address']}")
    print(f"Public Key: {peer['public_key']}")
    print(f"Private Key: {peer['private_key']}")
    print(f"ZIP Password: {peer['zip_password']}")
    
    # Check ZIP file status
    if Helper.check_peer_zip_exists(peer_name, db):
        print("ZIP Status: ✓ Available")
    else:
        print("ZIP Status: ✗ Missing")


def regenerate_wg_conf(args: argparse.Namespace) -> None:
    """Regenerate WireGuard configuration from database"""
    output_path = args.output
    generate_wg_conf_content(output_path)


def update_config(args: argparse.Namespace) -> None:
    """Update server configuration"""
    config = db.get_server_config()
    if not config:
        print("Server not initialized. Run 'init' first.")
        sys.exit(1)

    updates = {}
    if args.dns:
        updates["dns_server"] = args.dns
    if args.client_root:
        updates["client_config_root"] = args.client_root
    if args.listen_port:
        updates["listen_port"] = args.listen_port

    if not updates:
        print("No updates specified")
        return

    try:
        for key, value in updates.items():
            db.update_server_config(key, value)
        print("Server configuration updated successfully")
        for key, value in updates.items():
            print(f"  {key}: {value}")
    except Exception as e:
        print(f"Error updating config: {e}")
        sys.exit(1)


def restart_wireguard(_args: argparse.Namespace) -> None:
    """Restart WireGuard interface"""
    config = db.get_server_config()
    if not config:
        print("Server not initialized. Run 'init' first.")
        sys.exit(1)

    config_path = config.get("config_path")
    if not config_path:
        print("Error: No config path found in database")
        sys.exit(1)

    # Extract interface name from config path
    interface_name = Path(config_path).stem
    
    print(f"Restarting WireGuard interface: {interface_name}")
    
    # Stop interface
    try:
        subprocess.run(["wg-quick", "down", interface_name], check=True)
        print(f"Interface {interface_name} stopped")
    except subprocess.CalledProcessError:
        print(f"Warning: Could not stop interface {interface_name} (may not be running)")

    # Start interface
    try:
        subprocess.run(["wg-quick", "up", config_path], check=True)
        print(f"Interface {interface_name} started")
    except subprocess.CalledProcessError as e:
        print(f"Error starting interface: {e}")
        sys.exit(1)


def export_peers(args: argparse.Namespace) -> None:
    """Export peers to CSV or JSON"""
    peers = db.get_all_peers()
    if not peers:
        print("No peers found")
        return

    master_password, _ = get_master_password_and_salt()
    peer_data = []
    
    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        peer_data.append(peer)

    try:
        if args.format == 'csv':
            with open(args.output, 'w', newline='', encoding='utf-8') as f:
                if peer_data:
                    writer = csv.DictWriter(f, fieldnames=peer_data[0].keys())
                    writer.writeheader()
                    writer.writerows(peer_data)
        elif args.format == 'json':
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(peer_data, f, indent=2)
        
        print(f"Peers exported to: {args.output}")
    except Exception as e:
        print(f"Error exporting peers: {e}")
        sys.exit(1)


def import_peers(args: argparse.Namespace) -> None:
    """Import peers from a file"""
    file_path = args.file
    
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found")
        sys.exit(1)

    try:
        if file_path.endswith('.json'):
            with open(file_path, 'r', encoding='utf-8') as f:
                peer_data = json.load(f)
        elif file_path.endswith('.csv'):
            with open(file_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                peer_data = list(reader)
        else:
            print("Error: Unsupported file format. Use .json or .csv")
            sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    master_password, salt = get_master_password_and_salt()
    imported_count = 0
    
    for peer in peer_data:
        try:
            # Check if peer already exists
            if db.get_peer_by_name(peer['name']):
                print(f"Skipping existing peer: {peer['name']}")
                continue

            # Encrypt if needed
            if master_password and salt:
                peer = encrypt_peer_data(peer, master_password, salt)

            db.add_peer(peer)
            imported_count += 1
            print(f"Imported peer: {peer['name']}")
        except Exception as e:
            print(f"Error importing peer {peer.get('name', 'unknown')}: {e}")

    print(f"Successfully imported {imported_count} peers")
    
    # Auto-regenerate WireGuard config
    if imported_count > 0:
        auto_regenerate_wg_config()


def peer_zip_info(_args: argparse.Namespace) -> None:
    """View ZIP information for all peers"""
    peers = db.get_all_peers()
    if not peers:
        print("No peers found")
        return

    master_password, _ = get_master_password_and_salt()
    
    print(f"{'Peer Name':<20} {'ZIP Password':<20} {'ZIP Status'}")
    print("-" * 65)
    
    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        zip_exists = Helper.check_peer_zip_exists(peer["name"], db)
        zip_status = "✓ Available" if zip_exists else "✗ Missing"
        print(f"{peer['name']:<20} {peer['zip_password']:<20} {zip_status}")


def repair_peer_zips(_args: argparse.Namespace) -> None:
    """Regenerate all peer ZIPs to ensure they contain conf, QR, pub, and key files"""
    peers = db.get_all_peers()
    if not peers:
        print("No peers found")
        return

    master_password, _ = get_master_password_and_salt()
    repaired_count = 0
    
    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        peer_name = peer["name"]
        
        try:
            Helper.generate_client_config(peer_name, db)
            repaired_count += 1
            print(f"Repaired ZIP package for peer: {peer_name}")
        except Exception as e:
            print(f"Error repairing ZIP for peer {peer_name}: {e}")

    print(f"Successfully repaired {repaired_count} peer ZIP packages")


def check_wireguard_permissions() -> Tuple[bool, str]:
    """Check if we have permissions to access WireGuard tools"""
    try:
        result = subprocess.run(
            ["wg", "show"], capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return True, ""
        else:
            return False, "Cannot access WireGuard interfaces. Root/sudo access required."
    except FileNotFoundError:
        return False, "WireGuard tools not found. Please install wireguard-tools."
    except Exception as e:
        return False, f"Error checking WireGuard permissions: {e}"


def check_config_file_access() -> Tuple[bool, str]:
    """Check if we can write to WireGuard config files"""
    config = db.get_server_config()
    if not config:
        return False, "Server not initialized"
    
    config_path = config.get("config_path")
    if not config_path:
        return False, "No config path found in database"
    
    try:
        # Try to open the file for writing (append mode to not truncate)
        with open(config_path, 'a', encoding='utf-8'):
            pass
        return True, ""
    except PermissionError:
        return False, f"Cannot write to config file: {config_path}. Root/sudo access required."
    except Exception as e:
        return False, f"Error accessing config file: {e}"


# === Version Command ===
def version_command(_args: argparse.Namespace) -> None:
    """Display version information"""
    print(f"WireGuard Peer Tool {__version__}")
    print("A modern, secure Python-based CLI tool for managing WireGuard VPN servers")


def main() -> None:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WireGuard Manager - A modern, secure Python-based CLI tool for managing WireGuard VPN servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} init                    Initialize with existing config
  {sys.argv[0]} list-peers              List all peers (no sudo needed)
  sudo {sys.argv[0]} add-peer alice     Add a new peer
  {sys.argv[0]} peer-zip-info           View ZIP passwords
  {sys.argv[0]} version                 Show version information

For more help: {sys.argv[0]} <command> --help
"""
    )
    
    # Add version argument
    parser.add_argument(
        '--version', action='version', 
        version=f'WireGuard Peer Tool {__version__}'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    version_parser.set_defaults(func=version_command)

    # Init
    init_parser = subparsers.add_parser('init', help='Initialize WireGuard manager with existing config')
    init_parser.set_defaults(func=init)

    # Add peer
    add_parser = subparsers.add_parser('add-peer', help='Add a new peer')
    add_parser.add_argument('name', help='Peer name')
    add_parser.set_defaults(func=add_peer)

    # Import peers
    import_parser = subparsers.add_parser('import-peers', help='Import peers from a file')
    import_parser.add_argument('file', help='Path to the file containing peer information')
    import_parser.set_defaults(func=import_peers)

    # View peer zip info
    view_parser = subparsers.add_parser('peer-zip-info', help='View ZIP information for a peer')
    view_parser.set_defaults(func=peer_zip_info)

    # Repair peer zips
    repair_parser = subparsers.add_parser(
        'repair-peer-zips',
        help='Regenerate all peer ZIPs to ensure they contain conf, QR, pub, and key files'
    )
    repair_parser.set_defaults(func=repair_peer_zips)

    # Remove peer
    remove_parser = subparsers.add_parser('remove-peer', help='Remove a peer')
    remove_parser.add_argument('name', help='Peer name')
    remove_parser.set_defaults(func=remove_peer)

    # List peers
    list_parser = subparsers.add_parser('list-peers', help='List all peers')
    list_parser.set_defaults(func=list_peers)

    # Show peer details
    show_parser = subparsers.add_parser(
        'show-peer', help='Show detailed peer information including ZIP password'
    )
    show_parser.add_argument('name', help='Peer name')
    show_parser.set_defaults(func=show_peer)

    # Regenerate config
    regen_parser = subparsers.add_parser(
        'regenerate-wg-conf', help='Regenerate WireGuard config from database'
    )
    regen_parser.add_argument('--output', '-o', help='Output path (default: original config path)')
    regen_parser.set_defaults(func=regenerate_wg_conf)

    # Update config
    update_parser = subparsers.add_parser('update-config', help='Update server configuration')
    update_parser.add_argument('--dns', help='Update DNS server')
    update_parser.add_argument('--client-root', help='Update client config root directory')
    update_parser.add_argument('--listen-port', type=int, help='Update listen port')
    update_parser.set_defaults(func=update_config)

    # Restart WireGuard
    restart_parser = subparsers.add_parser('restart-wireguard', help='Restart WireGuard interface')
    restart_parser.set_defaults(func=restart_wireguard)

    # Export peers
    export_parser = subparsers.add_parser('export-peers', help='Export peers to CSV or JSON')
    export_parser.add_argument(
        '--format', choices=['csv', 'json'], default='csv', help='Export format'
    )
    export_parser.add_argument('--output', '-o', required=True, help='Output file path')
    export_parser.set_defaults(func=export_peers)

    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Check permissions for commands that need them
    if needs_elevated_permissions(args.command):
        wg_ok, wg_error = check_wireguard_permissions()
        if not wg_ok:
            print(f"Error: {wg_error}")
            suggest_sudo_usage()
            sys.exit(1)
        
        if args.command in ['regenerate-wg-conf', 'update-config', 'add-peer', 'import-peers', 'repair-peer-zips']:
            config_ok, config_error = check_config_file_access()
            if not config_ok:
                print(f"Error: {config_error}")
                suggest_sudo_usage()
                sys.exit(1)

    # Preload master password if encryption is enabled
    if args.command != 'version':
        config = db.get_server_config()
        if config and config.get("data_encrypted"):
            get_master_password_and_salt()

    # Execute the command
    args.func(args)


if __name__ == "__main__":
    main()
