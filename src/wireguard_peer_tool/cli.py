#!/usr/bin/env python3
"""
WireGuard Manager CLI
A modern, secure Python-based command-line tool for managing WireGuard VPN servers.
"""

import argparse
import base64
import csv
import getpass
import ipaddress
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from wireguard_peer_tool._version import __version__
from wireguard_peer_tool.core import Helper, db

# Constants
DEFAULT_DNS = "1.1.1.1"
DEFAULT_CLIENT_DIR = "./clients"

# Global variables for caching master password
_master_password_cache: Optional[str] = None
_salt_cache: Optional[bytes] = None


def get_master_password_and_salt() -> Tuple[Optional[str], Optional[bytes]]:
    """Get master password and salt, caching for session"""
    global _master_password_cache, _salt_cache

    # Return cached values if available
    if _master_password_cache is not None and _salt_cache is not None:
        return _master_password_cache, _salt_cache

    config = db.get_server_config()
    if not config or not config.get("data_encrypted"):
        return None, None

    # Get salt from database
    encoded_salt = config.get("encryption_salt")
    if not encoded_salt:
        sys.exit(1)

    try:
        salt = base64.b64decode(encoded_salt)
    except Exception:
        sys.exit(1)

    # Prompt for master password
    master_password = getpass.getpass("Enter master password: ")

    # Cache the values
    _master_password_cache = master_password
    _salt_cache = salt

    return master_password, salt


def needs_elevated_permissions(command: str) -> bool:
    """Check if a command needs elevated permissions"""
    elevated_commands = {
        "add-peer", "remove-peer", "restart-wireguard",
        "regenerate-wg-conf", "import-peers", "repair-peer-zips"
    }
    return command in elevated_commands


def suggest_sudo_usage():
    """Suggest using sudo for elevated commands"""


def encrypt_peer_data(
    peer_data: Dict[str, Any],
    master_password: str,
    salt: bytes
) -> Dict[str, Any]:
    """Encrypt sensitive peer data fields"""
    encrypted_data: Dict[str, Any] = {}
    # Only encrypt specific fields:
    # - private_key (encrypted)
    # - ip_address (encrypted)
    # - allowed_ips (encrypted)
    # - zip_password (encrypted)
    #
    # public_key should NOT be encrypted
    encrypted_fields = ["private_key", "ip_address", "allowed_ips", "zip_password"]

    for key, value in peer_data.items():
        if key in encrypted_fields and value:
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

    # Only decrypt fields that should be encrypted:
    # - private_key (encrypted)
    # - ip_address (encrypted)
    # - allowed_ips (encrypted)
    # - zip_password (encrypted)
    #
    # public_key should NOT be encrypted (leave as-is)
    encrypted_fields = ["private_key", "ip_address", "allowed_ips", "zip_password"]

    for key in encrypted_fields:
        if peer.get(key):
            val = peer[key]
            try:
                decrypted = Helper.decrypt_database_field(val, master_password)
                peer[key] = decrypted.strip() if isinstance(decrypted, str) else decrypted
            except Exception:
                # If decryption fails for this field, just keep the original value
                # This allows the tool to continue working even with some corrupted data
                pass

    # Also strip any unencrypted string fields to remove unwanted newlines
    for key, value in peer.items():
        if isinstance(value, str):
            peer[key] = value.strip()

    return peer


def get_server_private_key() -> str:
    """Get decrypted server private key"""
    config = db.get_server_config()
    if not config:
        sys.exit(1)

    private_key = config.get("private_key")
    is_encrypted = config.get("data_encrypted")

    if is_encrypted:
        master_password, _ = get_master_password_and_salt()
        if master_password:
            if private_key is not None:
                private_key = Helper.decrypt_database_field(private_key, master_password)
            else:
                sys.exit(1)

    if private_key is None:
        sys.exit(1)
    return private_key


def decrypt_server_config(config_row: dict) -> dict:
    """Decrypt server config if encryption is enabled. Always returns a dict."""
    if not config_row:
        return {}
    if not isinstance(config_row, dict):
        msg = f"Server config must be a dict. Got: {type(config_row)}"
        raise TypeError(msg)

    is_encrypted = config_row.get("data_encrypted")
    if not is_encrypted:
        return config_row

    master_password, _ = get_master_password_and_salt()
    if not master_password:
        return config_row

    config = config_row.copy()
    # Only decrypt the private_key - public keys are never encrypted
    for key in ["private_key"]:
        if config.get(key):
            try:
                config[key] = Helper.decrypt_database_field(config[key], master_password)
            except (ValueError, KeyError, json.JSONDecodeError):
                sys.exit(1)
    return config


def auto_regenerate_wg_config():
    """Auto-regenerate WireGuard config after peer changes"""
    config = db.get_server_config()
    if not config:
        return

    config_path = config.get("config_path")
    if config_path and os.path.exists(config_path):
        generate_wg_conf_content(config_path)


def generate_wg_conf_content(output_path: Optional[str] = None) -> None:
    """Generate WireGuard configuration file content from database"""
    config = db.get_server_config()
    if not config:
        sys.exit(1)

    # Decrypt config if needed
    config = decrypt_server_config(config)

    if output_path is None:
        output_path = config.get("config_path")
    if not output_path:
        sys.exit(1)

    # Build WireGuard config content
    content = f"""[Interface]
PrivateKey = {config['private_key']}
Address = {config['address']}
ListenPort = {config.get('listen_port', 51820)}
"""

    # Add PostUp and PostDown if they exist
    if config.get("post_up"):
        content += f"PostUp = {config['post_up']}\n"
    if config.get("post_down"):
        content += f"PostDown = {config['post_down']}\n"

    # Add peers
    peers = db.get_all_peers()
    master_password, _ = get_master_password_and_salt()

    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        content += f"""
# {peer['name']}
[Peer]
PublicKey = {peer['public_key']}
AllowedIPs = {peer['ip_address']}/32
"""

    # Write to file
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception:
        sys.exit(1)


def get_next_ip() -> str:
    """Get next available IP address for a new peer"""
    config = db.get_server_config()
    if not config:
        sys.exit(1)
    if not isinstance(config, dict):
        msg = f"db.get_server_config() must return dict or None, got {type(config)}"
        raise TypeError(msg)

    # Decrypt config if needed
    config = decrypt_server_config(config)
    server_address = config.get("address")
    if not server_address:
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

    sys.exit(1)


def generate_keypair() -> Tuple[str, str]:
    """Generate WireGuard private and public key pair"""
    # Generate private key
    private_key_result = subprocess.run(
        ["wg", "genkey"], capture_output=True, text=True, check=False
    )
    if private_key_result.returncode != 0:
        sys.exit(1)

    private_key = private_key_result.stdout.strip()

    # Generate public key
    public_key_result = subprocess.run(
        ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=False
    )
    if public_key_result.returncode != 0:
        sys.exit(1)

    public_key = public_key_result.stdout.strip()

    return private_key, public_key


def init(args: argparse.Namespace) -> None:
    """Initialize WireGuard manager from existing config file"""
    config_path = input("Enter path to existing WireGuard config file: ").strip()

    if not os.path.exists(config_path):
        sys.exit(1)

    # Read and parse config
    try:
        with open(config_path, encoding="utf-8") as f:
            content = f.read()
    except Exception:
        sys.exit(1)

    # Parse config using Helper
    try:
        parsed_config = Helper.parse_wireguard_config(content)
    except Exception:
        sys.exit(1)

    # Get server section
    server_section = parsed_config.get("Interface", {})
    if not server_section:
        sys.exit(1)

    # Extract server config
    private_key = server_section.get("PrivateKey")
    address = server_section.get("Address")
    listen_port = server_section.get("ListenPort", "51820")

    if not private_key or not address:
        sys.exit(1)

    # Generate public key from private key
    try:
        public_key_result = subprocess.run(
            ["wg", "pubkey"], input=private_key, capture_output=True, text=True, check=False
        )
        if public_key_result.returncode != 0:
            sys.exit(1)
        public_key = public_key_result.stdout.strip()
    except Exception:
        sys.exit(1)

    # Ask for encryption
    use_encryption = input("Enable database encryption? (y/N): ").strip().lower() == "y"
    master_password = None
    salt = None

    if use_encryption:
        password1 = getpass.getpass("Enter master password: ")
        password2 = getpass.getpass("Confirm master password: ")
        if password1 != password2:
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
        # Only encrypt private_key - public keys are never encrypted
        for key in ["private_key"]:
            if server_config.get(key):
                server_config[key] = Helper.encrypt_database_field(
                    server_config[key], master_password, salt
                )

    # Save to database
    try:
        db.save_server_config(server_config)
    except Exception:
        sys.exit(1)

    # Import existing peers
    peers_section = parsed_config.get("Peer", [])
    if peers_section:
        for i, peer_config in enumerate(peers_section):
            peer_name = peer_config.get("name", f"peer_{i+1}")
            public_key = peer_config.get("PublicKey")
            allowed_ips = peer_config.get("AllowedIPs")

            if public_key and allowed_ips:
                # Extract IP (remove /32 suffix)
                ip_address = allowed_ips.split("/")[0]

                # Generate private key for this peer (we don't have it from config)
                private_key, _ = generate_keypair()

                # Generate ZIP password
                zip_password = Helper.generate_zip_password()

                peer_data = {
                    "name": peer_name,
                    "public_key": public_key,
                    "private_key": private_key,  # Note: This is newly generated
                    "ip_address": ip_address,
                    "allowed_ips": allowed_ips,  # Use the original allowed_ips from config
                    "zip_password": zip_password
                }

                # Encrypt peer data if encryption is enabled
                if use_encryption and master_password and salt:
                    peer_data = encrypt_peer_data(peer_data, master_password, salt)

                try:
                    db.add_peer(peer_data)
                except Exception:
                    pass



def add_peer(args: argparse.Namespace) -> None:
    """Add a new peer"""
    peer_name = args.name

    # Check if peer already exists
    existing_peer = db.get_peer_by_name(peer_name)
    if existing_peer:
        sys.exit(1)

    # Get server config
    config = db.get_server_config()
    if not config:
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
        "allowed_ips": f"{ip_address}/32",  # Add allowed_ips field
        "zip_password": zip_password
    }

    # Encrypt if needed
    master_password, salt = get_master_password_and_salt()
    if master_password and salt:
        peer_data = encrypt_peer_data(peer_data, master_password, salt)

    # Add to database
    try:
        db.add_peer(peer_data)
    except Exception:
        sys.exit(1)

    # Generate client config
    try:
        Helper.generate_client_config(peer_name, db)
    except Exception:
        sys.exit(1)

    # Auto-regenerate WireGuard config
    auto_regenerate_wg_config()


def remove_peer(args: argparse.Namespace) -> None:
    """Remove a peer"""
    peer_name = args.name

    # Check if peer exists
    peer_row = db.get_peer_by_name(peer_name)
    if not peer_row:
        sys.exit(1)

    # Remove from database
    try:
        db.remove_peer(peer_name)
    except Exception:
        sys.exit(1)

    # Remove client files
    config = db.get_server_config()
    if config:
        client_root = config.get("client_config_root", DEFAULT_CLIENT_DIR)
        client_dir = Path(client_root) / peer_name
        if client_dir.exists():
            try:
                shutil.rmtree(client_dir)
            except Exception:
                pass

    # Auto-regenerate WireGuard config
    auto_regenerate_wg_config()


def list_peers(_args: argparse.Namespace) -> None:
    """List all peers"""
    peers = db.get_all_peers()
    if not peers:
        return

    master_password, _ = get_master_password_and_salt()


    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)

        # Get the actual ZIP path
        config = db.get_server_config()
        if config:
            config = decrypt_server_config(config)
            client_root = config.get("client_config_root", "./clients")
            zip_path = Path(client_root) / peer["name"] / f"{peer['name']}.zip"
            str(zip_path).strip() if zip_path.exists() else f"{str(zip_path).strip()} (missing)"
        else:
            pass



def show_peer(args: argparse.Namespace) -> None:
    """Show detailed peer information"""
    peer_name = args.name

    peer_row = db.get_peer_by_name(peer_name)
    if not peer_row:
        sys.exit(1)

    master_password, _ = get_master_password_and_salt()
    decrypt_peer_data(peer_row, master_password)


    # Show ZIP file path
    config = db.get_server_config()
    if config:
        config = decrypt_server_config(config)
        client_root = config.get("client_config_root", "./clients")
        zip_path = Path(client_root) / peer_name / f"{peer_name}.zip"
        if zip_path.exists():
            pass
        else:
            pass
    else:
        pass


def regenerate_wg_conf(args: argparse.Namespace) -> None:
    """Regenerate WireGuard configuration from database"""
    output_path = args.output
    generate_wg_conf_content(output_path)


def update_config(args: argparse.Namespace) -> None:
    """Update server configuration"""
    config = db.get_server_config()
    if not config:
        sys.exit(1)

    updates = {}
    if args.dns:
        updates["dns_server"] = args.dns
    if args.client_root:
        updates["client_config_root"] = args.client_root
    if args.listen_port:
        updates["listen_port"] = args.listen_port

    if not updates:
        return

    try:
        for key, value in updates.items():
            db.update_server_config(key, value)
        for key, value in updates.items():
            pass
    except Exception:
        sys.exit(1)


def restart_wireguard(_args: argparse.Namespace) -> None:
    """Restart WireGuard interface"""
    config = db.get_server_config()
    if not config:
        sys.exit(1)

    config_path = config.get("config_path")
    if not config_path:
        sys.exit(1)

    # Extract interface name from config path
    interface_name = Path(config_path).stem


    # Stop interface
    try:
        subprocess.run(["wg-quick", "down", interface_name], check=True)
    except subprocess.CalledProcessError:
        pass

    # Start interface
    try:
        subprocess.run(["wg-quick", "up", config_path], check=True)
    except subprocess.CalledProcessError:
        sys.exit(1)


def export_peers(args: argparse.Namespace) -> None:
    """Export peers to CSV or JSON"""
    peers = db.get_all_peers()
    if not peers:
        return

    master_password, _ = get_master_password_and_salt()
    peer_data = []

    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        peer_data.append(peer)

    try:
        if args.format == "csv":
            with open(args.output, "w", newline="", encoding="utf-8") as f:
                if peer_data:
                    writer = csv.DictWriter(f, fieldnames=peer_data[0].keys())
                    writer.writeheader()
                    writer.writerows(peer_data)
        elif args.format == "json":
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(peer_data, f, indent=2)

    except Exception:
        sys.exit(1)


def import_peers(args: argparse.Namespace) -> None:
    """Import peers from a file"""
    file_path = args.file

    if not os.path.exists(file_path):
        sys.exit(1)

    try:
        if file_path.endswith(".json"):
            with open(file_path, encoding="utf-8") as f:
                peer_data = json.load(f)
        elif file_path.endswith(".csv"):
            with open(file_path, encoding="utf-8") as f:
                reader = csv.DictReader(f)
                peer_data = list(reader)
        else:
            sys.exit(1)
    except Exception:
        sys.exit(1)

    master_password, salt = get_master_password_and_salt()
    imported_count = 0

    for peer in peer_data:
        try:
            # Check if peer already exists
            if db.get_peer_by_name(peer["name"]):
                continue

            # Encrypt if needed
            if master_password and salt:
                peer = encrypt_peer_data(peer, master_password, salt)

            db.add_peer(peer)
            imported_count += 1
        except Exception:
            pass


    # Auto-regenerate WireGuard config
    if imported_count > 0:
        auto_regenerate_wg_config()


def peer_zip_info(_args: argparse.Namespace) -> None:
    """View ZIP information for all peers"""
    peers = db.get_all_peers()
    if not peers:
        return

    master_password, _ = get_master_password_and_salt()

    # Get server config for ZIP path calculation
    config = db.get_server_config()
    client_root = "./clients"  # default
    if config:
        config = decrypt_server_config(config)
        client_root = config.get("client_config_root", "./clients")


    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        zip_path = Path(client_root) / peer["name"] / f"{peer['name']}.zip"
        str(zip_path).strip() if zip_path.exists() else f"{str(zip_path).strip()} (missing)"


def debug_peer_data(args: argparse.Namespace) -> None:
    """Debug peer data encryption issues"""
    peer_name = args.name

    peer_row = db.get_peer_by_name(peer_name)
    if not peer_row:
        sys.exit(1)

    peer = dict(peer_row) if not isinstance(peer_row, dict) else peer_row.copy()


    # Check if database is encrypted
    config = db.get_server_config()
    config.get("data_encrypted") if config else False

    # Show raw field values
    for key in ["public_key", "private_key", "ip_address", "zip_password"]:
        if peer.get(key):
            val = peer[key]

            if isinstance(val, str):
                if val.startswith("{"):
                    try:
                        import json
                        parsed = json.loads(val)
                        if isinstance(parsed, dict):
                            if "data" in parsed:
                                parsed["data"]
                    except json.JSONDecodeError:
                        pass


def repair_database_encryption(args: argparse.Namespace) -> None:
    """Repair database encryption issues by encrypting unencrypted fields"""

    # Check database write permissions first
    try:
        db_instance = db.get_db_instance()
        # Try a simple write operation to test permissions
        with db_instance.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM peers")
            # Try to create a temporary table to test write access
            cursor.execute("CREATE TEMPORARY TABLE test_write (id INTEGER)")
            cursor.execute("DROP TABLE test_write")
    except Exception:
        sys.exit(1)

    # Get master password
    master_password, salt = get_master_password_and_salt()
    if not master_password or not salt:
        sys.exit(1)


    # Get all peers and check/fix encryption
    db_instance = db.get_db_instance()
    with db_instance.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM peers")  # Get all fields including private_key
        peers = cursor.fetchall()

    repaired_count = 0

    # Fields that should be encrypted:
    # - private_key (encrypted)
    # - ip_address (encrypted)
    # - allowed_ips (encrypted)
    # - zip_password (encrypted)
    #
    # Fields that should NOT be encrypted:
    # - name, public_key, created_at, dns, endpoint
    encrypted_fields = ["private_key", "ip_address", "allowed_ips", "zip_password"]
    unencrypted_fields = ["name", "public_key", "created_at", "dns", "endpoint"]

    for peer_row in peers:
        peer = dict(peer_row) if not isinstance(peer_row, dict) else peer_row.copy()
        peer_name = peer.get("name", "unknown")
        needs_repair = False


        # Check fields that should NOT be encrypted
        for field_name in unencrypted_fields:
            if peer.get(field_name):
                field_value = peer[field_name]
                if isinstance(field_value, str) and field_value.strip().startswith("{"):
                    needs_repair = True

                    # Decrypt and store as plain text
                    try:
                        decrypted_value = Helper.decrypt_database_field(field_value, master_password)

                        # Check if decryption actually worked
                        # For a successful decryption, the result should:
                        # 1. Be different from the original encrypted value
                        # 2. Not start with '{' (not JSON)
                        # 3. Have reasonable length for the field type
                        decryption_worked = (
                            decrypted_value != field_value and
                            not decrypted_value.startswith("{") and
                            len(decrypted_value) > 0
                        )

                        if not decryption_worked:
                            # Decryption failed, handle special case for public_key
                            if field_name == "public_key":

                                # Get the decrypted private key to regenerate public key
                                private_key_encrypted = peer.get("private_key", "")
                                if private_key_encrypted:
                                    try:
                                        private_key_plain = Helper.decrypt_database_field(private_key_encrypted, master_password)
                                        # Check if we got a valid WireGuard private key (44 chars, base64-like)
                                        if (private_key_plain and
                                            len(private_key_plain) == 44 and
                                            private_key_plain != private_key_encrypted and
                                            not private_key_plain.startswith("{")):
                                            # Successfully decrypted private key, regenerate public key
                                            import subprocess
                                            result = subprocess.run([
                                                "wg", "pubkey"
                                            ], input=private_key_plain, capture_output=True, text=True, check=False)

                                            if result.returncode == 0:
                                                regenerated_public_key = result.stdout.strip()

                                                # Update database with regenerated public key
                                                with db_instance.get_connection() as conn:
                                                    cursor = conn.cursor()
                                                    cursor.execute(f"UPDATE peers SET {field_name} = ? WHERE name = ?",
                                                                 (regenerated_public_key, peer_name))
                                                    conn.commit()

                                            else:
                                                pass
                                        else:
                                            pass
                                    except Exception:
                                        pass
                                else:
                                    pass
                            else:
                                pass
                        else:
                            # Decryption worked, update the database with the decrypted value
                            with db_instance.get_connection() as conn:
                                cursor = conn.cursor()
                                cursor.execute(f"UPDATE peers SET {field_name} = ? WHERE name = ?",
                                             (decrypted_value, peer_name))
                                conn.commit()


                    except Exception:
                        pass

                else:
                    pass

        # Check each field that should be encrypted
        for field_name in encrypted_fields:
            if peer.get(field_name):
                field_value = peer[field_name]

                # Check if this field is unencrypted (doesn't start with JSON format)
                if (isinstance(field_value, str) and
                    not field_value.strip().startswith("{")):

                    needs_repair = True

                    # Encrypt the field
                    try:
                        encrypted_value = Helper.encrypt_database_field(field_value, master_password, salt)

                        # Update the database
                        with db_instance.get_connection() as conn:
                            cursor = conn.cursor()
                            cursor.execute(f"UPDATE peers SET {field_name} = ? WHERE name = ?",
                                         (encrypted_value, peer_name))
                            conn.commit()


                    except Exception:
                        pass

                elif field_value.strip().startswith("{"):
                    # Try to verify it's properly encrypted and can be decrypted
                    try:
                        decrypted = Helper.decrypt_database_field(field_value, master_password)
                        # Check if decryption actually worked
                        if (decrypted != field_value and
                            not decrypted.startswith("{") and
                            len(decrypted) > 0):
                            pass
                        # Try to fix this encrypted field that can't be decrypted
                        elif field_name == "private_key":
                            try:
                                # Generate new keypair
                                new_private_key, new_public_key = generate_keypair()

                                # Encrypt the new private key
                                encrypted_private_key = Helper.encrypt_database_field(new_private_key, master_password, salt)

                                # Update database with new private key
                                with db_instance.get_connection() as conn:
                                    cursor = conn.cursor()
                                    cursor.execute("UPDATE peers SET private_key = ? WHERE name = ?",
                                                 (encrypted_private_key, peer_name))
                                    # Also update public key to match
                                    cursor.execute("UPDATE peers SET public_key = ? WHERE name = ?",
                                                 (new_public_key, peer_name))
                                    conn.commit()

                                needs_repair = True
                            except Exception:
                                pass
                        else:
                            pass
                    except Exception:
                        pass
                else:
                    pass

        if needs_repair:
            repaired_count += 1


    if repaired_count > 0:
        pass


def repair_peer_zips(_args: argparse.Namespace) -> None:
    """Regenerate all peer ZIPs to ensure they contain conf, QR, pub, and key files"""
    peers = db.get_all_peers()
    if not peers:
        return

    master_password, _ = get_master_password_and_salt()
    repaired_count = 0

    for peer_row in peers:
        peer = decrypt_peer_data(peer_row, master_password)
        peer_name = peer["name"]

        try:
            Helper.generate_client_config(peer_name, db)
            repaired_count += 1
        except Exception:
            pass



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
        with open(config_path, "a", encoding="utf-8"):
            pass
        return True, ""
    except PermissionError:
        return False, f"Cannot write to config file: {config_path}. Root/sudo access required."
    except Exception as e:
        return False, f"Error accessing config file: {e}"


def version_command(_args: argparse.Namespace) -> None:
    """Display version information"""


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
        "--version", action="version",
        version=f"WireGuard Peer Tool {__version__}"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Version command
    version_parser = subparsers.add_parser("version", help="Show version information")
    version_parser.set_defaults(func=version_command)

    # Init
    init_parser = subparsers.add_parser("init", help="Initialize WireGuard manager with existing config")
    init_parser.set_defaults(func=init)

    # Add peer
    add_parser = subparsers.add_parser("add-peer", help="Add a new peer")
    add_parser.add_argument("name", help="Peer name")
    add_parser.set_defaults(func=add_peer)

    # Import peers
    import_parser = subparsers.add_parser("import-peers", help="Import peers from a file")
    import_parser.add_argument("file", help="Path to the file containing peer information")
    import_parser.set_defaults(func=import_peers)

    # View peer zip info
    view_parser = subparsers.add_parser("peer-zip-info", help="View ZIP information for a peer")
    view_parser.set_defaults(func=peer_zip_info)

    # Repair peer zips
    repair_parser = subparsers.add_parser(
        "repair-peer-zips",
        help="Regenerate all peer ZIPs to ensure they contain conf, QR, pub, and key files"
    )
    repair_parser.set_defaults(func=repair_peer_zips)

    # Remove peer
    remove_parser = subparsers.add_parser("remove-peer", help="Remove a peer")
    remove_parser.add_argument("name", help="Peer name")
    remove_parser.set_defaults(func=remove_peer)

    # List peers
    list_parser = subparsers.add_parser("list-peers", help="List all peers")
    list_parser.set_defaults(func=list_peers)

    # Show peer details
    show_parser = subparsers.add_parser(
        "show-peer", help="Show detailed peer information including ZIP password"
    )
    show_parser.add_argument("name", help="Peer name")
    show_parser.set_defaults(func=show_peer)

    # Regenerate config
    regen_parser = subparsers.add_parser(
        "regenerate-wg-conf", help="Regenerate WireGuard config from database"
    )
    regen_parser.add_argument("--output", "-o", help="Output path (default: original config path)")
    regen_parser.set_defaults(func=regenerate_wg_conf)

    # Update config
    update_parser = subparsers.add_parser("update-config", help="Update server configuration")
    update_parser.add_argument("--dns", help="Update DNS server")
    update_parser.add_argument("--client-root", help="Update client config root directory")
    update_parser.add_argument("--listen-port", type=int, help="Update listen port")
    update_parser.set_defaults(func=update_config)

    # Restart WireGuard
    restart_parser = subparsers.add_parser("restart-wireguard", help="Restart WireGuard interface")
    restart_parser.set_defaults(func=restart_wireguard)

    # Export peers
    export_parser = subparsers.add_parser("export-peers", help="Export peers to CSV or JSON")
    export_parser.add_argument(
        "--format", choices=["csv", "json"], default="csv", help="Export format"
    )
    export_parser.add_argument("--output", "-o", required=True, help="Output file path")
    export_parser.set_defaults(func=export_peers)

    # Debug commands
    debug_parser = subparsers.add_parser("debug-peer", help="Debug peer data encryption issues")
    debug_parser.add_argument("name", help="Peer name")
    debug_parser.set_defaults(func=debug_peer_data)

    repair_encryption_parser = subparsers.add_parser(
        "repair-encryption", help="Repair database encryption issues"
    )
    repair_encryption_parser.set_defaults(func=repair_database_encryption)

    # Parse arguments
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Check permissions for commands that need them
    if needs_elevated_permissions(args.command):
        wg_ok, wg_error = check_wireguard_permissions()
        if not wg_ok:
            suggest_sudo_usage()
            sys.exit(1)

        if args.command in ["regenerate-wg-conf", "update-config", "add-peer", "import-peers", "repair-peer-zips"]:
            config_ok, config_error = check_config_file_access()
            if not config_ok:
                suggest_sudo_usage()
                sys.exit(1)

    # Preload master password if encryption is enabled
    if args.command != "version":
        config = db.get_server_config()
        if config and config.get("data_encrypted"):
            get_master_password_and_salt()

    # Execute the command
    args.func(args)


if __name__ == "__main__":
    main()
