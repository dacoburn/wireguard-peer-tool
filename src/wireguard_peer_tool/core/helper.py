"""
Helper module for creating QR codes and ZIP archives
"""

import base64
import ipaddress
import json
import os
import secrets
import tempfile
from pathlib import Path
from typing import Any

import pyzipper
import qrcode
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image


class ClientConfig:
    """Data class to hold client configuration information"""

    def __init__(
        self,
        private_key: str,
        client_ip: str,
        dns: str,
        server_public_key: str,
        server_endpoint: str,
    ):
        self.private_key = private_key
        self.client_ip = client_ip
        self.dns = dns
        self.server_public_key = server_public_key
        self.server_endpoint = server_endpoint


class Helper:
    """Helper class for various utility functions"""

    @staticmethod
    def extract_zip_with_optional_password(
        zip_file: str,
        password: str | None = None,
        required_files: list[str] | None = None
    ) -> tuple[bool, bool, bool, str, str | None]:
        """
        Try to extract a zip file with no password, then with password if provided.
        Returns (extracted_without_password, extracted_with_password, found_all,
                 temp_dir, error_message)
        """
        temp_dir = tempfile.mkdtemp()
        extracted_with_password = False
        extracted_without_password = False
        error_message = None
        try:
            with pyzipper.AESZipFile(zip_file, "r") as zf:
                try:
                    zf.extractall(temp_dir)
                    extracted_without_password = True
                except RuntimeError:
                    if password:
                        try:
                            zf.pwd = password.encode()
                            zf.extractall(temp_dir)
                            extracted_with_password = True
                        except Exception as e:
                            error_message = (
                                f"Failed to extract {zip_file} with password: {e}"
                            )
                    else:
                        error_message = (
                            f"Failed to extract {zip_file}: no password and "
                            "no default extraction worked."
                        )
        except (OSError, pyzipper.BadZipFile, pyzipper.LargeZipFile) as e:
            error_message = f"Failed to open {zip_file}: {e}"

        found_all = False
        if required_files:
            found_all = all(
                os.path.exists(os.path.join(temp_dir, fname))
                for fname in required_files
            )
        return (
            extracted_without_password,
            extracted_with_password,
            found_all,
            temp_dir,
            error_message,
        )

    @staticmethod
    def create_password_protected_zip(
        zip_path: str, files: list[tuple[str, str]], password: str
    ) -> None:
        """
        Create a password-protected zip at zip_path with the given files
        (list of (src, arcname)).
        """
        with pyzipper.AESZipFile(
            zip_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(password.encode())
            for src, arcname in files:
                zf.write(src, arcname=arcname)

    @staticmethod
    def create_qr_code(peer_dir: Path, peer_name: str, client_config: str) -> Path:
        """Create QR code image from client config"""
        temp_qr_path = peer_dir / f"{peer_name}.png"
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(client_config)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        # Ensure img is a PIL Image (for qrcode >=7.3 use get_image())
        try:
            if not isinstance(img, Image.Image):
                img = img.get_image()
        except ImportError:
            pass
        with open(temp_qr_path, "wb") as f:
            img.save(f)
        return temp_qr_path

    @staticmethod
    def create_config(peer_dir: Path, peer_name: str, client_config: str) -> Path:
        """Create WireGuard client config string"""
        temp_config_path = peer_dir / f"{peer_name}.conf"
        with open(temp_config_path, "w", encoding="utf-8") as f:
            f.write(client_config)
        return temp_config_path

    @staticmethod
    def create_zip_with_config_and_qr(
        peer_dir: Path, peer_name: str, client_config: str, zip_password: str
    ) -> Path:
        """
        Create ZIP file containing config, QR code, public key, and private key,
        using AES encryption.
        """
        # Create temporary files for ZIP
        temp_config_path = Helper.create_config(peer_dir, peer_name, client_config)
        temp_qr_path = Helper.create_qr_code(peer_dir, peer_name, client_config)

        # Paths for key files
        private_key_path = peer_dir / f"{peer_name}.key"
        public_key_path = peer_dir / f"{peer_name}.pub"

        # If config file exists, try to extract private key and create
        # .key/.pub files if missing
        if temp_config_path.exists():
            # Read config and extract PrivateKey
            private_key = None
            with open(temp_config_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip().startswith("PrivateKey ="):
                        private_key = line.strip().split("=", 1)[1].strip()
                        break
            if private_key:
                # Write private key file if missing
                if not private_key_path.exists():
                    with open(private_key_path, "w", encoding="utf-8") as pkf:
                        pkf.write(private_key)
                # Generate public key file if missing
                if not public_key_path.exists():
                    try:
                        import subprocess

                        result = subprocess.run(
                            ["wg", "pubkey"],
                            input=private_key,
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if result.returncode == 0:
                            public_key = result.stdout.strip()
                            with open(public_key_path, "w", encoding="utf-8") as pubf:
                                pubf.write(public_key)
                    except Exception:
                        pass

        # Create AES-encrypted ZIP archive using pyzipper
        zip_path = peer_dir / f"{peer_name}.zip"
        with pyzipper.AESZipFile(
            zip_path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as zf:
            zf.setpassword(zip_password.encode())
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            zf.write(temp_config_path, f"{peer_name}.conf")
            zf.write(temp_qr_path, f"{peer_name}.png")
            # Add private key if exists
            if private_key_path.exists():
                zf.write(private_key_path, f"{peer_name}.key")
            # Add public key if exists
            if public_key_path.exists():
                zf.write(public_key_path, f"{peer_name}.pub")

        # Remove temporary files
        temp_config_path.unlink()
        temp_qr_path.unlink()

        return zip_path

    @staticmethod
    def create_client_config(
        private_key: str,
        client_ip: str,
        dns: str,
        server_public_key: str,
        server_endpoint: str,
        allowed_ip: str,
    ) -> str:
        """Create WireGuard client configuration string"""
        return f"""[Interface]
PrivateKey = {private_key}
Address = {client_ip}/32
DNS = {dns}

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = {allowed_ip}
"""

    @staticmethod
    def load_config_from_file(config_path: Path) -> dict:
        """Load WireGuard client configuration from file"""
        file = open(config_path, encoding="utf-8")
        lines = file.readlines()
        file.close()
        config = Helper.parse_wireguard_config("\n".join(lines))
        return config

    @staticmethod
    def parse_wireguard_config(config_text: str) -> dict[str, Any]:
        """Parse WireGuard configuration text into a structured dictionary"""
        result: dict[str, Any] = {"server_config": {}, "peers": {}}
        lines = config_text.strip().splitlines()
        current_peer: dict[str, Any] | None = None
        peer_name = None
        last_comment = None
        in_peer_section = False
        in_interface_section = False

        for line in lines:
            line = line.strip()

            if not line:
                continue  # Skip blank lines

            if line.startswith("#"):
                last_comment = line.lstrip("#").strip()
                continue

            if line == "[Interface]":
                in_peer_section = False
                in_interface_section = True
                continue

            if line == "[Peer]":
                # Save previous peer
                if current_peer is not None and peer_name is not None and current_peer:
                    result["peers"][peer_name] = current_peer
                current_peer = {}
                peer_name = last_comment or "unnamed"
                in_peer_section = True
                in_interface_section = False
                continue

            if "=" in line:
                key, value = map(str.strip, line.split("=", 1))

                if in_interface_section:
                    result["server_config"][key] = value
                elif in_peer_section and current_peer is not None:
                    if key == "AllowedIPs":
                        current_peer[key] = [ip.strip() for ip in value.split(",")]
                    else:
                        current_peer[key] = value

        # Append the final peer after the loop
        if (
            in_peer_section
            and current_peer is not None
            and peer_name is not None
            and current_peer
        ):
            result["peers"][peer_name] = current_peer
        return result

    @staticmethod
    def get_next_ip(ip_list: list[str]) -> str:
        """Get the next available IP address from a list of IPs"""
        if not ip_list:
            msg = "IP list is empty"
            raise ValueError(msg)

        last_ip = ipaddress.ip_address(sorted(ip_list, key=ipaddress.ip_address)[-1])
        if last_ip.packed[-1] == 254:
            msg = f"Cannot increment IP {last_ip}; it ends with .254"
            raise ValueError(msg)
        next_ip = last_ip + 1
        return str(next_ip)

    @staticmethod
    def get_contents(file_path: Path) -> str:
        """Read the contents of a file"""
        if not file_path.exists():
            msg = f"File {file_path} does not exist"
            raise FileNotFoundError(msg)
        with open(file_path, encoding="utf-8") as f:
            return f.read()

    @staticmethod
    def is_zip_encrypted(
        master_password: str, zip_password: str | dict[str, Any]
    ) -> tuple[bool, bool]:
        """Check if a ZIP password is encrypted and valid.
        Returns a tuple (is_encrypted, is_valid)."""
        if master_password:
            if isinstance(zip_password, dict):
                # Check if it's a properly formatted encrypted dict
                if "salt" in zip_password and "data" in zip_password:
                    return (True, True)  # encrypted and valid
                else:
                    return (True, False)  # encrypted but invalid format
            elif isinstance(zip_password, str):
                # Check if it's a JSON string representing encrypted data
                if (
                    zip_password.strip().startswith("{")
                    and "data" in zip_password
                    and "salt" in zip_password
                ):
                    return (True, True)  # encrypted JSON string and valid
                else:
                    return (False, True)  # not encrypted but valid (plain text)
            else:
                return (False, False)  # not encrypted and invalid (empty/None)
        else:
            # No master password, so encryption is not expected
            return (False, True)  # not encrypted but valid

    @staticmethod
    def handle_zip_password(
        peer_data: dict[str, Any],
        raw_peer_data: dict[str, Any],
        master_password: str,
        config: dict[str, Any],
        peer_name: str,
        db_update_callback: Any,
        generate_zip_password_func: Any,
        encrypt_database_field_func: Any,
        decrypt_database_field_func: Any,
        update_allowed: bool = True,
    ) -> str:
        """
        Handle zip password validation, encryption, and database updates.
        Returns the final zip password (decrypted for display/use).

        Args:
            peer_data: Decrypted peer data dict
            raw_peer_data: Raw peer data dict (before decryption)
            master_password: Master password if encryption is enabled
            config: Server config dict
            peer_name: Name of the peer
            db_update_callback: Function to call for database updates
                               (peer_name, new_password)
            generate_zip_password_func: Function to generate new zip passwords
            encrypt_database_field_func: Function to encrypt database fields
            decrypt_database_field_func: Function to decrypt database fields
            update_allowed: Whether database updates are allowed
                           (False for read-only operations)

        Returns:
            str: The zip password (decrypted/plain text for use)
        """
        zip_password = peer_data.get("zip_password", "")
        raw_zip_password = raw_peer_data.get("zip_password", "")

        # Check if password is valid and encrypted
        password_is_encrypted, password_is_valid = Helper.is_zip_encrypted(
            master_password, raw_zip_password
        )

        # Handle completely missing passwords - ONLY CASE WHERE WE GENERATE NEW PASSWORD
        if not raw_zip_password:
            if update_allowed:
                zip_password = generate_zip_password_func()
                if master_password:
                    # Encrypt the new password before saving
                    salt = config.get("encryption_salt", "")
                    if salt:
                        encrypted_password = encrypt_database_field_func(
                            zip_password, master_password, base64.b64decode(salt)
                        )
                        db_update_callback(peer_name, encrypted_password)
                    else:
                        db_update_callback(peer_name, zip_password)
                else:
                    db_update_callback(peer_name, zip_password)
                return zip_password
            else:
                return "[No Password]"  # Read-only mode

        # Handle invalid passwords (malformed encrypted data)
        elif not password_is_valid:
            if update_allowed:
                # Generate new password to replace invalid one
                zip_password = generate_zip_password_func()
                if master_password:
                    salt = config.get("encryption_salt", "")
                    if salt:
                        encrypted_password = encrypt_database_field_func(
                            zip_password, master_password, base64.b64decode(salt)
                        )
                        db_update_callback(peer_name, encrypted_password)
                    else:
                        db_update_callback(peer_name, zip_password)
                else:
                    db_update_callback(peer_name, zip_password)
                return zip_password
            else:
                return "[Invalid Password]"  # Read-only mode

        # Handle valid encrypted passwords - DECRYPT FOR DISPLAY
        elif password_is_encrypted and password_is_valid and master_password:
            try:
                if isinstance(raw_zip_password, str):
                    return decrypt_database_field_func(
                        raw_zip_password, master_password
                    )
                elif isinstance(raw_zip_password, dict):
                    return decrypt_database_field_func(
                        json.dumps(raw_zip_password), master_password
                    )
                else:
                    return "[Decryption Error]"
            except Exception:
                return "[Decryption Error]"

        # Handle valid but unencrypted passwords when master password is set
        # ONLY ENCRYPT IF update_allowed and actually unencrypted in the database
        elif (
            password_is_valid
            and not password_is_encrypted
            and master_password
            and update_allowed
        ):
            # Encrypt the existing password and save it (one-time migration)
            salt = config.get("encryption_salt", "")
            if salt:
                encrypted_password = encrypt_database_field_func(
                    zip_password,  # This is the plain text password
                    master_password,
                    base64.b64decode(salt),
                )
                db_update_callback(peer_name, encrypted_password)
            # Return the plain text password for display
            return zip_password

        # Return as-is for other cases (no master password, already valid)
        return zip_password if zip_password else "[No Password]"

    @staticmethod
    def ensure_zip_password_encryption(
        zip_password,
        master_password,
        config,
        peer_name,
        db_update_callback,
        encrypt_database_field_func,
        decrypt_database_field_func,
    ):
        """
        Ensure zip password is properly encrypted if master password is set.
        Used by repair_peer_zips for its specific encryption flow.

        Returns:
            str: The zip password (decrypted for use)
        """
        if not master_password or not zip_password:
            return zip_password

        # If encryption is enabled and zip_password is a plain string,
        # encrypt and update DB
        if isinstance(zip_password, str):
            zp = zip_password.strip()
            if not (zp.startswith("{") and "data" in zp and "salt" in zp):
                # It's a plain text password that needs encryption
                salt_b64 = config.get("encryption_salt")
                if salt_b64:
                    salt = base64.b64decode(salt_b64)
                    encrypted_pw = encrypt_database_field_func(
                        zip_password, master_password, salt
                    )
                    db_update_callback(peer_name, encrypted_pw)
                return zip_password
            else:
                # It's already encrypted JSON string, decrypt it
                try:
                    return decrypt_database_field_func(zip_password, master_password)
                except Exception:
                    return zip_password
        elif (
            isinstance(zip_password, dict)
            and "data" in zip_password
            and "salt" in zip_password
        ):
            # It's an encrypted dict, decrypt it
            try:
                return decrypt_database_field_func(
                    json.dumps(zip_password), master_password
                )
            except Exception:
                return zip_password

        return zip_password

    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive a key from password and salt using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_data(data: str, password: str, salt: bytes | None = None) -> dict:
        """Encrypt data using Fernet with password-derived key"""
        if salt is None:
            salt = secrets.token_bytes(32)

        key = Helper.derive_key(password, salt)
        fernet = Fernet(base64.urlsafe_b64encode(key))
        encrypted_data = fernet.encrypt(data.encode())

        return {
            "data": base64.b64encode(encrypted_data).decode(),
            "salt": base64.b64encode(salt).decode(),
        }

    @staticmethod
    def decrypt_data(enc_data: dict, password: str) -> str:
        """Decrypt data using Fernet with password-derived key"""
        try:
            salt = base64.b64decode(enc_data["salt"])
            key = Helper.derive_key(password, salt)
            fernet = Fernet(base64.urlsafe_b64encode(key))

            # Handle various base64 issues
            encrypted_data_str = enc_data["data"]
            encrypted_data = None

            # Try different base64 decoding methods
            # 1. Try treating as raw Fernet token first
            #    (this works for private_key, public_key, zip_password)
            try:
                fernet_token = encrypted_data_str.encode()
                decrypted = fernet.decrypt(fernet_token)
                return decrypted.decode().strip()
            except Exception:
                pass

            # 2. Try base64 decode then treat as raw Fernet token
            #    (this works for ip_address)
            try:
                decoded_once = base64.b64decode(encrypted_data_str)
                # The decoded result should be a Fernet token string, use it as bytes
                fernet_token = decoded_once.decode().encode()
                decrypted = fernet.decrypt(fernet_token)
                return decrypted.decode().strip()
            except Exception:
                pass

            # 3. Try standard base64 decode
            try:
                encrypted_data = base64.b64decode(encrypted_data_str)
            except Exception:
                # 4. Try URL-safe base64 (for data that was incorrectly encoded)
                try:
                    encrypted_data = base64.urlsafe_b64decode(encrypted_data_str)
                except Exception:
                    # 5. Try adding padding to standard base64
                    missing_padding = len(encrypted_data_str) % 4
                    if missing_padding:
                        padded_str = encrypted_data_str + "=" * (4 - missing_padding)
                        try:
                            encrypted_data = base64.b64decode(padded_str)
                        except Exception:
                            # 6. Try adding padding to URL-safe base64
                            try:
                                encrypted_data = base64.urlsafe_b64decode(padded_str)
                            except Exception:
                                # 7. Last resort: try removing padding and re-adding
                                clean_str = encrypted_data_str.rstrip("=")
                                missing_padding = len(clean_str) % 4
                                if missing_padding:
                                    clean_str += "=" * (4 - missing_padding)
                                    try:
                                        encrypted_data = base64.b64decode(clean_str)
                                    except Exception:
                                        encrypted_data = base64.urlsafe_b64decode(
                                            clean_str
                                        )
                                else:
                                    raise
                    else:
                        raise

            if encrypted_data is None:
                msg = "Could not decode base64 data with any method"
                raise ValueError(msg)

            decrypted_result = fernet.decrypt(encrypted_data).decode()
            # Strip any trailing whitespace/newlines from decrypted data
            return decrypted_result.strip()
        except Exception as e:
            # Don't raise immediately - let the calling function handle it
            msg = f"Decryption failed: {e}"
            raise ValueError(msg) from e

    @staticmethod
    def generate_zip_password(length: int = 16) -> str:
        """Generate a random password for ZIP files"""
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def encrypt_database_field(data: str, master_password: str, salt: bytes) -> str:
        """Encrypt a database field using the master password"""
        encrypted_data = Helper.encrypt_data(data, master_password, salt)
        return json.dumps(encrypted_data)

    @staticmethod
    def decrypt_database_field(enc_json: str, master_password: str) -> str:
        """Decrypt a database field using the master password"""
        if not isinstance(enc_json, str):
            return str(enc_json)

        enc_json_stripped = enc_json.strip()

        # If it doesn't look like JSON, return as-is (unencrypted data)
        if not enc_json_stripped.startswith("{"):
            return enc_json

        # Try to parse as JSON and decrypt if it's an encrypted object
        try:
            enc_data = json.loads(enc_json_stripped)
            if isinstance(enc_data, dict) and "data" in enc_data and "salt" in enc_data:
                # This is encrypted data, try to decrypt it
                try:
                    decrypted = Helper.decrypt_data(enc_data, master_password)
                    # Strip any trailing whitespace/newlines from decrypted data
                    return (
                        decrypted.strip() if isinstance(decrypted, str) else decrypted
                    )
                except Exception:
                    # If decryption fails, it might be corrupted but we should
                    # try to continue
                    # Return the original data so the tool can still function
                    return enc_json
            else:
                # It's JSON but not encrypted format, return as-is
                return enc_json
        except json.JSONDecodeError:
            # If JSON parsing fails, assume it's unencrypted data
            return enc_json
        except Exception:
            # For any other error, return original data
            return enc_json

    @staticmethod
    def generate_salt() -> bytes:
        """Generate a random salt for encryption"""
        return secrets.token_bytes(32)

    @staticmethod
    def generate_client_config(peer_name: str, db_module: Any) -> Path:
        """Generate client configuration files and ZIP package"""
        # Get peer data from database
        peer_row = db_module.get_peer_by_name(peer_name)
        if not peer_row:
            msg = f"Peer '{peer_name}' not found"
            raise ValueError(msg)

        # Get server config
        server_config = db_module.get_server_config()
        if not server_config:
            msg = "Server not initialized"
            raise ValueError(msg)

        # Decrypt server config if encrypted
        from wireguard_peer_tool import cli  # Import here to avoid circular import

        server_config = cli.decrypt_server_config(server_config)

        # Decrypt peer data if encrypted
        master_password, _ = cli.get_master_password_and_salt()
        peer = cli.decrypt_peer_data(peer_row, master_password)

        # Create client directory
        client_root = server_config.get("client_config_root", "./clients")
        peer_dir = Path(client_root) / peer_name
        peer_dir.mkdir(parents=True, exist_ok=True)

        # Create client config content
        endpoint = server_config.get("endpoint", "your-server.com")
        listen_port = server_config.get("listen_port", 51820)
        client_config_content = f"""[Interface]
PrivateKey = {peer['private_key']}
Address = {peer['ip_address']}/32
DNS = {server_config.get('dns_server', '1.1.1.1')}

[Peer]
PublicKey = {server_config['public_key']}
AllowedIPs = 0.0.0.0/0
Endpoint = {endpoint}:{listen_port}
"""

        # Write config file
        config_file = peer_dir / f"{peer_name}.conf"
        config_file.write_text(client_config_content, encoding="utf-8")

        # Create QR code
        qr_file = peer_dir / f"{peer_name}.png"
        Helper.create_qr_code(peer_dir, peer_name, client_config_content)

        # Write key files
        public_key_file = peer_dir / f"{peer_name}.pub"
        public_key_file.write_text(peer["public_key"], encoding="utf-8")

        private_key_file = peer_dir / f"{peer_name}.key"
        private_key_file.write_text(peer["private_key"], encoding="utf-8")

        # Create ZIP file
        zip_file = peer_dir / f"{peer_name}.zip"
        files_to_zip = [
            (str(config_file), f"{peer_name}.conf"),
            (str(qr_file), f"{peer_name}.png"),
            (str(public_key_file), f"{peer_name}.pub"),
            (str(private_key_file), f"{peer_name}.key"),
        ]
        Helper.create_password_protected_zip(
            str(zip_file), files_to_zip, peer["zip_password"]
        )

        return zip_file

    @staticmethod
    def check_peer_zip_exists(peer_name: str, db_module) -> bool:
        """Check if a peer's ZIP file exists"""
        try:
            server_config = db_module.get_server_config()
            if not server_config:
                return False

            client_root = server_config.get("client_config_root", "./clients")
            zip_file = Path(client_root) / peer_name / f"{peer_name}.zip"
            return zip_file.exists()
        except Exception:
            return False
