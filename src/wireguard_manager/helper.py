"""
Helper module for creating QR codes and ZIP archives
"""
from pathlib import Path
import ipaddress
import tempfile
import os
import base64
import json
import secrets
import string
from typing import Union, Dict, Optional
import pyzipper
import qrcode
from PIL import Image
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class ClientConfig:
    """Data class to hold client configuration information"""
    def __init__(self, private_key: str, client_ip: str, dns: str,
                 server_public_key: str, server_endpoint: str):
        self.private_key = private_key
        self.client_ip = client_ip
        self.dns = dns
        self.server_public_key = server_public_key
        self.server_endpoint = server_endpoint

class Helper:
    """Helper class for various utility functions"""
    @staticmethod
    def extract_zip_with_optional_password(zip_file, password=None, required_files=None):
        """
        Try to extract a zip file with no password, then with password if provided.
        Returns (extracted_without_password, extracted_with_password, found_all, temp_dir, error_message)
        """
        temp_dir = tempfile.mkdtemp()
        extracted_with_password = False
        extracted_without_password = False
        error_message = None
        try:
            with pyzipper.AESZipFile(zip_file, 'r') as zf:
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
                            error_message = f"Failed to extract {zip_file} with password: {e}"
                    else:
                        error_message = f"Failed to extract {zip_file}: no password and no default extraction worked."
        except (OSError, pyzipper.BadZipFile, pyzipper.LargeZipFile) as e:
            error_message = f"Failed to open {zip_file}: {e}"

        found_all = False
        if required_files:
            found_all = all(os.path.exists(os.path.join(temp_dir, fname)) for fname in required_files)
        return (extracted_without_password, extracted_with_password, found_all, temp_dir, error_message)

    @staticmethod
    def create_password_protected_zip(zip_path, files, password):
        """
        Create a password-protected zip at zip_path with the given files (list of (src, arcname)).
        """
        with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
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
        with open(temp_qr_path, 'wb') as f:
            img.save(f)
        return temp_qr_path

    @staticmethod
    def create_config(
        peer_dir: Path, peer_name: str, client_config: str
    ) -> Path:
        """Create WireGuard client config string"""
        temp_config_path = peer_dir / f"{peer_name}.conf"
        with open(temp_config_path, 'w', encoding='utf-8') as f:
            f.write(client_config)
        return temp_config_path

    @staticmethod
    def create_zip_with_config_and_qr(
        peer_dir: Path,
        peer_name: str,
        client_config: str,
        zip_password: str
    ) -> Path:
        """Create ZIP file containing config, QR code, public key, and private key, using AES encryption."""
        # Create temporary files for ZIP
        temp_config_path = Helper.create_config(peer_dir, peer_name, client_config)
        temp_qr_path = Helper.create_qr_code(peer_dir, peer_name, client_config)

        # Paths for key files
        private_key_path = peer_dir / f"{peer_name}.key"
        public_key_path = peer_dir / f"{peer_name}.pub"

        # If config file exists, try to extract private key and create .key/.pub files if missing
        if temp_config_path.exists():
            # Read config and extract PrivateKey
            private_key = None
            with open(temp_config_path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip().startswith("PrivateKey ="):
                        private_key = line.strip().split("=", 1)[1].strip()
                        break
            if private_key:
                # Write private key file if missing
                if not private_key_path.exists():
                    with open(private_key_path, 'w', encoding='utf-8') as pkf:
                        pkf.write(private_key)
                # Generate public key file if missing
                if not public_key_path.exists():
                    try:
                        import subprocess
                        result = subprocess.run([
                            "wg", "pubkey"
                        ], input=private_key, capture_output=True, text=True, check=False)
                        if result.returncode == 0:
                            public_key = result.stdout.strip()
                            with open(public_key_path, 'w', encoding='utf-8') as pubf:
                                pubf.write(public_key)
                    except Exception:
                        pass

        # Create AES-encrypted ZIP archive using pyzipper
        zip_path = peer_dir / f"{peer_name}.zip"
        with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
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
        allowed_ip: str
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
        file = open(config_path, 'r', encoding='utf-8')
        lines = file.readlines()
        file.close()
        config = Helper.parse_wireguard_config('\n'.join(lines))
        return config

    @staticmethod
    def parse_wireguard_config(config_text):
        """Parse WireGuard configuration text into a structured dictionary"""
        result = {
            "server_config": {},
            "peers": {}
        }
        lines = config_text.strip().splitlines()
        current_peer = None
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
        if in_peer_section and current_peer is not None and peer_name is not None and current_peer:
            result["peers"][peer_name] = current_peer
        return result


    @staticmethod
    def get_next_ip(ip_list):
        """Get the next available IP address from a list of IPs"""
        if not ip_list:
            raise ValueError("IP list is empty")

        last_ip = ipaddress.ip_address(sorted(ip_list, key=ipaddress.ip_address)[-1])
        if last_ip.packed[-1] == 254:
            raise ValueError(f"Cannot increment IP {last_ip}; it ends with .254")
        next_ip = last_ip + 1
        return str(next_ip)

    @staticmethod
    def get_contents(file_path: Path) -> str:
        """Read the contents of a file"""
        if not file_path.exists():
            raise FileNotFoundError(f"File {file_path} does not exist")
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()

    @staticmethod
    def is_zip_encrypted(master_password, zip_password: Union[str, dict]) -> tuple[bool, bool]:
        """ Check if a ZIP password is encrypted and valid.
        Returns a tuple (is_encrypted, is_valid)."""
        if master_password:
            if isinstance(zip_password, dict):
                # Check if it's a properly formatted encrypted dict
                if 'salt' in zip_password and 'data' in zip_password:
                    return (True, True)  # encrypted and valid
                else:
                    return (True, False)  # encrypted but invalid format
            elif isinstance(zip_password, str):
                # Check if it's a JSON string representing encrypted data
                if zip_password.strip().startswith('{') and 'data' in zip_password and 'salt' in zip_password:
                    return (True, True)  # encrypted JSON string and valid
                else:
                    return (False, True)  # not encrypted but valid (plain text)
            else:
                return (False, False)  # not encrypted and invalid (empty/None)
        else:
            # No master password, so encryption is not expected
            return (False, True)  # not encrypted but valid

    @staticmethod
    def handle_zip_password(peer_data, raw_peer_data, master_password, config, peer_name, db_update_callback, 
                           generate_zip_password_func, encrypt_database_field_func, decrypt_database_field_func,
                           update_allowed=True):
        """
        Handle zip password validation, encryption, and database updates.
        Returns the final zip password (decrypted for display/use).
        
        Args:
            peer_data: Decrypted peer data dict
            raw_peer_data: Raw peer data dict (before decryption)
            master_password: Master password if encryption is enabled
            config: Server config dict
            peer_name: Name of the peer
            db_update_callback: Function to call for database updates (peer_name, new_password)
            generate_zip_password_func: Function to generate new zip passwords
            encrypt_database_field_func: Function to encrypt database fields
            decrypt_database_field_func: Function to decrypt database fields
            update_allowed: Whether database updates are allowed (False for read-only operations)
        
        Returns:
            str: The zip password (decrypted/plain text for use)
        """
        zip_password = peer_data.get("zip_password", "")
        raw_zip_password = raw_peer_data.get("zip_password", "")
        
        # Check if password is valid and encrypted
        password_is_encrypted, password_is_valid = Helper.is_zip_encrypted(master_password, raw_zip_password)
        
        # Handle completely missing passwords - ONLY CASE WHERE WE GENERATE NEW PASSWORD
        if not raw_zip_password:
            if update_allowed:
                zip_password = generate_zip_password_func()
                if master_password:
                    # Encrypt the new password before saving
                    salt = config.get("encryption_salt", "")
                    if salt:
                        encrypted_password = encrypt_database_field_func(
                            zip_password,
                            master_password,
                            base64.b64decode(salt)
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
                            zip_password,
                            master_password,
                            base64.b64decode(salt)
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
                    return decrypt_database_field_func(raw_zip_password, master_password)
                elif isinstance(raw_zip_password, dict):
                    return decrypt_database_field_func(json.dumps(raw_zip_password), master_password)
                else:
                    return "[Decryption Error]"
            except Exception:
                return "[Decryption Error]"
        
        # Handle valid but unencrypted passwords when master password is set
        # ONLY ENCRYPT IF update_allowed and actually unencrypted in the database
        elif password_is_valid and not password_is_encrypted and master_password and update_allowed:
            # Encrypt the existing password and save it (one-time migration)
            salt = config.get("encryption_salt", "")
            if salt:
                encrypted_password = encrypt_database_field_func(
                    zip_password,  # This is the plain text password
                    master_password,
                    base64.b64decode(salt)
                )
                db_update_callback(peer_name, encrypted_password)
            # Return the plain text password for display
            return zip_password
        
        # Return as-is for other cases (no master password, already valid)
        return zip_password if zip_password else "[No Password]"

    @staticmethod
    def ensure_zip_password_encryption(zip_password, master_password, config, peer_name, db_update_callback,
                                     encrypt_database_field_func, decrypt_database_field_func):
        """
        Ensure zip password is properly encrypted if master password is set.
        Used by repair_peer_zips for its specific encryption flow.
        
        Returns:
            str: The zip password (decrypted for use)
        """
        if not master_password or not zip_password:
            return zip_password

        # If encryption is enabled and zip_password is a plain string, encrypt and update DB
        if isinstance(zip_password, str):
            zp = zip_password.strip()
            if not (zp.startswith('{') and 'data' in zp and 'salt' in zp):
                # It's a plain text password that needs encryption
                salt_b64 = config.get("encryption_salt")
                if salt_b64:
                    salt = base64.b64decode(salt_b64)
                    encrypted_pw = encrypt_database_field_func(zip_password, master_password, salt)
                    db_update_callback(peer_name, encrypted_pw)
                return zip_password
            else:
                # It's already encrypted JSON string, decrypt it
                try:
                    return decrypt_database_field_func(zip_password, master_password)
                except Exception:
                    return zip_password
        elif isinstance(zip_password, dict) and 'data' in zip_password and 'salt' in zip_password:
            # It's an encrypted dict, decrypt it
            try:
                return decrypt_database_field_func(json.dumps(zip_password), master_password)
            except Exception:
                return zip_password

        return zip_password

    # === Encryption ===
    @staticmethod
    def derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))

    @staticmethod
    def encrypt_data(data: str, password: str, salt: Optional[bytes] = None) -> Dict[str, str]:
        """Encrypt data with password"""
        if salt is None:
            salt = os.urandom(16)
        key = Helper.derive_key(password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return {
            "salt": base64.b64encode(salt).decode(),
            "data": encrypted.decode()
        }

    @staticmethod
    def decrypt_data(enc_data: Dict[str, str], password: str) -> str:
        """Decrypt data with password"""
        salt = base64.b64decode(enc_data["salt"])
        key = Helper.derive_key(password, salt)
        f = Fernet(key)
        return f.decrypt(enc_data["data"].encode()).decode()

    @staticmethod
    def generate_zip_password(length: int = 16) -> str:
        """Generate a random password for ZIP files"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    # === Database Encryption ===
    @staticmethod
    def encrypt_database_field(data: str, master_password: str, salt: bytes) -> str:
        """Encrypt a database field using the master password"""
        encrypted = Helper.encrypt_data(data, master_password, salt)
        return json.dumps(encrypted)

    @staticmethod
    def decrypt_database_field(enc_json: str, master_password: str) -> str:
        """Decrypt a database field using the master password, only if actually encrypted"""
        if not isinstance(enc_json, str):
            return enc_json
        enc_json_stripped = enc_json.strip()
        # Only decrypt if it looks like a JSON object with 'data' and 'salt'
        try:
            enc_data = json.loads(enc_json_stripped)
            if isinstance(enc_data, dict) and 'data' in enc_data and 'salt' in enc_data:
                return Helper.decrypt_data(enc_data, master_password)
            else:
                return enc_json
        except (json.JSONDecodeError, TypeError):
            return enc_json
