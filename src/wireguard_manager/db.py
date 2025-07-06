"""Module for managing WireGuard peers in a database"""
import sqlite3
from typing import Optional
import os
from pathlib import Path
from contextlib import contextmanager

class ServerConfig:
    """Class representing the server configuration"""

    def __init__(self, config_path: str, interface_name: str, address: str,
                 listen_port: int, private_key: str, public_key: str,
                 post_up: str, post_down: str, table: str,  dns: str, client_root: str,
                 data_encrypted: int = 0, encryption_salt: Optional[str] = None,
                 endpoint: str = 'palmdale.dactbc.com'):
        self.config_path = config_path
        self.interface_name = interface_name
        self.address = address
        self.listen_port = listen_port
        self.private_key = private_key
        self.public_key = public_key
        self.post_up = post_up
        self.post_down = post_down
        self.table = table
        self.dns = dns
        self.client_root = client_root
        self.data_encrypted = data_encrypted
        self.encryption_salt = encryption_salt
        self.endpoint = endpoint

class PeerData:
    """Data class to hold peer information"""
    def __init__(self, name: str, public_key: str, private_key: str,
                 ip_address: str, allowed_ips: str, zip_path: Path,
                 zip_password: str):
        self.name = name
        self.public_key = public_key
        self.private_key = private_key
        self.ip_address = ip_address
        self.allowed_ips = allowed_ips
        self.zip_path = zip_path
        self.zip_password = zip_password

class DB:
    """Database class for managing WireGuard peers"""
    def update_peer_ip_address(self, peer_name: str, new_ip_address: str) -> bool:
        """Update the ip_address for a peer by name. Returns True if updated, False if peer not found."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM peers WHERE name = ?", (peer_name,))
            if cursor.fetchone()[0] == 0:
                return False
            cursor.execute("UPDATE peers SET ip_address = ? WHERE name = ?", (new_ip_address, peer_name))
            conn.commit()
            return True

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()

    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self):
        """Initialize the database with required tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Create server_config table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS server_config (
                    id INTEGER PRIMARY KEY,
                    config_path TEXT NOT NULL,
                    interface_name TEXT NOT NULL,
                    address TEXT NOT NULL,
                    listen_port INTEGER NOT NULL,
                    private_key TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    post_up TEXT,
                    post_down TEXT,
                    table_name TEXT DEFAULT 'off',
                    dns TEXT NOT NULL,
                    client_root TEXT NOT NULL,
                    data_encrypted INTEGER DEFAULT 0,
                    encryption_salt TEXT,
                    endpoint TEXT DEFAULT 'palmdale.dactbc.com'
                )
            ''')
            
            # Create peers table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS peers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    public_key TEXT NOT NULL,
                    private_key TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    allowed_ips TEXT NOT NULL,
                    zip_password TEXT,
                    zip_path TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()

    def check_if_server_config_exists(self) -> bool:
        """Check if server configuration exists"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM server_config")
            return cursor.fetchone()[0] > 0

    def insert_server_config(self, config: ServerConfig):
        """Insert server configuration"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO server_config 
                (config_path, interface_name, address, listen_port, private_key, 
                 public_key, post_up, post_down, table_name, dns, client_root,
                 data_encrypted, encryption_salt, endpoint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                config.config_path, config.interface_name, config.address,
                config.listen_port, config.private_key, config.public_key,
                config.post_up, config.post_down, config.table,
                config.dns, config.client_root, config.data_encrypted,
                config.encryption_salt, config.endpoint
            ))
            conn.commit()

    def get_server_config(self) -> Optional[dict]:
        """Get server configuration"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM server_config LIMIT 1")
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def update_server_config(self, updates: dict):
        """Update server configuration"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
            values = list(updates.values())
            cursor.execute(f"UPDATE server_config SET {set_clause}", values)
            conn.commit()

    def insert_peer_to_db(self, peer: PeerData):
        """Insert peer into database"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO peers (name, public_key, private_key, ip_address, 
                                 allowed_ips, zip_password, zip_path)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                peer.name, peer.public_key, peer.private_key,
                peer.ip_address, peer.allowed_ips, peer.zip_password,
                str(peer.zip_path)
            ))
            conn.commit()

    def check_peer_exists(self, peer_name: str):
        """Check if peer exists and exit if it does"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM peers WHERE name = ?", (peer_name,))
            if cursor.fetchone():
                print(f"Peer '{peer_name}' already exists.")
                exit(1)

    def get_peer_by_name(self, peer_name: str) -> Optional[dict]:
        """Get peer by name"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM peers WHERE name = ?", (peer_name,))
            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    def remove_peer_from_db(self, peer_name: str) -> Optional[tuple]:
        """Remove peer from database and return the removed peer data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # First, get the peer data before removing
            cursor.execute("SELECT * FROM peers WHERE name = ?", (peer_name,))
            peer_data = cursor.fetchone()
            
            if peer_data:
                # Remove the peer
                cursor.execute("DELETE FROM peers WHERE name = ?", (peer_name,))
                conn.commit()
                return tuple(peer_data)
            
            return None

    def list_peers(self) -> list:
        """List all peers"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, public_key, private_key, ip_address, allowed_ips, zip_password, zip_path, created_at FROM peers")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_peers_list(self) -> list:
        """Get list of peers for config generation"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name, public_key, ip_address, allowed_ips FROM peers")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def get_ips(self) -> list:
        """Get all IP addresses"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address FROM peers")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    def update_peer_zip_password(self, peer_name: str, new_password: str) -> bool:
        """Update the zip_password for a peer by name. Returns True if updated, False if peer not found."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM peers WHERE name = ?", (peer_name,))
            if cursor.fetchone()[0] == 0:
                return False
            cursor.execute("UPDATE peers SET zip_password = ? WHERE name = ?", (new_password, peer_name))
            conn.commit()
            return True

    def update_peer_allowed_ips(self, peer_name: str, new_allowed_ips: str) -> bool:
        """Update the allowed_ips for a peer by name. Returns True if updated, False if peer not found."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM peers WHERE name = ?", (peer_name,))
            if cursor.fetchone()[0] == 0:
                return False
            cursor.execute("UPDATE peers SET allowed_ips = ? WHERE name = ?", (new_allowed_ips, peer_name))
            conn.commit()
            return True

# Global database instance
_db_instance = None

def get_db_instance():
    """Get or create the global database instance"""
    global _db_instance
    if _db_instance is None:
        db_path = os.path.join(os.getcwd(), "wg_manager.db")
        _db_instance = DB(db_path)
    return _db_instance

# Wrapper functions for CLI compatibility
def get_server_config():
    """Get server configuration from database"""
    return get_db_instance().get_server_config()

def save_server_config(server_config: dict):
    """Save server configuration to database"""
    db_instance = get_db_instance()
    
    # Convert dict to ServerConfig object
    config_obj = ServerConfig(
        config_path=server_config.get("config_path", ""),
        interface_name=server_config.get("interface_name", "wg0"),
        address=server_config.get("address", ""),
        listen_port=server_config.get("listen_port", 51820),
        private_key=server_config.get("private_key", ""),
        public_key=server_config.get("public_key", ""),
        post_up=server_config.get("post_up", ""),
        post_down=server_config.get("post_down", ""),
        table=server_config.get("table", ""),
        dns=server_config.get("dns_server", "1.1.1.1"),
        client_root=server_config.get("client_config_root", "./clients"),
        data_encrypted=1 if server_config.get("data_encrypted") else 0,
        encryption_salt=server_config.get("encryption_salt"),
        endpoint=server_config.get("endpoint", "")
    )
    
    if db_instance.check_if_server_config_exists():
        # Update existing config
        updates = {k: v for k, v in server_config.items() if v is not None}
        db_instance.update_server_config(updates)
    else:
        # Insert new config
        db_instance.insert_server_config(config_obj)

def update_server_config(key: str, value):
    """Update a single server configuration value"""
    get_db_instance().update_server_config({key: value})

def get_all_peers():
    """Get all peers from database"""
    return get_db_instance().get_peers_list()

def get_peer_by_name(name: str):
    """Get peer by name from database"""
    return get_db_instance().get_peer_by_name(name)

def get_ips():
    """Get all peer IPs from database"""
    return get_db_instance().get_ips()

def add_peer(peer_data: dict):
    """Add a peer to the database"""
    db_instance = get_db_instance()
    
    # Convert dict to PeerData object
    peer_obj = PeerData(
        name=peer_data["name"],
        public_key=peer_data["public_key"],
        private_key=peer_data["private_key"],
        ip_address=peer_data["ip_address"],
        allowed_ips=peer_data.get("allowed_ips", f"{peer_data['ip_address']}/32"),
        zip_path=Path("./clients") / peer_data["name"] / f"{peer_data['name']}.zip",
        zip_password=peer_data["zip_password"]
    )
    
    db_instance.insert_peer_to_db(peer_obj)

def remove_peer(name: str):
    """Remove a peer from the database"""
    return get_db_instance().remove_peer_from_db(name)
