"""
WireGuard Manager - A modern, secure Python-based command-line tool for
managing WireGuard VPN servers.
"""

from wireguard_peer_tool._version import __version__
from wireguard_peer_tool.core import db, helper

__all__ = ["__version__", "db", "helper"]
