"""Test the CLI functionality"""
import pytest
import tempfile
import os
from pathlib import Path
import subprocess
import sys

# Add the src directory to Python path for testing
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from wireguard_manager.cli import main, version_command
from wireguard_manager._version import __version__


def test_version_import():
    """Test that version can be imported"""
    assert __version__
    assert isinstance(__version__, str)
    assert len(__version__.split('.')) >= 2  # At least major.minor


def test_version_command(capsys):
    """Test the version command"""
    import argparse
    args = argparse.Namespace()
    
    version_command(args)
    captured = capsys.readouterr()
    
    assert "WireGuard Manager" in captured.out
    assert __version__ in captured.out


def test_cli_help():
    """Test that CLI help works"""
    # This should work even without WireGuard installed
    result = subprocess.run([
        sys.executable, "-m", "wireguard_manager.cli", "--help"
    ], capture_output=True, text=True, cwd=Path(__file__).parent.parent)
    
    assert result.returncode == 0
    assert "WireGuard Manager" in result.stdout
    assert "init" in result.stdout
    assert "add-peer" in result.stdout


def test_cli_version():
    """Test CLI version flag"""
    result = subprocess.run([
        sys.executable, "-m", "wireguard_manager.cli", "--version"
    ], capture_output=True, text=True, cwd=Path(__file__).parent.parent)
    
    assert result.returncode == 0
    assert __version__ in result.stdout


def test_cli_version_command():
    """Test CLI version subcommand"""
    result = subprocess.run([
        sys.executable, "-m", "wireguard_manager.cli", "version"
    ], capture_output=True, text=True, cwd=Path(__file__).parent.parent)
    
    assert result.returncode == 0
    assert "WireGuard Manager" in result.stdout
    assert __version__ in result.stdout


@pytest.mark.skipif(not os.path.exists("/usr/bin/wg"), reason="WireGuard not installed")
def test_cli_list_peers_no_config():
    """Test list-peers command with no configuration (should work)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Change to temp directory so we don't interfere with real DB
        os.chdir(tmpdir)
        
        result = subprocess.run([
            sys.executable, "-m", "wireguard_manager.cli", "list-peers"
        ], capture_output=True, text=True, cwd=Path(__file__).parent.parent)
        
        # Should complete successfully even with no config
        assert result.returncode == 0
        assert "No peers found" in result.stdout or "Server not initialized" in result.stderr


class TestCLIImports:
    """Test that all modules can be imported"""
    
    def test_import_cli(self):
        """Test importing the CLI module"""
        from wireguard_manager import cli
        assert hasattr(cli, 'main')
    
    def test_import_db(self):
        """Test importing the database module"""
        from wireguard_manager import db
        assert hasattr(db, 'DB')
    
    def test_import_helper(self):
        """Test importing the helper module"""
        from wireguard_manager import helper
        assert hasattr(helper, 'Helper')
    
    def test_import_version(self):
        """Test importing version"""
        from wireguard_manager import _version
        assert hasattr(_version, '__version__')


if __name__ == "__main__":
    pytest.main([__file__])
