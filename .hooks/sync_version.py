#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys
import urllib.request
import json

VERSION_FILE = pathlib.Path("src/wireguard_peer_tool/_version.py")
PYPROJECT_FILE = pathlib.Path("pyproject.toml")

VERSION_PATTERN = re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]")
PYPROJECT_PATTERN = re.compile(r'^version\s*=\s*".*"$', re.MULTILINE)
PYPI_API = "https://test.pypi.org/pypi/wireguard-peer-tool/json"

def read_version_from_file(path: pathlib.Path) -> str:
    """Read version from _version.py file"""
    content = path.read_text()
    match = VERSION_PATTERN.search(content)
    if not match:
        print(f"❌ Could not find __version__ in {path}")
        sys.exit(1)
    return match.group(1)

def read_version_from_git(path: str) -> str | None:
    """Read version from git HEAD for the given file"""
    try:
        output = subprocess.check_output(["git", "show", f"HEAD:{path}"], text=True)
        match = VERSION_PATTERN.search(output)
        if not match:
            return None
        return match.group(1)
    except subprocess.CalledProcessError:
        return None

def bump_patch_version(version: str) -> str:
    """Bump the patch version (e.g., 0.1.0 -> 0.1.1)"""
    if ".dev" in version:
        version = version.split(".dev")[0]
    parts = version.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)

def fetch_existing_versions() -> set:
    """Fetch existing versions from Test PyPI"""
    try:
        with urllib.request.urlopen(PYPI_API) as response:
            data = json.load(response)
        return set(data.get("releases", {}).keys())
    except Exception as e:
        print(f"⚠️ Warning: Failed to fetch existing versions from Test PyPI: {e}")
        return set()

def find_next_available_dev_version(base_version: str) -> str:
    """Find the next available .devN version on Test PyPI"""
    existing_versions = fetch_existing_versions()
    for i in range(1, 100):
        candidate = f"{base_version}.dev{i}"
        if candidate not in existing_versions:
            return candidate
    print("❌ Could not find available .devN slot after 100 attempts.")
    sys.exit(1)

def inject_version(version: str, dev_mode: bool = False):
    """Update version in both _version.py and pyproject.toml"""
    print(f"🔁 Updating version to: {version}")

    # Update _version.py
    version_content = VERSION_FILE.read_text()
    new_version_content = VERSION_PATTERN.sub(f"__version__ = '{version}'", version_content)
    VERSION_FILE.write_text(new_version_content)

    # Update pyproject.toml
    pyproject = PYPROJECT_FILE.read_text()
    
    if dev_mode:
        # For dev builds, switch to static versioning
        # Remove dynamic version line if it exists
        pyproject = re.sub(r'dynamic\s*=\s*\["version"\]', '', pyproject)
        pyproject = re.sub(r'dynamic\s*=\s*\[.*"version".*\]', '', pyproject)
        
        # Add or update static version
        if PYPROJECT_PATTERN.search(pyproject):
            new_pyproject = PYPROJECT_PATTERN.sub(f'version = "{version}"', pyproject)
        else:
            # Insert version after [project] line
            new_pyproject = re.sub(r"(\[project\])", rf"\1\nversion = \"{version}\"", pyproject)
        
        # Remove VCS version source if it exists
        new_pyproject = re.sub(r'\[tool\.hatch\.version\]\s*\nsource\s*=\s*"vcs"', '', new_pyproject)
        new_pyproject = re.sub(r'\[tool\.hatch\.build\.hooks\.vcs\]\s*\nversion-file\s*=.*', '', new_pyproject)
        
        # Remove hatch-vcs from build requirements
        new_pyproject = re.sub(r'requires\s*=\s*\["hatchling",\s*"hatch-vcs"\]', 'requires = ["hatchling"]', new_pyproject)
        
        PYPROJECT_FILE.write_text(new_pyproject)
    else:
        # For production builds, ensure we keep VCS-based versioning but clean up any dev modifications
        # Restore dynamic version if it was removed
        if 'dynamic = ["version"]' not in pyproject and 'version =' in pyproject:
            # Remove static version and restore dynamic
            pyproject = re.sub(r'version\s*=\s*".*"\s*\n', '', pyproject)
            if 'dynamic' not in pyproject:
                pyproject = re.sub(r'(\[project\]\s*\n)', r'\1dynamic = ["version"]\n', pyproject)
        
        # Ensure VCS configuration exists
        if '[tool.hatch.version]' not in pyproject:
            pyproject += '\n[tool.hatch.version]\nsource = "vcs"\n'
        
        # Ensure build hooks exist
        if '[tool.hatch.build.hooks.vcs]' not in pyproject:
            pyproject += '\n[tool.hatch.build.hooks.vcs]\nversion-file = "src/wireguard_peer_tool/_version.py"\n'
            
        # Ensure hatch-vcs is in build requirements
        if 'hatch-vcs' not in pyproject:
            pyproject = re.sub(r'requires\s*=\s*\["hatchling"\]', 'requires = ["hatchling", "hatch-vcs"]', pyproject)
        
        PYPROJECT_FILE.write_text(pyproject)

def main():
    dev_mode = "--dev" in sys.argv
    current_version = read_version_from_file(VERSION_FILE)
    previous_version = read_version_from_git("src/wireguard_peer_tool/_version.py")

    print(f"Current: {current_version}, Previous: {previous_version}")
    print(f"Mode: {'DEV' if dev_mode else 'PRODUCTION'}")

    if current_version == previous_version:
        if dev_mode:
            # For dev mode, find next available dev version
            base_version = current_version.split(".dev")[0] if ".dev" in current_version else current_version
            new_version = find_next_available_dev_version(base_version)
            inject_version(new_version, dev_mode=True)
            print("✅ Dev version auto-bumped for CI build.")
            sys.exit(0)
        else:
            # For production mode, ensure clean version management
            clean_version = current_version.split(".dev")[0] if ".dev" in current_version else current_version
            inject_version(clean_version, dev_mode=False)
            print("✅ Production version prepared for release.")
            sys.exit(0)
    else:
        print("✅ Version already bumped — proceeding.")
        if not dev_mode:
            # Ensure production configuration is correct
            clean_version = current_version.split(".dev")[0] if ".dev" in current_version else current_version
            inject_version(clean_version, dev_mode=False)
        sys.exit(0)

if __name__ == "__main__":
    main()
