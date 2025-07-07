#!/usr/bin/env python3
import subprocess
import pathlib
import re
import sys
import urllib.request
import urllib.error
import json
import os
from urllib.parse import urlparse

VERSION_FILE = pathlib.Path("src/wireguard_peer_tool/_version.py")
PYPROJECT_FILE = pathlib.Path("pyproject.toml")

VERSION_PATTERN = re.compile(r"__version__\s*=\s*.*?['\"]([^'\"]+)['\"]")
PYPROJECT_PATTERN = re.compile(r'^version\s*=\s*".*"$', re.MULTILINE)
PYPI_API = "https://test.pypi.org/pypi/wireguard-peer-tool/json"

def clean_version(version: str) -> str:
    """Clean version string by removing local identifiers and git metadata"""
    # Remove local version identifier (everything after +)
    if "+" in version:
        version = version.split("+")[0]
    return version

def read_version_from_file(path: pathlib.Path) -> str:
    """Read version from _version.py file"""
    content = path.read_text(encoding='utf-8')
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
    # Ensure we have at least major.minor.patch
    if len(parts) == 2:
        parts.append("0")  # Add patch version if missing
    
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)

def fetch_existing_versions() -> set:
    """Fetch existing versions from Test PyPI"""
    try:
        with urllib.request.urlopen(PYPI_API) as response:
            data = json.load(response)
        return set(data.get("releases", {}).keys())
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as e:
        print(f"⚠️ Warning: Failed to fetch existing versions from Test PyPI: {e}")
        return set()

def find_next_available_dev_version(base_version: str) -> str:
    """Find the next available .devN version on Test PyPI"""
    # Ensure base version has proper semantic versioning (major.minor.patch)
    parts = base_version.split(".")
    if len(parts) == 2:
        # If only major.minor, add patch version 0
        base_version = f"{base_version}.0"
    
    existing_versions = fetch_existing_versions()
    for i in range(1, 100):
        candidate = f"{base_version}.dev{i}"
        if candidate not in existing_versions:
            return candidate
    print("❌ Could not find available .devN slot after 100 attempts.")
    sys.exit(1)

def get_latest_git_tag_version() -> str | None:
    """Get the latest version from git tags"""
    try:
        # Get the latest tag that looks like a version
        output = subprocess.check_output(
            ["git", "tag", "--sort=-version:refname", "--merged", "HEAD"], 
            text=True
        ).strip()
        
        if not output:
            return None
            
        # Get the first (latest) tag
        latest_tag = output.split('\n')[0]
        
        # Remove 'v' prefix if present
        if latest_tag.startswith('v'):
            latest_tag = latest_tag[1:]
            
        return latest_tag
    except subprocess.CalledProcessError:
        return None

def get_github_repo_info():
    """Extract GitHub repo owner and name from git remote"""
    try:
        output = subprocess.check_output(["git", "remote", "get-url", "origin"], text=True).strip()
        # Parse GitHub URL (both https and ssh formats)
        if output.startswith("git@github.com:"):
            repo_path = output.replace("git@github.com:", "").replace(".git", "")
        elif "github.com/" in output:
            parsed = urlparse(output)
            repo_path = parsed.path.strip("/").replace(".git", "")
        else:
            return None
        
        parts = repo_path.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]
        return None
    except subprocess.CalledProcessError:
        return None

def get_pr_number():
    """Get PR number from environment variables (GitHub Actions sets this)"""
    # Check common environment variables for PR number
    pr_number = os.environ.get("GITHUB_PR_NUMBER")
    if not pr_number:
        pr_number = os.environ.get("PR_NUMBER")
    if not pr_number:
        # Try to get from GitHub event if in GitHub Actions
        github_event_path = os.environ.get("GITHUB_EVENT_PATH")
        if github_event_path and os.path.exists(github_event_path):
            try:
                with open(github_event_path, 'r', encoding='utf-8') as f:
                    event_data = json.load(f)
                if "pull_request" in event_data:
                    pr_number = str(event_data["pull_request"]["number"])
            except (OSError, json.JSONDecodeError, KeyError):
                pass
    return pr_number

def update_pr_comment(version: str):
    """Update or create a PR comment with the new test version install command"""
    repo_info = get_github_repo_info()
    pr_number = get_pr_number()
    github_token = os.environ.get("GITHUB_TOKEN")
    
    if not repo_info or not pr_number or not github_token:
        print(f"⚠️ Missing GitHub info - repo: {bool(repo_info)}, PR: {bool(pr_number)}, token: {bool(github_token)}")
        return False
    
    owner, repo = repo_info
    
    # Comment content with install command
    comment_marker = "<!-- WIREGUARD_PEER_TOOL_TEST_INSTALL -->"
    install_command = f"pip install -i https://test.pypi.org/simple/ wireguard-peer-tool=={version}"
    
    comment_body = f"""{comment_marker}
## 🧪 Test Build Available

A test build of this PR is now available on Test PyPI:

```bash
{install_command}
```

**Note:** This is a test build and should only be used for testing purposes.
"""
    
    # GitHub API URLs
    comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "wireguard-peer-tool-sync-version"
    }
    
    try:
        # Get existing comments
        req = urllib.request.Request(comments_url, headers=headers)
        with urllib.request.urlopen(req) as response:
            comments = json.load(response)
        
        # Find existing comment with our marker
        existing_comment = None
        for comment in comments:
            if comment_marker in comment.get("body", ""):
                existing_comment = comment
                break
        
        if existing_comment:
            # Update existing comment
            comment_url = existing_comment["url"]
            data = json.dumps({"body": comment_body}).encode('utf-8')
            req = urllib.request.Request(comment_url, data=data, headers=headers, method="PATCH")
            with urllib.request.urlopen(req) as response:
                print(f"✅ Updated PR comment with test version {version}")
                return True
        else:
            # Create new comment
            data = json.dumps({"body": comment_body}).encode('utf-8')
            req = urllib.request.Request(comments_url, data=data, headers=headers)
            with urllib.request.urlopen(req) as response:
                print(f"✅ Created PR comment with test version {version}")
                return True
                
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError) as e:
        print(f"⚠️ Failed to update PR comment: {e}")
        return False

def inject_version(version: str, dev_mode: bool = False):
    """Update version in both _version.py and pyproject.toml"""
    print(f"🔁 Updating version to: {version}")

    # Update _version.py
    version_content = VERSION_FILE.read_text(encoding='utf-8')
    # Handle both simple and multiple assignment formats
    if "__version__ = version =" in version_content:
        # Multiple assignment format: __version__ = version = 'value'
        new_version_content = re.sub(r"__version__\s*=\s*version\s*=\s*['\"][^'\"]+['\"]", f"__version__ = version = '{version}'", version_content)
    else:
        # Simple assignment format: __version__ = 'value'
        new_version_content = VERSION_PATTERN.sub(f"__version__ = '{version}'", version_content)
    VERSION_FILE.write_text(new_version_content, encoding='utf-8')

    # Update pyproject.toml
    pyproject = PYPROJECT_FILE.read_text(encoding='utf-8')
    
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
            new_pyproject = re.sub(r"(\[project\])", rf'\1\nversion = "{version}"', pyproject)
        
        # Remove VCS version source if it exists
        new_pyproject = re.sub(r'\[tool\.hatch\.version\]\s*\nsource\s*=\s*"vcs"', '', new_pyproject)
        new_pyproject = re.sub(r'\[tool\.hatch\.build\.hooks\.vcs\]\s*\nversion-file\s*=.*', '', new_pyproject)
        
        # Remove hatch-vcs from build requirements
        new_pyproject = re.sub(r'requires\s*=\s*\["hatchling",\s*"hatch-vcs"\]', 'requires = ["hatchling"]', new_pyproject)
        
        PYPROJECT_FILE.write_text(new_pyproject, encoding='utf-8')
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
        
        PYPROJECT_FILE.write_text(pyproject, encoding='utf-8')

def main():
    dev_mode = "--dev" in sys.argv
    raw_current_version = read_version_from_file(VERSION_FILE)
    current_version = clean_version(raw_current_version)
    
    raw_previous_version = read_version_from_git("src/wireguard_peer_tool/_version.py")
    previous_version = clean_version(raw_previous_version) if raw_previous_version else None

    print(f"Current: {current_version} (raw: {raw_current_version})")
    print(f"Previous: {previous_version} (raw: {raw_previous_version})")
    print(f"Mode: {'DEV' if dev_mode else 'PRODUCTION'}")

    if current_version == previous_version:
        if dev_mode:
            # For dev mode, use latest git tag as base version
            git_tag_version = get_latest_git_tag_version()
            if git_tag_version:
                print(f"Latest git tag version: {git_tag_version}")
                # Bump from the latest tag version
                base_version = bump_patch_version(git_tag_version)
                print(f"Base version for dev: {base_version}")
            else:
                print("No git tags found, using current version as base")
                # Fallback to current version logic
                base_version = current_version.split(".dev")[0] if ".dev" in current_version else current_version
                # If the current version looks like a dev version from an old base, 
                # try to extract the real base version
                if ".dev" not in current_version:
                    base_version = bump_patch_version(base_version)
            
            new_version = find_next_available_dev_version(base_version)
            inject_version(new_version, dev_mode=True)
            print("✅ Dev version auto-bumped for CI build.")
            
            # Update PR comment with install command
            update_pr_comment(new_version)
            
            sys.exit(0)
        else:
            # For production mode, ensure clean version management
            clean_version_str = current_version.split(".dev")[0] if ".dev" in current_version else current_version
            inject_version(clean_version_str, dev_mode=False)
            print("✅ Production version prepared for release.")
            sys.exit(0)
    else:
        print("✅ Version already bumped — proceeding.")
        if not dev_mode:
            # Ensure production configuration is correct
            clean_version_str = current_version.split(".dev")[0] if ".dev" in current_version else current_version
            inject_version(clean_version_str, dev_mode=False)
        sys.exit(0)

if __name__ == "__main__":
    main()
