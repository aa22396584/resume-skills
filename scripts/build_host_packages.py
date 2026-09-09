#!/usr/bin/env python3
"""Build deterministic direct-skill and supported plugin/marketplace archives."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import struct
import sys
import zipfile
from pathlib import Path
from typing import Any, Mapping

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from portable_resume import __version__  # noqa: E402
from portable_resume.install.catalog import SOURCE_TITLES  # noqa: E402
from portable_resume.install.package_contracts import (  # noqa: E402
    PACKAGE_CONTRACTS_SCHEMA,
    contract_for_package_type,
    contracts_report,
    validate_archive_bytes,
)
from portable_resume.install.render import materialize_plan  # noqa: E402
from portable_resume.registry import (  # noqa: E402
    PACKAGE_SURFACES,
    enabled_destination_keys,
    enabled_package_keys,
    enabled_source_keys,
)
from build_artifact_identity import (  # noqa: E402
    identity_sha256,
    resolve_build_identity,
)

DESCRIPTION = "Offline, inert context migration across supported coding agents"
AUTHOR = {
    "name": "portable-resume-skills contributors",
    "url": "https://github.com/ImL1s",
}
DEVELOPER_NAME = "ImL1s"
DISPLAY_NAME = "Portable Resume"
REPOSITORY_URL = "https://github.com/ImL1s/resume-skills"
WEBSITE_URL = "https://iml1s.github.io/resume-skills/"
BRAND_COLOR = "#0EA5E9"
# OpenAI plugin directory limit for ``interface.shortDescription``.
MAX_SHORT_DESCRIPTION_CHARS = 30
SHORT_DESCRIPTION = "Resume past agent sessions"
KEYWORDS = ["context-migration", "agent-skills", "offline", "portable-resume"]
DEFAULT_PROMPTS = (
    "Resume my last session from this repository as a fresh handoff.",
    "List my recent local coding-agent sessions for this project and show the latest one.",
    "Import the context of my previous Claude Code session here without restoring a live process.",
)
# Archive-relative brand asset path -> minimum square pixel size required by
# the directories that display it (logo >= 256, composer icon >= 48).
BRAND_ASSETS: dict[str, int] = {
    "assets/logo.png": 256,
    "assets/icon.png": 48,
}
# Plugin-root documents shipped in the standalone OpenAI bundle.
PLUGIN_ROOT_DOCUMENTS = ("LICENSE", "NOTICE", "README.md")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _png_dimensions(data: bytes) -> tuple[int, int]:
    """Return (width, height) from a PNG IHDR chunk; fail closed otherwise."""

    if len(data) < 24 or data[:8] != _PNG_SIGNATURE or data[12:16] != b"IHDR":
        raise ValueError("brand asset is not a PNG image")
    width, height = struct.unpack(">II", data[16:24])
    return int(width), int(height)


def _brand_assets() -> dict[str, bytes]:
    """Read the committed brand PNGs and enforce the directory size floors."""

    files: dict[str, bytes] = {}
    for relative, minimum in BRAND_ASSETS.items():
        path = REPO / relative
        if not path.is_file():
            raise ValueError(f"missing brand asset: {relative}")
        data = path.read_bytes()
        width, height = _png_dimensions(data)
        if width != height or width < minimum:
            raise ValueError(
                f"brand asset {relative} must be a square PNG of at least "
                f"{minimum}px, got {width}x{height}"
            )
        files[relative] = data
    return files


def _long_description() -> str:
    sources = sorted(enabled_source_keys())
    titles = ", ".join(SOURCE_TITLES[key] for key in sources)
    return (
        f"{DISPLAY_NAME} migrates bounded context from your previous local "
        "coding-agent sessions into a fresh session. One resume skill per "
        f"supported source ({len(sources)} sources: {titles}) reads that "
        "agent's own on-disk session store, selects the newest session "
        "recorded for the current working directory where the source records "
        "one (sessions without a recorded directory stay eligible, and "
        "OpenHands has no directory filter), and prints an inert, best-effort "
        "redacted markdown handoff that the destination agent reads as data "
        "and summarizes; during a skill invocation the host and its model "
        "provider receive that output directly. Everything runs locally with "
        "Python's standard library: the bundled reader never contacts the "
        "network, never invokes the source agent's CLI, never modifies the "
        "source store, and ships no MCP server, credentials, scheduler or "
        "background service. Recovered text is marked untrusted and stale, "
        "and redaction is best-effort rather than complete data-loss "
        "prevention. This is offline context migration, not live session "
        "restore."
    )


def _interface() -> dict[str, Any]:
    if len(SHORT_DESCRIPTION) > MAX_SHORT_DESCRIPTION_CHARS:
        raise ValueError("interface.shortDescription exceeds the directory limit")
    if "$" in DEFAULT_PROMPTS[0]:
        raise ValueError("the first default prompt must not reference a $skill token")
    return {
        "displayName": DISPLAY_NAME,
        "shortDescription": SHORT_DESCRIPTION,
        "longDescription": _long_description(),
        "developerName": DEVELOPER_NAME,
        "category": "Developer Tools",
        "capabilities": ["Interactive", "Read"],
        "websiteURL": WEBSITE_URL,
        "supportURL": f"{WEBSITE_URL}support/",
        "privacyPolicyURL": f"{WEBSITE_URL}privacy/",
        "termsOfServiceURL": f"{WEBSITE_URL}terms/",
        "defaultPrompt": list(DEFAULT_PROMPTS),
        "brandColor": BRAND_COLOR,
        "composerIcon": "./assets/icon.png",
        "logo": "./assets/logo.png",
    }


def _prefixed_plan(
    host: str,
    prefix: str,
    *,
    identity: Mapping[str, Any],
) -> dict[str, bytes]:
    return {
        f"{prefix}{path}": data
        for path, data in materialize_plan(host, identity=identity).items()
    }


def _common_manifest() -> dict[str, Any]:
    return {
        "name": "portable-resume",
        "version": __version__,
        "description": DESCRIPTION,
        "author": AUTHOR,
        "license": "Apache-2.0",
        "homepage": REPOSITORY_URL,
        "repository": REPOSITORY_URL,
        "keywords": list(KEYWORDS),
    }


def _codex_plugin_root(*, identity: Mapping[str, Any]) -> dict[str, bytes]:
    """Plugin-root tree shared by the Codex marketplace and standalone bundle."""

    files = _prefixed_plan("codex", "skills/", identity=identity)
    files.update(_brand_assets())
    files[".codex-plugin/plugin.json"] = _json_bytes(
        {**_common_manifest(), "skills": "./skills/", "interface": _interface()}
    )
    return files


def _plugin_files(
    surface_key: str,
    *,
    identity: Mapping[str, Any],
) -> dict[str, bytes] | None:
    surface = PACKAGE_SURFACES[surface_key]
    host = surface.destination
    common = _common_manifest()
    if surface_key == "claude-marketplace":
        plugin_root = "plugins/portable-resume/"
        files = _prefixed_plan(host, f"{plugin_root}skills/", identity=identity)
        files[f"{plugin_root}.claude-plugin/plugin.json"] = _json_bytes(common)
        files[".claude-plugin/marketplace.json"] = _json_bytes(
            {
                "$schema": "https://code.claude.com/schemas/marketplace.json",
                "name": "portable-resume",
                "description": DESCRIPTION,
                "owner": AUTHOR,
                "plugins": [
                    {
                        "name": "portable-resume",
                        "displayName": DISPLAY_NAME,
                        "description": DESCRIPTION,
                        "version": __version__,
                        "source": "./plugins/portable-resume",
                        "author": AUTHOR,
                        "repository": REPOSITORY_URL,
                        "license": "Apache-2.0",
                    }
                ],
            }
        )
        return files
    if surface_key == "codex-marketplace":
        plugin_root = "plugins/portable-resume/"
        files = {
            f"{plugin_root}{path}": data
            for path, data in _codex_plugin_root(identity=identity).items()
        }
        files[".agents/plugins/marketplace.json"] = _json_bytes(
            {
                "name": "portable-resume",
                "interface": {"displayName": DISPLAY_NAME},
                "plugins": [
                    {
                        "name": "portable-resume",
                        "source": {
                            "source": "local",
                            "path": "./plugins/portable-resume",
                        },
                        "policy": {
                            "installation": "AVAILABLE",
                            "authentication": "ON_INSTALL",
                        },
                        "category": "Developer Tools",
                    }
                ],
            }
        )
        return files
    if surface_key == "codex-plugin":
        # Plugin root at the archive top level: the skills-only bundle shape the
        # OpenAI plugin directory accepts as an upload.
        files = _codex_plugin_root(identity=identity)
        for name in PLUGIN_ROOT_DOCUMENTS:
            files[name] = (REPO / name).read_bytes()
        return files
    if surface_key == "cursor-marketplace":
        plugin_root = "plugins/portable-resume/"
        files = _prefixed_plan(host, f"{plugin_root}skills/", identity=identity)
        files[f"{plugin_root}.cursor-plugin/plugin.json"] = _json_bytes(
            {
                "name": "portable-resume",
                "displayName": DISPLAY_NAME,
                "version": __version__,
                "description": DESCRIPTION,
                "author": AUTHOR,
                "homepage": common["homepage"],
                "repository": common["repository"],
                "license": common["license"],
                "keywords": common["keywords"],
                "category": "developer-tools",
                "tags": ["agent-skills", "context-migration", "offline"],
                "skills": "./skills/",
            }
        )
        files[".cursor-plugin/marketplace.json"] = _json_bytes(
            {
                "name": "portable-resume",
                "owner": AUTHOR,
                "metadata": {"description": DESCRIPTION},
                "plugins": [
                    {
                        "name": "portable-resume",
                        "source": "plugins/portable-resume",
                        "description": DESCRIPTION,
                    }
                ],
            }
        )
        return files
    if surface_key == "antigravity-plugin":
        files = _prefixed_plan(host, "skills/", identity=identity)
        files["plugin.json"] = _json_bytes({"name": "portable-resume"})
        return files
    if surface_key == "grok-plugin":
        files = _prefixed_plan(host, "skills/", identity=identity)
        files.update(_brand_assets())
        files[".grok-plugin/plugin.json"] = _json_bytes(
            {**common, "skills": "./skills/"}
        )
        return files
    if surface_key == "qwen-extension":
        files = _prefixed_plan(host, "skills/", identity=identity)
        files["qwen-extension.json"] = _json_bytes(
            {
                "name": "portable-resume",
                "version": __version__,
                "description": DESCRIPTION,
                "skills": "skills",
            }
        )
        return files
    if surface_key == "kimi-plugin":
        files = _prefixed_plan(host, "skills/", identity=identity)
        files["kimi.plugin.json"] = _json_bytes(
            {
                **common,
                "skills": "./skills/",
                "interface": {
                    "displayName": DISPLAY_NAME,
                    "shortDescription": "Resume inert local coding-agent context",
                },
            }
        )
        return files
    return None


def _safe_files(files: dict[str, bytes]) -> None:
    for path, data in files.items():
        pure = Path(path)
        if (
            not path
            or pure.is_absolute()
            or "\\" in path
            or ".." in pure.parts
            or path.startswith("/")
            or not isinstance(data, bytes)
        ):
            raise ValueError(f"unsafe archive member: {path!r}")


def _write_zip(path: Path, files: dict[str, bytes]) -> str:
    _safe_files(files)
    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for relative in sorted(files):
            info = zipfile.ZipInfo(relative, ZIP_TIMESTAMP)
            info.create_system = 3
            executable = relative.endswith("/scripts/run_reader.py")
            mode = 0o755 if executable else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(
                info,
                files[relative],
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validated_zip(
    path: Path,
    files: dict[str, bytes],
    *,
    package_type: str,
    expected_identity: Mapping[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Write zip, run offline contract validation (#27), return digest + report."""

    digest = _write_zip(path, files)
    validation = validate_archive_bytes(
        path.read_bytes(),
        package_type=package_type,
        expected_identity=expected_identity,
    )
    if not validation["ok"]:
        raise ValueError(
            f"package contract failed for {package_type}: {validation['failures'][:8]}"
        )
    contract = contract_for_package_type(package_type)
    return digest, {
        "contract_id": contract.contract_id,
        "package_contracts_schema": PACKAGE_CONTRACTS_SCHEMA,
        "native_evidence_status": contract.native_evidence_status,
        "last_native_evidence_ref": contract.last_native_evidence_ref,
        "offline_validation": "pass",
        "build_identity_sha256": validation["build_identity_sha256"],
    }


def build(
    output: Path,
    *,
    identity_file: str | Path | None = None,
    identity_digest: str | None = None,
) -> dict[str, Any]:
    """Build direct-skill zips for every enabled destination + registry package surfaces.

    Direct Skills and native packages are independent axes (#36): destinations
    without a package surface still get a direct zip; package surfaces without
    ``buildable`` are skipped. Each artifact is offline-validated against a
    versioned package contract (#27); native host install remains ``not-run``
    unless separately recorded.
    """

    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("output directory must be empty")
    hosts = tuple(sorted(enabled_destination_keys()))
    package_keys = tuple(sorted(enabled_package_keys()))
    identity = resolve_build_identity(
        repo_root=REPO,
        package_root=SRC / "portable_resume",
        identity_file=identity_file,
        expected_sha256=identity_digest,
    )
    canonical_identity_sha256 = identity_sha256(identity)
    artifact_version = str(identity["version"])
    artifacts: list[dict[str, Any]] = []
    # #121: collapse byte-identical direct Skill trees by skill_payload_profile.
    from portable_resume.install.catalog import HOST_PROFILES

    profile_hosts: dict[str, list[str]] = {}
    for host in hosts:
        profile = HOST_PROFILES[host].skill_payload_profile
        profile_hosts.setdefault(profile, []).append(host)

    profile_artifacts: dict[str, dict[str, Any]] = {}
    for profile, group in sorted(profile_hosts.items()):
        # Representative host for materialize (payload is host-neutral for shared profile).
        rep = group[0]
        direct_files = materialize_plan(rep, identity=identity)
        if len(group) == 1:
            direct_name = f"portable-resume-{artifact_version}-{rep}-skills.zip"
        elif profile == "agent-skills-portable-v1" or len(profile_hosts) == 1:
            direct_name = f"portable-resume-{artifact_version}-skills.zip"
        else:
            safe = profile.replace("/", "-")
            direct_name = f"portable-resume-{artifact_version}-{safe}-skills.zip"
        direct_path = output / direct_name
        digest, meta = _validated_zip(
            direct_path,
            direct_files,
            package_type="direct-skills",
            expected_identity=identity,
        )
        entry = {
            "host": group[0],
            "hosts": group,
            "skill_payload_profile": profile,
            "type": "direct-skills",
            "file": direct_name,
            "sha256": digest,
            "members": len(direct_files),
            "install": contract_for_package_type("direct-skills").install_hint,
            "universal": len(group) > 1,
            **meta,
        }
        profile_artifacts[profile] = entry
        # One artifact row per payload profile (#121), not per destination.
        artifacts.append(entry)
    for surface_key in package_keys:
        surface = PACKAGE_SURFACES[surface_key]
        files = _plugin_files(surface_key, identity=identity)
        if files is None:
            raise ValueError(f"package surface not buildable: {surface_key}")
        name = f"portable-resume-{artifact_version}-{surface_key}.zip"
        path = output / name
        digest, meta = _validated_zip(
            path,
            files,
            package_type=surface_key,
            expected_identity=identity,
        )
        artifacts.append(
            {
                "host": surface.destination,
                "type": surface_key,
                "package_surface": surface.key,
                "file": name,
                "sha256": digest,
                "members": len(files),
                "install": contract_for_package_type(surface_key).install_hint,
                **meta,
            }
        )
    report = {
        "schema_version": "portable-resume/host-packages-v2",
        "version": __version__,
        "artifact_version": artifact_version,
        "build_identity": identity,
        "build_identity_sha256": canonical_identity_sha256,
        "package_contracts_schema": PACKAGE_CONTRACTS_SCHEMA,
        "host_count": len(hosts),
        "direct_package_count": len(profile_hosts),
        "direct_payload_profiles": sorted(profile_hosts),
        "plugin_package_count": len(package_keys),
        "package_surfaces": list(package_keys),
        "artifacts": artifacts,
        # Honest native-layer status: offline contracts are not host CLI proof.
        "live_host_installation": "not-run",
        "native_package_activation": "not-run",
        "contracts": contracts_report()["contracts"],
    }
    (output / "host-packages.json").write_bytes(_json_bytes(report))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--identity-file")
    parser.add_argument("--identity-sha256")
    parser.add_argument("--json", action="store_true")
    namespace = parser.parse_args(argv)
    try:
        report = build(
            Path(namespace.output_dir),
            identity_file=namespace.identity_file,
            identity_digest=namespace.identity_sha256,
        )
    except (OSError, ValueError, KeyError) as error:
        print(f"HOST_PACKAGE_BUILD FAIL {type(error).__name__}", file=sys.stderr)
        return 1
    if namespace.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(
            "HOST_PACKAGE_BUILD PASS "
            f"direct={report['direct_package_count']} "
            f"plugin={report['plugin_package_count']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
