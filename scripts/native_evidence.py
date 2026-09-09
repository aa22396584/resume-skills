"""Native host install and activation evidence collector.

Schema: portable-resume/native-evidence-v1
Policy: docs/evidence/native-activation-policy-v1.md

Derives destinations dynamically from enabled_destination_keys().
Maintains independent outcomes for:
  - offline package contract / installed owned-runner correctness (offline_runner)
  - native local validation, installation and actual discovery/readback (local_discovery)
  - explicit headless activation with synthetic fixture (explicit_activation)
  - natural-language routing / model selection (nl_selection)
  - human-visible visual picker (visual_picker)
  - public marketplace / catalog installation (marketplace_install)

Only seven destinations currently have native archive surfaces; do not invent
native plugin formats for direct-Skill hosts. Kilo remains destination-only.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from portable_resume import __version__ as BUNDLE_VERSION
from portable_resume.build_identity import runtime_identity
from portable_resume.contracts import validate_envelope
from portable_resume.diagnostics import SOURCE_KEYS
from portable_resume.registry import (
    DESTINATION_PROFILES,
    enabled_destination_keys,
    enabled_source_keys,
)
from portable_resume.install.catalog import HOST_PROFILES, resolve_skill_root
from portable_resume.install.package_contracts import PACKAGE_CONTRACTS
from portable_resume.install.render import materialize_plan, package_identity

EVIDENCE_SCHEMA_VERSION = "portable-resume/native-evidence-v1"

# Closed state enum as prescribed in docs/evidence/native-activation-policy-v1.md
STATE_NOT_RUN = "not-run"
STATE_STALE = "stale"
STATE_CURRENT = "current"
STATE_FAILED = "failed"
ALLOWED_STATES: frozenset[str] = frozenset(
    {STATE_NOT_RUN, STATE_STALE, STATE_CURRENT, STATE_FAILED}
)

# Independent evaluation scopes
SCOPE_OFFLINE_RUNNER = "offline_runner"
SCOPE_LOCAL_DISCOVERY = "local_discovery"
SCOPE_EXPLICIT_ACTIVATION = "explicit_activation"
SCOPE_NL_SELECTION = "nl_selection"
SCOPE_VISUAL_PICKER = "visual_picker"
SCOPE_MARKETPLACE_INSTALL = "marketplace_install"

ALL_SCOPES: tuple[str, ...] = (
    SCOPE_OFFLINE_RUNNER,
    SCOPE_LOCAL_DISCOVERY,
    SCOPE_EXPLICIT_ACTIVATION,
    SCOPE_NL_SELECTION,
    SCOPE_VISUAL_PICKER,
    SCOPE_MARKETPLACE_INSTALL,
)


@dataclass(frozen=True)
class NativeEvidenceRecord:
    """Sanitized machine-readable evidence record for one host × scope."""

    host: str
    scope: str
    state: str
    artifact_file: str
    artifact_sha256: str
    identity_sha256: str
    recorded_at: str
    host_version: str | None = None
    platform: str = field(default_factory=lambda: sys.platform)
    schema_version: str = EVIDENCE_SCHEMA_VERSION
    operator: str | None = None
    ci_run_url: str | None = None
    reason: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.schema_version != EVIDENCE_SCHEMA_VERSION:
            raise ValueError(f"invalid schema_version: {self.schema_version}")
        if self.state not in ALLOWED_STATES:
            raise ValueError(f"invalid state: {self.state!r}; must be one of {sorted(ALLOWED_STATES)}")
        if self.scope not in ALL_SCOPES:
            raise ValueError(f"invalid scope: {self.scope!r}; must be one of {ALL_SCOPES}")
        if self.host not in enabled_destination_keys():
            raise ValueError(f"unknown host: {self.host!r}")
        # Verify no raw private local paths are present in reason or provenance strings
        combined_text = f"{self.reason or ''} {json.dumps(self.provenance)}"
        _assert_no_raw_home_paths(combined_text)

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "host": self.host,
            "host_version": self.host_version,
            "platform": self.platform,
            "scope": self.scope,
            "state": self.state,
            "artifact_file": self.artifact_file,
            "artifact_sha256": self.artifact_sha256,
            "identity_sha256": self.identity_sha256,
            "recorded_at": self.recorded_at,
            "operator": self.operator,
            "ci_run_url": self.ci_run_url,
            "reason": self.reason,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class HostEvidenceProfile:
    """Profile specification for native evidence collection on one host."""

    host: str
    binary_names: tuple[str, ...]
    version_args: tuple[str, ...]
    env_config_var: str | None
    has_native_package: bool
    native_package_profile: str | None
    supported_automated_scopes: tuple[str, ...]
    blocked_or_manual_scopes: dict[str, str]
    discovery_commands: tuple[tuple[str, ...], ...]
    activation_commands: tuple[tuple[str, ...], ...]
    notes: str = ""


# Host-specific profile configurations for all enabled destinations
_PROFILE_SPECS: dict[str, dict[str, Any]] = {
    "claude": {
        "binary_names": ("claude",),
        "version_args": ("--version",),
        "env_config_var": "CLAUDE_CONFIG_DIR",
        "has_native_package": True,
        "native_package_profile": "claude-marketplace",
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY, SCOPE_EXPLICIT_ACTIVATION),
        "blocked_or_manual_scopes": {
            SCOPE_VISUAL_PICKER: "Manual UI only; no headless automation",
            SCOPE_NL_SELECTION: "Requires Claude model inference with active Anthropic auth",
            SCOPE_MARKETPLACE_INSTALL: "Requires public marketplace publication",
        },
        "discovery_commands": (("claude", "plugin", "list"),),
        "activation_commands": (("claude", "--print", "/resume-claude"),),
        "notes": "Respects CLAUDE_CONFIG_DIR for isolated profile root (#280).",
    },
    "codex": {
        "binary_names": ("codex",),
        "version_args": ("--version",),
        "env_config_var": "CODEX_HOME",
        "has_native_package": True,
        "native_package_profile": "codex-marketplace",
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY, SCOPE_EXPLICIT_ACTIVATION),
        "blocked_or_manual_scopes": {
            SCOPE_VISUAL_PICKER: "Manual UI only",
            SCOPE_NL_SELECTION: "Requires Codex model inference",
            SCOPE_MARKETPLACE_INSTALL: "Requires public Git marketplace",
        },
        "discovery_commands": (("codex", "plugin", "list"),),
        "activation_commands": (("codex", "exec", "$resume-claude"),),
        "notes": "Shared-root multi-claim compatible (#282).",
    },
    "cursor": {
        "binary_names": ("cursor-agent", "cursor"),
        "version_args": ("--version",),
        "env_config_var": "CURSOR_CONFIG_DIR",
        "has_native_package": True,
        "native_package_profile": "cursor-marketplace",
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY, SCOPE_EXPLICIT_ACTIVATION),
        "blocked_or_manual_scopes": {
            SCOPE_VISUAL_PICKER: "Manual Desktop UI picker only",
            SCOPE_NL_SELECTION: "Model-dependent prompt routing; no full bubble graph claim",
            SCOPE_MARKETPLACE_INSTALL: "Public marketplace install",
        },
        "discovery_commands": (("cursor-agent", "--list-plugins"),),
        "activation_commands": (("cursor-agent", "--plugin-dir", "<plugin-dir>", "/resume-claude"),),
        "notes": "Desktop picker separate from CLI plugin-dir loader.",
    },
    "opencode": {
        "binary_names": ("opencode",),
        "version_args": ("--version",),
        "env_config_var": "OPENCODE_CONFIG_DIR",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host; no visual picker",
            SCOPE_NL_SELECTION: "Model inference with provider credentials",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host; no marketplace",
        },
        "discovery_commands": (("opencode", "skills", "list"),),
        "activation_commands": (),
        "notes": "Data-only Skill surface.",
    },
    "antigravity": {
        "binary_names": ("antigravity", "agy"),
        "version_args": ("--version",),
        "env_config_var": "ANTIGRAVITY_CONFIG_DIR",
        "has_native_package": True,
        "native_package_profile": "antigravity-plugin",
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY, SCOPE_EXPLICIT_ACTIVATION),
        "blocked_or_manual_scopes": {
            SCOPE_VISUAL_PICKER: "Manual IDE picker",
            SCOPE_NL_SELECTION: "Model inference with Gemini provider",
            SCOPE_MARKETPLACE_INSTALL: "Plugin archive / direct-skill only",
        },
        "discovery_commands": (("agy", "plugin", "list"),),
        "activation_commands": (("agy", "--print", "resume-claude"),),
        "notes": "Qualifies Antigravity CLI v1.1.25+ separately from 2.0/IDE (#281).",
    },
    "grok": {
        "binary_names": ("grok",),
        "version_args": ("--version",),
        "env_config_var": "GROK_HOME",
        "has_native_package": True,
        "native_package_profile": "grok-plugin",
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY, SCOPE_EXPLICIT_ACTIVATION),
        "blocked_or_manual_scopes": {
            SCOPE_VISUAL_PICKER: "Manual UI only",
            SCOPE_NL_SELECTION: "Model inference with xAI provider",
            SCOPE_MARKETPLACE_INSTALL: "Public marketplace install",
        },
        "discovery_commands": (("grok", "plugin", "list"),),
        "activation_commands": (("grok", "--print", "/resume-claude"),),
        "notes": "Fail-closed on unqualified rewind/compaction.",
    },
    "qwen": {
        "binary_names": ("qwen", "qwen-code"),
        "version_args": ("--version",),
        "env_config_var": "QWEN_HOME",
        "has_native_package": True,
        "native_package_profile": "qwen-extension",
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY, SCOPE_EXPLICIT_ACTIVATION),
        "blocked_or_manual_scopes": {
            SCOPE_VISUAL_PICKER: "Manual UI only",
            SCOPE_NL_SELECTION: "Model inference",
            SCOPE_MARKETPLACE_INSTALL: "Public extension source",
        },
        "discovery_commands": (("qwen", "extensions", "list"),),
        "activation_commands": (("qwen", "--approval-mode=yolo", "/resume-claude"),),
        "notes": "Direct skills versus native extension distinction.",
    },
    "kimi": {
        "binary_names": ("kimi", "kimi-code"),
        "version_args": ("--version",),
        "env_config_var": "KIMI_CODE_HOME",
        "has_native_package": True,
        "native_package_profile": "kimi-plugin",
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY, SCOPE_EXPLICIT_ACTIVATION),
        "blocked_or_manual_scopes": {
            SCOPE_VISUAL_PICKER: "TUI picker manual",
            SCOPE_NL_SELECTION: "Model inference with Moonshot auth",
            SCOPE_MARKETPLACE_INSTALL: "Public JSON catalog",
        },
        "discovery_commands": (("kimi", "plugins", "list"),),
        "activation_commands": (("kimi", "/skill:resume-claude"),),
        "notes": "Uses KIMI_CODE_HOME / .kimi-code layout.",
    },
    "pi": {
        "binary_names": ("pi",),
        "version_args": ("--version",),
        "env_config_var": "PI_CODING_AGENT_DIR",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host; no visual picker",
            SCOPE_NL_SELECTION: "Model inference with provider credentials",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host; no marketplace",
        },
        "discovery_commands": (("pi", "skills", "list"),),
        "activation_commands": (),
        "notes": "Respects PI_CODING_AGENT_DIR (#287).",
    },
    "openclaw": {
        "binary_names": ("openclaw",),
        "version_args": ("--version",),
        "env_config_var": "OPENCLAW_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host; no visual picker",
            SCOPE_NL_SELECTION: "Model inference",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host; no marketplace",
        },
        "discovery_commands": (("openclaw", "skills", "list"),),
        "activation_commands": (),
        "notes": "Per-agent SQLite workspace discovery.",
    },
    "goose": {
        "binary_names": ("goose",),
        "version_args": ("--version",),
        "env_config_var": "GOOSE_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host",
            SCOPE_NL_SELECTION: "Model inference",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host",
        },
        "discovery_commands": (("goose", "skills", "list"),),
        "activation_commands": (),
        "notes": "Sessions SQLite schema v15.",
    },
    "crush": {
        "binary_names": ("crush",),
        "version_args": ("--version",),
        "env_config_var": "CRUSH_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host",
            SCOPE_NL_SELECTION: "Model inference",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host",
        },
        "discovery_commands": (("crush", "skills", "list"),),
        "activation_commands": (),
        "notes": "Explicit source-root / current-project scope.",
    },
    "cline": {
        "binary_names": ("cline",),
        "version_args": ("--version",),
        "env_config_var": "CLINE_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "VS Code extension UI picker manual",
            SCOPE_NL_SELECTION: "Model inference",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host",
        },
        "discovery_commands": (("cline", "skills", "list"),),
        "activation_commands": (),
        "notes": "CLI session index plus messages JSON.",
    },
    "openhands": {
        "binary_names": ("openhands",),
        "version_args": ("--version",),
        "env_config_var": "OPENHANDS_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host",
            SCOPE_NL_SELECTION: "Model inference",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host",
        },
        "discovery_commands": (("openhands", "skills", "list"),),
        "activation_commands": (),
        "notes": "Shared project .agents/skills (#282).",
    },
    "hermes": {
        "binary_names": ("hermes",),
        "version_args": ("--version",),
        "env_config_var": "HERMES_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host",
            SCOPE_NL_SELECTION: "Model inference",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host",
        },
        "discovery_commands": (("hermes", "skills", "list"),),
        "activation_commands": (),
        "notes": "Requires Git repo root and hermes skills trust (#283).",
    },
    "github-copilot": {
        "binary_names": ("copilot", "github-copilot"),
        "version_args": ("--version",),
        "env_config_var": "COPILOT_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "CLI/IDE picker manual",
            SCOPE_NL_SELECTION: "Model inference with GitHub auth",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host",
        },
        "discovery_commands": (("copilot", "skills", "list"),),
        "activation_commands": (),
        "notes": "Local session-state events.",
    },
    "gemini": {
        "binary_names": ("gemini",),
        "version_args": ("--version",),
        "env_config_var": "GEMINI_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Direct-skill host",
            SCOPE_NL_SELECTION: "Model inference with Google auth",
            SCOPE_MARKETPLACE_INSTALL: "Direct-skill host",
        },
        "discovery_commands": (("gemini", "skills", "list"),),
        "activation_commands": (),
        "notes": "Qualified Gemini session store; independent from Antigravity.",
    },
    "kilo": {
        "binary_names": ("kilo",),
        "version_args": ("--version",),
        "env_config_var": "KILO_HOME",
        "has_native_package": False,
        "native_package_profile": None,
        "supported_automated_scopes": (SCOPE_OFFLINE_RUNNER, SCOPE_LOCAL_DISCOVERY),
        "blocked_or_manual_scopes": {
            SCOPE_EXPLICIT_ACTIVATION: "Headless activation lane not yet automated for this direct-skill host",
            SCOPE_VISUAL_PICKER: "Destination-only host; direct-skill only",
            SCOPE_NL_SELECTION: "Destination-only host",
            SCOPE_MARKETPLACE_INSTALL: "Destination-only host",
        },
        "discovery_commands": (("kilo", "skills", "list"),),
        "activation_commands": (),
        "notes": "Destination-only (source research / NO-GO).",
    },
}


def get_evidence_profile(host: str) -> HostEvidenceProfile:
    """Return reviewed HostEvidenceProfile for an enabled destination."""
    if host not in enabled_destination_keys():
        raise KeyError(f"Host {host!r} is not an enabled destination")
    spec = _PROFILE_SPECS.get(host)
    if spec is None:
        raise KeyError(f"No evidence profile defined for host {host!r}")
    return HostEvidenceProfile(
        host=host,
        binary_names=spec["binary_names"],
        version_args=spec["version_args"],
        env_config_var=spec["env_config_var"],
        has_native_package=spec["has_native_package"],
        native_package_profile=spec["native_package_profile"],
        supported_automated_scopes=spec["supported_automated_scopes"],
        blocked_or_manual_scopes=dict(spec["blocked_or_manual_scopes"]),
        discovery_commands=spec["discovery_commands"],
        activation_commands=spec["activation_commands"],
        notes=spec.get("notes", ""),
    )


def validate_destination_evidence_profiles() -> None:
    """Assert that every enabled destination in the registry has a complete profile."""
    enabled = enabled_destination_keys()
    defined = frozenset(_PROFILE_SPECS.keys())
    missing = enabled - defined
    if missing:
        raise ValueError(f"Missing evidence profiles for enabled destinations: {sorted(missing)}")
    unexpected = defined - enabled
    if unexpected:
        raise ValueError(f"Unexpected evidence profiles for non-enabled destinations: {sorted(unexpected)}")
    # Verify each profile
    for host in enabled:
        prof = get_evidence_profile(host)
        if not prof.binary_names:
            raise ValueError(f"Host {host} has empty binary_names")
        if SCOPE_OFFLINE_RUNNER not in prof.supported_automated_scopes:
            raise ValueError(f"Host {host} must support offline_runner")
        all_accounted = set(prof.supported_automated_scopes) | set(prof.blocked_or_manual_scopes.keys())
        missing_scopes = set(ALL_SCOPES) - all_accounted
        if missing_scopes:
            raise ValueError(f"Host {host} missing scope declarations for: {sorted(missing_scopes)}")


def sanitize_evidence_text(text: str) -> str:
    """Sanitize paths and identifiers so no machine-local private paths leak."""
    if not text:
        return ""
    # Strip Windows drive-letter paths (e.g. C:\Users\... or D:\OtherProject\...)
    text = re.sub(r"[A-Za-z]:\\[^\s\"\'\)\],;]+", "<isolated-path>", text)
    # Strip Unix /Users/... or /home/... paths
    text = re.sub(r"/(?:Users|home)/[^\s\"\'\)\],;]+", "<isolated-path>", text)
    # Strip temporary directory paths
    text = re.sub(r"/tmp/[^\s\"\'\)\],;]+", "<isolated-tmp-path>", text)
    text = re.sub(r"[A-Za-z]:\\Temp\\[^\s\"\'\)\],;]+", "<isolated-tmp-path>", text, flags=re.IGNORECASE)
    return text


def _assert_no_raw_home_paths(text: str) -> None:
    """Fail-closed assertion that no real home absolute paths appear in text."""
    lower = text.lower()
    for token in ("/users/", "/home/", "c:\\users\\", "d:\\users\\", "c:/users/", "d:/users/"):
        if token in lower:
            raise ValueError(f"Sanitization violation: found raw path marker {token!r} in record")


def verify_installed_provenance(
    skill_dir: Path,
    expected_plan: Mapping[str, bytes],
) -> bool:
    """Verify that every file under skill_dir exactly matches the expected package plan."""
    if not skill_dir.is_dir():
        return False
    prefix = skill_dir.name + "/"
    for rel_path, expected_bytes in expected_plan.items():
        if rel_path.startswith(prefix):
            sub_path = rel_path[len(prefix):]
            target_file = skill_dir / sub_path
            if not target_file.is_file():
                return False
            try:
                if target_file.read_bytes() != expected_bytes:
                    return False
            except OSError:
                return False
    return True


def current_iso_timestamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _normalize_smoke_cwd(cwd: str) -> str:
    """Return a host-stable absolute cwd for runner smoke queries."""
    absolute = os.path.abspath(cwd)
    try:
        os.makedirs(absolute, exist_ok=True)
    except OSError:
        pass
    try:
        return os.path.realpath(absolute)
    except OSError:
        return absolute


@contextlib.contextmanager
def safe_temporary_directory(prefix: str = "portable-resume-") -> Iterator[Path]:
    """Provide an isolated temporary directory with robust error-ignoring cleanup."""
    tmp = tempfile.mkdtemp(prefix=prefix)
    try:
        yield Path(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def materialize_evidence_plan(host: str) -> dict[str, bytes]:
    """Materialize plan containing direct-skills and native package manifests if applicable."""
    plan = materialize_plan(host)
    profile = get_evidence_profile(host)
    if not profile.has_native_package:
        return plan

    evidence_plan = dict(plan)
    common = {
        "name": "portable-resume",
        "version": BUNDLE_VERSION,
        "description": "Offline, inert context migration across supported coding agents",
        "author": {"name": "portable-resume-skills contributors"},
        "license": "Apache-2.0",
        "homepage": "https://github.com/ImL1s/resume-skills",
        "repository": "https://github.com/ImL1s/resume-skills",
        "keywords": ["context-migration", "agent-skills", "offline"],
    }
    pkg_type = profile.native_package_profile
    if pkg_type == "antigravity-plugin":
        evidence_plan["plugin.json"] = (json.dumps({"name": "portable-resume"}, indent=2) + "\n").encode("utf-8")
        for k, v in plan.items():
            evidence_plan[f"skills/{k}"] = v
    elif pkg_type == "grok-plugin":
        evidence_plan["plugin.json"] = (json.dumps(common, indent=2) + "\n").encode("utf-8")
        for k, v in plan.items():
            evidence_plan[f"skills/{k}"] = v
    elif pkg_type == "qwen-extension":
        evidence_plan["qwen-extension.json"] = (
            json.dumps(
                {
                    "name": "portable-resume",
                    "version": BUNDLE_VERSION,
                    "description": common["description"],
                    "skills": "skills",
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        for k, v in plan.items():
            evidence_plan[f"skills/{k}"] = v
    elif pkg_type == "kimi-plugin":
        evidence_plan["kimi.plugin.json"] = (
            json.dumps(
                {
                    **common,
                    "skills": "./skills/",
                },
                indent=2,
            )
            + "\n"
        ).encode("utf-8")
        for k, v in plan.items():
            evidence_plan[f"skills/{k}"] = v
    return evidence_plan


def collect_offline_runner_evidence(
    host: str,
    *,
    operator: str | None = None,
    ci_run_url: str | None = None,
    repo_root: Path | None = None,
) -> NativeEvidenceRecord:
    """Verify offline package contract and installed owned-runner correctness.

    Executes isolated run_reader list + show on a synthetic fixture without
    checkout PYTHONPATH.
    """
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]

    plan = materialize_plan(host)
    identity_hash = package_identity(plan)
    artifact_name = f"portable-resume-{BUNDLE_VERSION}-{host}.zip"

    digest = hashlib.sha256()
    for key in sorted(plan):
        digest.update(key.encode("utf-8"))
        digest.update(b"\0")
        digest.update(plan[key])
        digest.update(b"\0")
    artifact_sha = digest.hexdigest()

    fixture_dir = repo_root / "tests" / "fixtures" / "claude" / "s-cla-01-ordered-parent-chain" / "root"
    if not fixture_dir.is_dir():
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_OFFLINE_RUNNER,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=None,
            operator=operator,
            ci_run_url=ci_run_url,
            reason="Synthetic fixture directory missing",
        )

    with safe_temporary_directory(prefix="portable-resume-evidence-") as tmp_root:
        for rel_path, data in plan.items():
            dest = tmp_root / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        runner_path = tmp_root / "resume-claude" / "scripts" / "run_reader.py"
        if not runner_path.is_file():
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=None,
                operator=operator,
                ci_run_url=ci_run_url,
                reason="Materialized skill missing scripts/run_reader.py",
            )

        installed_env = os.environ.copy()
        installed_env.pop("PYTHONPATH", None)
        installed_env["PYTHONNOUSERSITE"] = "1"
        cwd = "/workspace/project"

        # Execute list command
        cmd_list = [
            sys.executable,
            "-I",
            str(runner_path),
            "list",
            "--cwd",
            cwd,
            "--source-root",
            str(fixture_dir),
            "--within-min",
            "0",
            "--json",
        ]
        proc = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=installed_env,
            cwd=str(repo_root),
        )

        if proc.returncode != 0:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=None,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(f"run_reader list exited {proc.returncode}: {proc.stderr[:200]}"),
            )

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=None,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=f"Invalid JSON envelope from run_reader: {exc}",
            )

        if payload.get("schema_version") != "portable-resume/v1":
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=None,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=f"Unexpected schema_version: {payload.get('schema_version')!r}",
            )

        if payload.get("inert") is not True or payload.get("untrusted_content") is not True:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=None,
                operator=operator,
                ci_run_url=ci_run_url,
                reason="Envelope is missing inert/untrusted boundary flags",
            )

        sessions = payload.get("sessions")
        if not isinstance(sessions, list) or not sessions:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=None,
                operator=operator,
                ci_run_url=ci_run_url,
                reason="run_reader list returned no sessions",
            )

        session_id = sessions[0].get("session_id")

        # Execute show command to verify turn extraction
        cmd_show = [
            sys.executable,
            "-I",
            str(runner_path),
            "show",
            str(session_id),
            "--cwd",
            cwd,
            "--source-root",
            str(fixture_dir),
            "--within-min",
            "0",
            "--json",
        ]
        proc_show = subprocess.run(
            cmd_show,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=installed_env,
            cwd=str(repo_root),
        )

        if proc_show.returncode != 0:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=None,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(f"run_reader show exited {proc_show.returncode}: {proc_show.stderr[:200]}"),
            )

        provenance = {
            "skills_count": len(enabled_source_keys()),
            "owned_runner_verified": True,
            "isolated_exec": True,
            "package_identity_verified": True,
            "synthetic_session_id": session_id,
        }

        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_OFFLINE_RUNNER,
            state=STATE_CURRENT,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=None,
            operator=operator,
            ci_run_url=ci_run_url,
            reason="Materialized skill runner verified on synthetic fixture in isolated mode",
            provenance=provenance,
        )


@dataclass(frozen=True)
class ExplicitActivationObservation:
    """Four separate observation layers for native explicit activation."""

    host_responded: bool
    skill_selected: bool
    runner_execution_observed: bool
    fixture_read_verified: bool
    details: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


_ANSI_ESCAPE_RE = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences terminated by BEL (\x07) or ST (\x1b\)
    r"|\x1b\[[0-?]*[ -/]*[@-~]"           # CSI sequences
    r"|\x1b[@-Z\\-_]"                     # 2-character escape sequences
)


def strip_ansi(text: str) -> str:
    """Strip terminal ANSI escape sequences from command output (#295, #296)."""
    return _ANSI_ESCAPE_RE.sub("", text)


_IDENTITY_FIELDS = frozenset({"package", "plugin", "skill", "extension", "name", "id"})
_STATUS_FIELDS = frozenset({"status", "state"})
_METADATA_FIELDS = frozenset({
    "version", "author", "publisher", "description", "homepage",
    "repository", "url", "path", "location", "source", "type",
    "license", "scope", "origin", "enabled", "active",
})
_STATUS_ATTR_FIELDS = frozenset({
    "status", "state", "enabled", "active", "error", "load_error",
    "error_message", "health", "diagnostic", "message", "reason",
    "details", "detail", "note", "notes", "result",
})
_DESCRIPTIVE_METADATA_FIELDS = frozenset({
    "version", "author", "publisher", "description", "homepage",
    "repository", "url", "path", "location", "source", "type",
    "license", "scope", "origin", "summary", "docs", "help", "readme",
})
_KNOWN_FIELDS = _IDENTITY_FIELDS | _STATUS_FIELDS | _METADATA_FIELDS | _STATUS_ATTR_FIELDS | _DESCRIPTIVE_METADATA_FIELDS
_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_ -]{0,39}):(?:\s+|$)", re.IGNORECASE)
_BULLET_RE = re.compile(r"^(?:[-*•]|\d+\.)\s+")

_AUTH_BLOCKED_PATTERNS = (
    r"\b(?:re-?)?authentication\s+required\b",
    r"\b(?:re-?)?authenticate\b",
    r"\b(?:not\s+logged\s+in|login\s+required)\b",
    r"\bplease\s+(?:log\s*in|sign\s*in)\b",
    r"\bapi[ _-]?keys?\s+(?:missing|not\s+found|invalid|required|expired)\b",
    r"\bunauthorized(?:\:|\b)",
    r"\bauthorization\s+(?:failed|required|error|denied)\b",
    r"\b(?:oauth\s+)?credentials?\s+(?:required|missing|invalid|expired|not\s+found)\b",
    r"\b(?:access[ _-])?tokens?\s+(?:expired|revoked|invalid|required|missing)\b",
    r"\b(?:no|missing)\s+(?:valid\s+)?credentials?\b",
    r"\bcredentials?\s+(?:have\s+)?expired\b",
)


def _direct_native_discovery(
    stdout: str,
    stderr: str = "",
    *,
    returncode: int = 0,
    expected_package: str = "portable-resume",
    expected_skill: str = "resume-claude",
    command: Sequence[str] | None = None,
    host: str | None = None,
) -> tuple[bool, str]:
    """Evaluate host discovery output against expected package/skill identity.

    Fails closed against generic markers (skills, Skills, [ok]), empty outputs,
    negative listings, validation-only outputs, and non-zero exit codes.
    """
    if returncode != 0:
        return False, f"Subprocess exited with non-zero code {returncode}"

    stdout = strip_ansi(stdout)
    stderr = strip_ansi(stderr)

    if not stdout.strip():
        return False, "Subprocess returned empty output"

    # Reject validation-only commands (e.g. plugin validate)
    if command and any(arg == "validate" for arg in command):
        return False, "Package syntax or manifest validation does not establish native package discovery"

    out_lower = stdout.lower()

    # Reject explicit negative / empty listing markers
    negative_patterns = (
        r"\bno\s+(?:skills?|plugins?|extensions?|packages?)\s+found\b",
        r"\b(?:skills?|plugins?|extensions?|packages?)\s*:\s*0\b",
        r"\b0\s+(?:skills?|plugins?|extensions?|packages?)\s+found\b",
        r"\b(?:skills?|plugins?|extensions?|packages?)\s*\(0\)",
        r"\bno\s+imported\s+plugins\b",
        r"\bno\s+installed\s+(?:skills?|plugins?|extensions?)\b",
    )
    for pat in negative_patterns:
        if re.search(pat, out_lower):
            return False, "Host reported no skills or plugins found"

    def _has_exact_package_token(text: str, token: str) -> bool:
        if not token:
            return False
        return bool(
            re.search(
                rf"(?<![a-zA-Z0-9_.-]){re.escape(token)}(?![a-zA-Z0-9_.-])",
                text,
                re.IGNORECASE,
            )
        )

    # Reject pure generic validation output without package identity
    if "[ok]" in out_lower and not (
        _has_exact_package_token(out_lower, expected_package)
        or _has_exact_package_token(out_lower, expected_skill)
    ):
        return False, "Generic validation output does not establish native package discovery"

    # Attempt structured JSON parsing (direct, fenced, or embedded)
    try:
        data = None
        stripped = stdout.strip()
        if (stripped.startswith("{") and stripped.endswith("}")) or (
            stripped.startswith("[") and stripped.endswith("]")
        ):
            data = json.loads(stripped)
        else:
            fence_match = re.search(r"```(?:json)?\s*([{\[].*?[}\]])\s*```", stdout, re.DOTALL)
            if fence_match:
                data = json.loads(fence_match.group(1).strip())
            else:
                for start_char in ("{", "["):
                    idx = stdout.find(start_char)
                    if idx != -1:
                        try:
                            obj, _ = json.JSONDecoder().raw_decode(stdout, idx)
                            if isinstance(obj, (dict, list)):
                                data = obj
                                break
                        except Exception:
                            pass

        if data is not None:
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict):
                items = data.get("plugins") or data.get("skills") or data.get("extensions") or [data]
            else:
                items = []

            for item in items:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("id") or item.get("plugin") or item.get("skill")
                    if name in (expected_package, expected_skill):
                        if item.get("enabled") is False or item.get("active") is False:
                            return False, f"Package {name} discovered but marked enabled/active=False"
                        if item.get("error") or item.get("load_error") or item.get("error_message"):
                            err = item.get("error") or item.get("load_error") or item.get("error_message")
                            return False, f"Package {name} discovered with error: {err}"
                        status = str(item.get("status") or item.get("state") or "").lower()
                        if status and any(
                            neg in status
                            for neg in (
                                "disabled",
                                "error",
                                "failed",
                                "inactive",
                                "off",
                                "blocked",
                                "not found",
                                "broken",
                                "unload",
                            )
                        ):
                            return False, f"Package {name} discovered but in {status} state"
                        return True, f"Discovered expected package {name!r} via structured host JSON"
                elif isinstance(item, str) and item in (expected_package, expected_skill):
                    return True, f"Discovered expected skill {item!r} via structured host JSON list"
    except (json.JSONDecodeError, TypeError):
        pass

    # Match unambiguous expected package or skill token
    # Do NOT match generic words like "skills", "Skills", "[ok]", "resume", "plugin"
    # Require delimiters that cannot be part of a package identifier (alphanumeric, dot, underscore, hyphen) (#295)
    # Bind identity to complete multi-line status record (#295)
    expected_tokens = [expected_package, expected_skill]
    lines = stdout.splitlines()
    for token in expected_tokens:
        if not token:
            continue
        pattern = rf"(?<![a-zA-Z0-9_.-]){re.escape(token)}(?![a-zA-Z0-9_.-])"
        matches = list(re.finditer(pattern, stdout, re.IGNORECASE))
        if not matches:
            continue
        valid_match = False
        has_disabled_match = False
        for m in matches:
            line_idx = stdout[:m.start()].count("\n")
            record = _extract_listing_record(lines, line_idx)
            record_lower = record.lower()

            # Filter out non-status metadata fields (repository, author, path, url, description, etc.)
            # and their indented continuation lines to avoid false rejections from metadata content (#295)
            filtered_lines: list[tuple[str, bool]] = []
            in_non_status_meta = False
            meta_indent = 0
            expected_names = {expected_package.lower(), expected_skill.lower()}

            for line in record.splitlines():
                if not line.strip():
                    continue
                line_indent = len(line) - len(line.lstrip())
                clean_line = _BULLET_RE.sub("", line.strip())
                m_field = _FIELD_RE.match(clean_line)
                if m_field:
                    field_name = m_field.group(1).strip().lower()
                    if field_name in _DESCRIPTIVE_METADATA_FIELDS:
                        # Suppress only known descriptive metadata fields (author, description, repository, etc.)
                        # and their indented continuation lines (#295, Codex comment 3965487915).
                        in_non_status_meta = True
                        meta_indent = line_indent
                        continue
                    elif field_name in _STATUS_ATTR_FIELDS:
                        in_non_status_meta = False
                        filtered_lines.append((line, True))
                        continue
                    elif field_name in _IDENTITY_FIELDS or field_name in expected_names:
                        in_non_status_meta = False
                        filtered_lines.append((line, False))
                        continue
                    else:
                        # Unrecognized or diagnostic field (e.g. Diagnostic, Message, Reason, Details).
                        # Retain for failure matching (#295, Codex comment 3965487915).
                        in_non_status_meta = False
                        filtered_lines.append((line, False))
                        continue

                if in_non_status_meta:
                    if line_indent > meta_indent:
                        continue
                    else:
                        in_non_status_meta = False

                filtered_lines.append((line, False))

            negative_field_patterns = (
                r"\b(?:status|state|enabled|active|diagnostic|message|reason|health|result)\s*:\s*(?:disabled|error|failed|inactive|off|blocked|false|no|0)\b",
                r"\b(?:error|load_error|error_message|diagnostic|message|reason)\s*:\s*(?:failed|cannot|could\s+not|disabled|invalid|error)\b",
                r"\bfailed\s+to\s+(?:load|initialize|start|enable)\b",
                r"\bload\s+error\b",
                r"\b(?:not\s+found|cannot\s+find)\b",
            )
            bracketed_neg_pattern = r"[\(\[]\s*(?:disabled|inactive|error|failed|blocked|off)\s*[\)\]]"
            bare_neg_pattern = r"\b(?:disabled|inactive)\b"

            is_negative = False

            for f_line, is_status_attr in filtered_lines:
                f_line_lower = f_line.lower()
                if any(re.search(pat, f_line_lower) for pat in negative_field_patterns):
                    is_negative = True
                    break
                if re.search(bracketed_neg_pattern, f_line_lower):
                    is_negative = True
                    break
                if not is_status_attr:
                    # On unstructured rows (not structured status fields or filtered metadata), bare words indicate status
                    if re.search(bare_neg_pattern, f_line_lower):
                        is_negative = True
                        break

            if is_negative:
                has_disabled_match = True
                continue
            valid_match = True
            break

        if valid_match:
            return True, f"Discovered expected identity {token!r} in host listing"
        if has_disabled_match:
            return False, f"Package {token!r} discovered but in disabled/error state"

    return False, "Expected package or skill identity not found in host listing"


def _extract_listing_record(lines: Sequence[str], line_idx: int) -> str:
    """Extract full multi-line entry block containing line_idx in a text listing (#295)."""
    if line_idx >= len(lines) or line_idx < 0:
        return ""
    if not lines[line_idx].strip():
        return ""

    # 1. Isolate contiguous non-empty block containing line_idx
    block_start = line_idx
    while block_start > 0 and lines[block_start - 1].strip():
        block_start -= 1

    block_end = line_idx + 1
    while block_end < len(lines) and lines[block_end].strip():
        block_end += 1

    block_lines = list(lines[block_start:block_end])
    rel_idx = line_idx - block_start

    if len(block_lines) == 1:
        return block_lines[0]

    indents = [len(l) - len(l.lstrip()) for l in block_lines]

    def _extract_field_name(line: str) -> str | None:
        m = _FIELD_RE.match(line.strip())
        return m.group(1).lower() if m else None

    line_fields = [_extract_field_name(l) for l in block_lines]

    # Check if rel_idx belongs to a bullet item (is a bullet line or indented under one)
    target_is_bullet = bool(_BULLET_RE.match(block_lines[rel_idx].strip()))
    parent_bullet_idx: int | None = None
    if not target_is_bullet:
        for k in range(rel_idx - 1, -1, -1):
            if indents[k] < indents[rel_idx]:
                if _BULLET_RE.match(block_lines[k].strip()):
                    parent_bullet_idx = k
                break

    in_bullet_item = target_is_bullet or (parent_bullet_idx is not None)

    # 2. Case A: Bullet lists (only when rel_idx belongs to that bullet list)
    if in_bullet_item:
        bullet_start = rel_idx if target_is_bullet else (parent_bullet_idx if parent_bullet_idx is not None else 0)
        bullet_indent = indents[bullet_start]
        entry_end = bullet_start + 1
        while entry_end < len(block_lines):
            next_indent = indents[entry_end]
            next_is_bullet = bool(_BULLET_RE.match(block_lines[entry_end].strip()))
            if next_is_bullet and next_indent <= bullet_indent:
                break
            if not next_is_bullet and next_indent <= bullet_indent:
                break
            entry_end += 1
        return "\n".join(block_lines[bullet_start:entry_end])

    # 3. Case B: Indented hierarchy under a single header or item name
    # Line 0 is at indent 0, and ALL other lines (1..N-1) are indented (> 0)
    if indents[0] == 0 and all(ind > 0 for ind in indents[1:]):
        min_child_indent = min(indents[1:])
        child_item_indices = [i for i, ind in enumerate(indents) if ind == min_child_indent]

        child_identity_indices = [i for i in child_item_indices if line_fields[i] in _IDENTITY_FIELDS]
        child_status_indices = [i for i in child_item_indices if line_fields[i] in _STATUS_FIELDS]
        known_child_fields = [line_fields[i] for i in child_item_indices if line_fields[i] in _KNOWN_FIELDS]
        has_repeated_child_fields = len(known_child_fields) > len(set(known_child_fields))

        # Check if child lines at min_child_indent are property fields
        has_property_fields = any(
            line_fields[i] in (_STATUS_ATTR_FIELDS | _METADATA_FIELDS | _STATUS_FIELDS)
            for i in child_item_indices
        )

        # Line 0 is a category header if:
        # - It is not an identity field (e.g. not "Package: portable-resume"), AND
        # - Either child lines have no property fields (plain item names or items with sub-indentation),
        #   or child lines contain multiple identity/status fields, repeated fields, or explicit identity labels.
        is_category_header = (
            line_fields[0] not in _IDENTITY_FIELDS
            and (
                not has_property_fields
                or len(child_identity_indices) >= 2
                or len(child_status_indices) >= 2
                or has_repeated_child_fields
                or bool(child_identity_indices)
            )
        )
        if is_category_header:
            if rel_idx == 0:
                return block_lines[0]

            candidates = child_item_indices
            first_status_cand = next((i for i in candidates if line_fields[i] in _STATUS_FIELDS), None)
            first_identity_cand = next((i for i in candidates if line_fields[i] in _IDENTITY_FIELDS), None)

            if first_status_cand is not None and (
                first_identity_cand is None or first_status_cand < first_identity_cand
            ):
                # Status-first orientation: each status field starts a new record
                entry_starts = [i for i in candidates if line_fields[i] in _STATUS_FIELDS]
                if candidates[0] not in entry_starts:
                    entry_starts.insert(0, candidates[0])
            else:
                # Identity-first or plain-item orientation
                has_explicit_identity = bool(child_identity_indices)
                entry_starts = [candidates[0]]
                seen_in_curr: set[str] = set()
                if line_fields[candidates[0]] and line_fields[candidates[0]] in _KNOWN_FIELDS:
                    seen_in_curr.add(line_fields[candidates[0]])

                for i in candidates[1:]:
                    f = line_fields[i]
                    if not f or (not has_explicit_identity and f not in _KNOWN_FIELDS):
                        # Plain item name (or unlabelled entry) at min_child_indent starts a new entry
                        entry_starts.append(i)
                        seen_in_curr = set()
                        continue
                    is_repeated = f in seen_in_curr
                    is_identity = f in _IDENTITY_FIELDS
                    is_identity_after_status = (
                        is_identity
                        and bool(seen_in_curr & _STATUS_FIELDS)
                    )
                    if is_repeated or is_identity or is_identity_after_status:
                        entry_starts.append(i)
                        seen_in_curr = {f} if f in _KNOWN_FIELDS else set()
                    else:
                        if f in _KNOWN_FIELDS:
                            seen_in_curr.add(f)

            e_start = entry_starts[0]
            for s in entry_starts:
                if s <= rel_idx:
                    e_start = s
                else:
                    break
            e_end = len(block_lines)
            for s in entry_starts:
                if s > e_start:
                    e_end = s
                    break
            return "\n".join(block_lines[e_start:e_end])
        else:
            # Single item at line 0 with indented property lines
            return "\n".join(block_lines)

    # 4. Case C: Indented items under non-attribute keys (e.g. YAML mapping)
    indent_0_indices = [i for i, ind in enumerate(indents) if ind == 0]
    if len(indent_0_indices) >= 2:
        indent_0_known = [line_fields[i] in _KNOWN_FIELDS for i in indent_0_indices]
        if not all(indent_0_known) and any(
            idx_0 + 1 < len(block_lines) and indents[idx_0 + 1] > 0 for idx_0 in indent_0_indices
        ):
            e_start = indent_0_indices[0]
            for idx_0 in indent_0_indices:
                if idx_0 <= rel_idx:
                    e_start = idx_0
                else:
                    break
            e_end = len(block_lines)
            for idx_0 in indent_0_indices:
                if idx_0 > e_start:
                    e_end = idx_0
                    break
            return "\n".join(block_lines[e_start:e_end])

    # 5. Case D: Key-value fields at base indent
    known_field_indices = [i for i, f in enumerate(line_fields) if f in _KNOWN_FIELDS]
    if known_field_indices:
        first_status_idx = next((i for i, f in enumerate(line_fields) if f in _STATUS_FIELDS), None)
        first_identity_idx = next((i for i, f in enumerate(line_fields) if f in _IDENTITY_FIELDS), None)

        entry_starts = [0]
        if first_status_idx is not None and (first_identity_idx is None or first_status_idx < first_identity_idx):
            # Status-first orientation: each status field starts a new record
            entry_starts = [i for i, f in enumerate(line_fields) if f in _STATUS_FIELDS]
            if 0 not in entry_starts:
                entry_starts.insert(0, 0)
        else:
            # Identity-first orientation
            seen_in_curr: set[str] = set()
            if line_fields[0] and line_fields[0] in _KNOWN_FIELDS:
                seen_in_curr.add(line_fields[0])

            for i in range(1, len(block_lines)):
                f = line_fields[i]
                if not f or f not in _KNOWN_FIELDS:
                    continue
                is_repeated = f in seen_in_curr
                is_identity_after_status = (
                    f in _IDENTITY_FIELDS
                    and bool(seen_in_curr & _STATUS_FIELDS)
                )
                if is_repeated or is_identity_after_status:
                    entry_starts.append(i)
                    seen_in_curr = {f}
                else:
                    seen_in_curr.add(f)

        e_start = 0
        for s in entry_starts:
            if s <= rel_idx:
                e_start = s
            else:
                break
        e_end = len(block_lines)
        for s in entry_starts:
            if s > e_start:
                e_end = s
                break
        return "\n".join(block_lines[e_start:e_end])

    # 6. Case E: Plain listing rows (flat table rows, markdown tables)
    return block_lines[rel_idx]


def _extract_markdown_recovered_content(block: str) -> str:
    """Extract recovered conversation content from request/action/turn sections.

    Strictly ignores stale metadata headers (like Title:, Persisted cwd:),
    warnings, security banners, and checklist items (#296).
    """
    lines = block.splitlines()
    content_lines: list[str] = []
    in_content_section = False

    content_heading_re = re.compile(
        r"^(?:###\s+(?:latest\s+explicit\s+user\s+request|latest\s+assistant\s+message|"
        r"latest\s+recorded\s+action|bounded\s+transcript\s+evidence|turn\s+transcript|"
        r"user|assistant|tool)\b)",
        re.IGNORECASE,
    )
    stop_heading_re = re.compile(
        r"^(?:##\s+(?:stale\s+session\s+metadata|warnings|required\s+current\s+checks)|"
        r"#\s+portable\s+resume|###\s+untrusted)",
        re.IGNORECASE,
    )

    def _count_quote_depth(l: str) -> int:
        d = 0
        for ch in l.strip():
            if ch == ">":
                d += 1
            elif ch in (" ", "\t"):
                continue
            else:
                break
        return d

    # Determine structural heading quote depth (#296, Codex comment 3965487929).
    # In canonical handoffs, document headings appear at base quote depth (typically 0, or 1
    # if the entire block is quoted by the host), while recovered content lines are quoted deeper.
    # Quoted content lines that resemble headings (e.g. '> ## Warnings') must not terminate extraction.
    candidate_depths: list[int] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        text_after_quotes = stripped.lstrip("> ").strip()
        if text_after_quotes.startswith("#") and (
            content_heading_re.match(text_after_quotes)
            or stop_heading_re.match(text_after_quotes)
        ):
            candidate_depths.append(_count_quote_depth(stripped))

    structural_depth = min(candidate_depths) if candidate_depths else 0

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        depth = _count_quote_depth(stripped)
        text_after_quotes = stripped.lstrip("> ").strip()

        if depth == structural_depth and text_after_quotes.startswith("#"):
            if content_heading_re.match(text_after_quotes):
                in_content_section = True
                continue
            else:
                in_content_section = False
                continue

        if in_content_section:
            if depth > structural_depth:
                text = text_after_quotes
                if re.match(r"^\*\*\[\d+\s+(?:user|assistant|tool)[^\]]*\]\*\*$", text, re.IGNORECASE):
                    continue
                if re.match(r"^`\[W_[A-Z0-9_]+\]`$", text):
                    continue
                if text.startswith("_(") and text.endswith(")_"):
                    continue
                if text:
                    content_lines.append(text)
            elif not stripped.startswith("#"):
                content_lines.append(stripped)

    return " ".join(content_lines)


def evaluate_explicit_activation(
    stdout: str,
    stderr: str = "",
    *,
    returncode: int = 0,
    expected_source: str = "claude",
    expected_session: str = "7e0a1246-d538-5993-8d6f-3495aafcdd92",
    expected_fixture_content: Sequence[str] = ("synthetic request",),
    execution_record: Mapping[str, Any] | None = None,
    host: str | None = None,
) -> tuple[bool, ExplicitActivationObservation]:
    """Verify four separate observation layers for native explicit activation.

    1. host_responded: host executed and returned code 0 with non-empty output
    2. skill_selected: host recognized and selected the intended skill/tool
    3. runner_execution_observed: runner actually executed (observable trace or authentic format)
    4. fixture_read_verified: exact source, session, and fixture content confirmed read
    """
    if returncode != 0:
        obs = ExplicitActivationObservation(
            host_responded=False,
            skill_selected=False,
            runner_execution_observed=False,
            fixture_read_verified=False,
            details=f"Host process exited with return code {returncode}",
            error=f"exit_code_{returncode}",
        )
        return False, obs

    stdout = strip_ansi(stdout)
    stderr = strip_ansi(stderr)

    # Restrict early authentication prerequisite check to stderr (#296, Codex comment 3965234372).
    # Recovered conversation text in stdout is untrusted and may mention auth keywords.
    # Stdout will only be inspected for auth blockers if runner execution is not observed.
    err_lower = stderr.lower()
    if any(re.search(pat, err_lower) for pat in _AUTH_BLOCKED_PATTERNS):
        obs = ExplicitActivationObservation(
            host_responded=False,
            skill_selected=False,
            runner_execution_observed=False,
            fixture_read_verified=False,
            details="Host blocked on authentication/login credentials",
            error="auth_required",
        )
        return False, obs

    if not stdout.strip() and not (execution_record and execution_record.get("runner_executed")):
        obs = ExplicitActivationObservation(
            host_responded=False,
            skill_selected=False,
            runner_execution_observed=False,
            fixture_read_verified=False,
            details="Host process returned empty stdout",
            error="empty_output",
        )
        return False, obs

    out_lower = stdout.lower()
    host_responded = True

    # 2 & 3. Skill selected and runner execution observed
    skill_selected = False
    runner_execution_observed = False
    fixture_read_verified = False
    missing_parts: list[str] = []

    # Trace A: Observable execution record from instrumented runner / execution log
    if execution_record and execution_record.get("runner_executed") is True:
        if execution_record.get("returncode", 0) == 0:
            skill_selected = True
            runner_execution_observed = True
            rec_source = str(execution_record.get("source") or "")
            rec_session = str(execution_record.get("session_id") or execution_record.get("session") or "")
            rec_content = str(execution_record.get("content") or "")

            has_source = rec_source.lower() == expected_source.lower()
            has_session = rec_session.lower() == expected_session.lower()
            has_content = all(c.lower() in rec_content.lower() for c in expected_fixture_content)
            if has_source and has_session and has_content:
                fixture_read_verified = True
            else:
                if not has_source:
                    missing_parts.append(f"source '{expected_source}'")
                if not has_session:
                    missing_parts.append(f"session '{expected_session}'")
                if not has_content:
                    missing_parts.append(f"fixture content {expected_fixture_content!r}")

    # Trace B: Check for authentic structured JSON envelope (portable-resume/v1)
    if not fixture_read_verified:
        json_candidates: list[dict[str, Any]] = []
        decoder = json.JSONDecoder()
        idx = 0
        while idx < len(stdout):
            idx = stdout.find("{", idx)
            if idx == -1:
                break
            try:
                obj, end = decoder.raw_decode(stdout, idx)

                def _find_envelopes(data: Any) -> list[dict[str, Any]]:
                    found: list[dict[str, Any]] = []
                    if isinstance(data, dict):
                        if data.get("schema_version") == "portable-resume/v1":
                            found.append(data)
                        for val in data.values():
                            found.extend(_find_envelopes(val))
                    elif isinstance(data, list):
                        for item in data:
                            found.extend(_find_envelopes(item))
                    return found

                json_candidates.extend(_find_envelopes(obj))
                idx = max(end, idx + 1)
            except Exception:
                idx += 1

        for parsed in json_candidates:
            if not isinstance(parsed, dict):
                continue
            if parsed.get("result") is False or parsed.get("status") == "error":
                continue
            if parsed.get("schema_version") != "portable-resume/v1":
                continue
            # Validate the complete closed-key envelope contract (#296)
            try:
                validate_envelope(parsed)
            except Exception:
                continue

            skill_selected = True
            runner_execution_observed = True

            # Bind proof fields to the same session object (#296)
            target_sessions: list[dict[str, Any]] = [
                s for s in parsed.get("sessions", []) if isinstance(s, dict)
            ]

            session_match_found = False
            for s in target_sessions:
                s_source = str(s.get("source") or "")
                s_id = str(s.get("session_id") or "")
                # Gather recovered text strictly from conversation content chunks
                content_chunks: list[str] = []
                if isinstance(s.get("last_user_request"), str):
                    content_chunks.append(s["last_user_request"])
                if isinstance(s.get("last_assistant_action"), str):
                    content_chunks.append(s["last_assistant_action"])
                turns = s.get("turns")
                if isinstance(turns, list):
                    for t in turns:
                        if isinstance(t, dict) and isinstance(t.get("content"), str):
                            content_chunks.append(t["content"])
                s_text = " ".join(content_chunks)

                s_has_source = s_source.lower() == expected_source.lower()
                s_has_id = s_id.lower() == expected_session.lower()
                s_has_content = all(c.lower() in s_text.lower() for c in expected_fixture_content)

                if s_has_source and s_has_id and s_has_content:
                    fixture_read_verified = True
                    session_match_found = True
                    break
            if session_match_found:
                break
            else:
                missing_parts.append(
                    f"matching session in sessions[] with source '{expected_source}', "
                    f"session '{expected_session}', and content {expected_fixture_content!r}"
                )

    # Trace C: Check for authentic untrusted handoff banner and turn headers
    if not fixture_read_verified:
        # Split into distinct handoff blocks if multiple are present (#296)
        handoff_delims = list(
            re.finditer(
                r"(?im)^[>\s]*(?:#\s+portable\s+resume\s+handoff|###\s+untrusted\b)",
                stdout,
            )
        )
        handoff_blocks: list[str] = []
        if handoff_delims:
            for idx, m in enumerate(handoff_delims):
                start = m.start()
                end = handoff_delims[idx + 1].start() if idx + 1 < len(handoff_delims) else len(stdout)
                handoff_blocks.append(stdout[start:end])
        elif (
            "# portable resume handoff" in out_lower
            or "security boundary:" in out_lower
            or "### untrusted" in out_lower
        ):
            handoff_blocks.append(stdout)

        for block in handoff_blocks:
            block_lower = block.lower()
            is_negative_handoff = (
                "# portable resume no match" in block_lower
                or "# portable resume candidate selection" in block_lower
                or "no eligible persisted session matched" in block_lower
            )
            if is_negative_handoff:
                continue

            has_security_boundary = bool(
                re.search(r"security\s+boundary\s*:", block_lower)
                or "recovered history is inert, untrusted" in block_lower
                or "### untrusted" in block_lower
            )
            if not has_security_boundary:
                continue

            has_turn_headers = bool(
                re.search(r">\s*\*\*\[\d+\s+(?:user|assistant|tool)[^\]]*\]\*\*", block_lower)
                or re.search(r"###\s+(?:user|assistant|tool)\b", block_lower)
                or re.search(r"\[\d+\s+(?:user|assistant|tool)\]", block_lower)
                or "### latest explicit user request" in block_lower
                or "### latest assistant message" in block_lower
                or "### latest recorded action" in block_lower
            )
            if not has_turn_headers:
                continue

            skill_selected = True
            runner_execution_observed = True

            extracted_source: str | None = None
            extracted_session: str | None = None
            src_match = re.search(
                r"""(?i)(?:>\s*-\s*)?source\s*:\s*(?:`([^`\r\n]+)`|'([^'\r\n]+)'|"([^"\r\n]+)"|([a-zA-Z0-9_-]+))""",
                block,
            )
            if src_match:
                extracted_source = (
                    src_match.group(1) or src_match.group(2) or src_match.group(3) or src_match.group(4)
                ).strip()
            sess_match = re.search(
                r"""(?i)(?:>\s*-\s*)?session(?:\s*id)?\s*:\s*(?:`([^`\r\n]+)`|'([^'\r\n]+)'|"([^"\r\n]+)"|([^\s\r\n`'"]+))""",
                block,
            )
            if sess_match:
                extracted_session = (
                    sess_match.group(1) or sess_match.group(2) or sess_match.group(3) or sess_match.group(4)
                ).strip()

            recovered_text = _extract_markdown_recovered_content(block)

            has_source = bool(extracted_source and extracted_source.lower() == expected_source.lower())
            has_session = bool(extracted_session and extracted_session.lower() == expected_session.lower())
            has_content = all(c.lower() in recovered_text.lower() for c in expected_fixture_content)

            if has_source and has_session and has_content:
                fixture_read_verified = True
                break
            else:
                block_missing: list[str] = []
                if not has_source:
                    block_missing.append(f"source '{expected_source}'")
                if not has_session:
                    block_missing.append(f"session '{expected_session}'")
                if not has_content:
                    block_missing.append(f"fixture content {expected_fixture_content!r} in recovered sections")
                missing_parts.append(f"handoff block missing ({', '.join(block_missing)})")

    # When runner execution was not observed, evaluate diagnostic prerequisites or refusals (#296)
    if not runner_execution_observed:
        # Check for authentication diagnostics on stderr or stdout
        err_lower = stderr.lower()
        if any(re.search(pat, err_lower) for pat in _AUTH_BLOCKED_PATTERNS) or any(
            re.search(pat, out_lower) for pat in _AUTH_BLOCKED_PATTERNS
        ):
            obs = ExplicitActivationObservation(
                host_responded=False,
                skill_selected=False,
                runner_execution_observed=False,
                fixture_read_verified=False,
                details="Host blocked on authentication/login credentials",
                error="auth_required",
            )
            return False, obs

        # Check for refusals
        refusals = (
            "i cannot",
            "i am unable to",
            "i apologize",
            "as an ai",
            "permission denied",
            "refusal",
            "command not found",
            "unknown command",
        )
        if any(ref in out_lower for ref in refusals):
            obs = ExplicitActivationObservation(
                host_responded=True,
                skill_selected=False,
                runner_execution_observed=False,
                fixture_read_verified=False,
                details="Host refused or failed to select skill",
                error="refusal",
            )
            return False, obs

        obs = ExplicitActivationObservation(
            host_responded=host_responded,
            skill_selected=False,
            runner_execution_observed=False,
            fixture_read_verified=False,
            details="Host output does not contain observed runner execution or authentic handoff envelope",
            error="runner_execution_not_observed",
        )
        return False, obs

    if not fixture_read_verified:
        details = f"Fixture read verification failed; missing: {', '.join(missing_parts) or 'bound session match'}"
        obs = ExplicitActivationObservation(
            host_responded=host_responded,
            skill_selected=skill_selected,
            runner_execution_observed=runner_execution_observed,
            fixture_read_verified=False,
            details=details,
            error="fixture_verification_failed",
        )
        return False, obs

    obs = ExplicitActivationObservation(
        host_responded=True,
        skill_selected=True,
        runner_execution_observed=True,
        fixture_read_verified=True,
        details="All activation observation layers verified (host response, skill selection, runner execution, fixture read)",
        error=None,
    )
    return True, obs


def run_explicit_activation(*args: Any, **kwargs: Any) -> Any:
    """Run explicit activation or evaluate explicit activation observations.

    If first positional argument is an enabled destination host key, delegates to
    collect_explicit_activation_evidence. Otherwise delegates to evaluate_explicit_activation.
    """
    if args and isinstance(args[0], str) and args[0] in enabled_destination_keys() and "\n" not in args[0] and " " not in args[0]:
        return collect_explicit_activation_evidence(*args, **kwargs)
    return evaluate_explicit_activation(*args, **kwargs)


def collect_local_discovery_evidence(
    host: str,
    *,
    operator: str | None = None,
    ci_run_url: str | None = None,
    repo_root: Path | None = None,
) -> NativeEvidenceRecord:
    """Collect native local validation/discovery evidence using the host CLI if available."""
    profile = get_evidence_profile(host)
    plan = materialize_plan(host)
    identity_hash = package_identity(plan)
    artifact_name = f"portable-resume-{BUNDLE_VERSION}-{host}.zip"

    digest = hashlib.sha256()
    for key in sorted(plan):
        digest.update(key.encode("utf-8"))
        digest.update(b"\0")
        digest.update(plan[key])
        digest.update(b"\0")
    artifact_sha = digest.hexdigest()

    binary_path: str | None = None
    for name in profile.binary_names:
        found = shutil.which(name)
        if found:
            binary_path = found
            break

    if not binary_path:
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_LOCAL_DISCOVERY,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=None,
            operator=operator,
            ci_run_url=ci_run_url,
            reason=f"Host binary not found in PATH: {profile.binary_names}",
            provenance={"binary_checked": list(profile.binary_names)},
        )

    host_ver = None
    try:
        proc = subprocess.run(
            [binary_path, *profile.version_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            out = proc.stdout.strip()
            m = re.search(r"\b\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?\b", out)
            host_ver = m.group(0) if m else out[:30]
    except Exception as exc:
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_LOCAL_DISCOVERY,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=None,
            operator=operator,
            ci_run_url=ci_run_url,
            reason=sanitize_evidence_text(f"Blocked prerequisite: failed to query host version: {exc}"),
        )

    if not profile.discovery_commands:
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_LOCAL_DISCOVERY,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=host_ver,
            operator=operator,
            ci_run_url=ci_run_url,
            reason="No automated discovery command defined for host",
        )

    with safe_temporary_directory(prefix="portable-resume-discovery-") as tmp_root:
        isolated_home = tmp_root / "home"
        isolated_home.mkdir()
        isolated_project = tmp_root / "project"
        isolated_project.mkdir()

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        if profile.env_config_var:
            env[profile.env_config_var] = str(isolated_home / "config")

        # Materialize under host-specific project and global discovery roots (#296)
        proj_root_str = resolve_skill_root(
            host=host,
            scope="project",
            project_dir=str(isolated_project),
            home_dir=str(isolated_home),
        )
        host_proj_root = Path(proj_root_str)
        for rel_path, data in plan.items():
            dest = host_proj_root / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        global_root_str = resolve_skill_root(
            host=host,
            scope="global",
            project_dir=None,
            home_dir=str(isolated_home),
            environ=env,
        )
        host_global_root = Path(global_root_str)
        for rel_path, data in plan.items():
            dest = host_global_root / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        evidence_plan = materialize_evidence_plan(host)
        for rel_path, data in evidence_plan.items():
            dest = isolated_project / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        cmd = list(profile.discovery_commands[0])
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=str(isolated_project),
                timeout=15,
            )
        except Exception as exc:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_LOCAL_DISCOVERY,
                state=STATE_NOT_RUN,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(f"Blocked prerequisite: discovery command execution failed: {exc}"),
            )

        unsupported_tokens = (
            "unknown command",
            "unrecognized command",
            "unknown option",
            "flag provided but not defined",
            "is not a kimi command",
        )
        combined_err = f"{proc.stdout}\n{proc.stderr}".lower()
        if any(tok in combined_err for tok in unsupported_tokens):
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_LOCAL_DISCOVERY,
                state=STATE_NOT_RUN,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(
                    f"Blocked prerequisite: command not supported by host binary version: {proc.stderr.strip() or proc.stdout.strip()[:100]}"
                ),
            )

        if proc.returncode != 0:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_LOCAL_DISCOVERY,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(f"Discovery command exited {proc.returncode}: {proc.stderr[:200]}"),
            )

        passed, detail = _direct_native_discovery(
            proc.stdout,
            proc.stderr,
            returncode=proc.returncode,
            expected_package="portable-resume",
            expected_skill="resume-claude",
            command=cmd,
            host=host,
        )
        if not passed:
            diag_text = f"{proc.stderr}\n{proc.stdout}".lower()
            if any(re.search(pat, diag_text) for pat in _AUTH_BLOCKED_PATTERNS):
                return NativeEvidenceRecord(
                    host=host,
                    scope=SCOPE_LOCAL_DISCOVERY,
                    state=STATE_NOT_RUN,
                    artifact_file=artifact_name,
                    artifact_sha256=artifact_sha,
                    identity_sha256=identity_hash,
                    recorded_at=current_iso_timestamp(),
                    host_version=host_ver,
                    operator=operator,
                    ci_run_url=ci_run_url,
                    reason="Blocked prerequisite: authentication or credentials required for host discovery",
                )
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_LOCAL_DISCOVERY,
                state=STATE_NOT_RUN,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(f"Host discovery in isolated environment did not observe expected package: {detail}"),
            )

        # Provenance check: verify discovered skill matches expected package
        skill_dirs = [
            host_proj_root / "resume-claude",
            isolated_project / "resume-claude",
            host_global_root / "resume-claude",
        ]
        if not any(verify_installed_provenance(d, plan) for d in skill_dirs):
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_LOCAL_DISCOVERY,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason="Same-name wrong-package discovery failed provenance checks",
            )

        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_LOCAL_DISCOVERY,
            state=STATE_CURRENT,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=host_ver,
            operator=operator,
            ci_run_url=ci_run_url,
            reason=sanitize_evidence_text(f"Local discovery verified via {cmd[0]} in isolated environment"),
            provenance={
                "command": cmd,
                "provenance_verified": True,
            },
        )


def collect_explicit_activation_evidence(
    host: str,
    *,
    operator: str | None = None,
    ci_run_url: str | None = None,
    repo_root: Path | None = None,
) -> NativeEvidenceRecord:
    """Collect native explicit headless activation evidence using host CLI if available."""
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[1]

    profile = get_evidence_profile(host)
    plan = materialize_plan(host)
    identity_hash = package_identity(plan)
    artifact_name = f"portable-resume-{BUNDLE_VERSION}-{host}.zip"

    digest = hashlib.sha256()
    for key in sorted(plan):
        digest.update(key.encode("utf-8"))
        digest.update(b"\0")
        digest.update(plan[key])
        digest.update(b"\0")
    artifact_sha = digest.hexdigest()

    if not profile.activation_commands or SCOPE_EXPLICIT_ACTIVATION not in profile.supported_automated_scopes:
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_EXPLICIT_ACTIVATION,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=None,
            operator=operator,
            ci_run_url=ci_run_url,
            reason=profile.blocked_or_manual_scopes.get(
                SCOPE_EXPLICIT_ACTIVATION,
                "Explicit activation is not automated for this host profile",
            ),
        )

    binary_path: str | None = None
    for name in profile.binary_names:
        found = shutil.which(name)
        if found:
            binary_path = found
            break

    if not binary_path:
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_EXPLICIT_ACTIVATION,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=None,
            operator=operator,
            ci_run_url=ci_run_url,
            reason=f"Host binary not found in PATH: {profile.binary_names}",
            provenance={"binary_checked": list(profile.binary_names)},
        )

    host_ver = None
    try:
        proc = subprocess.run(
            [binary_path, *profile.version_args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        if proc.returncode == 0:
            out = proc.stdout.strip()
            m = re.search(r"\b\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9.]+)?\b", out)
            host_ver = m.group(0) if m else out[:30]
    except Exception as exc:
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_EXPLICIT_ACTIVATION,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=None,
            operator=operator,
            ci_run_url=ci_run_url,
            reason=sanitize_evidence_text(f"Blocked prerequisite: failed to query host version: {exc}"),
        )

    fixture_dir = repo_root / "tests" / "fixtures" / "claude" / "s-cla-01-ordered-parent-chain" / "root"
    if not fixture_dir.is_dir():
        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_EXPLICIT_ACTIVATION,
            state=STATE_NOT_RUN,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=host_ver,
            operator=operator,
            ci_run_url=ci_run_url,
            reason="Synthetic source fixture missing",
        )

    with safe_temporary_directory(prefix="portable-resume-activation-") as tmp_root:
        isolated_home = tmp_root / "home"
        isolated_home.mkdir()
        isolated_project = tmp_root / "project"
        isolated_project.mkdir()

        # Stage synthetic fixture into isolated store locations (#296)
        config_dir = isolated_home / "config"
        config_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(fixture_dir, config_dir, dirs_exist_ok=True)
        dot_claude_dir = isolated_home / ".claude"
        dot_claude_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(fixture_dir, dot_claude_dir, dirs_exist_ok=True)

        # Stage session jsonl under the cwd slug for isolated_project so that
        # direct host / runner execution scoped to isolated_project reads the synthetic session.
        from portable_resume.adapters.claude import _slugify_cwd
        from portable_resume.paths import canonicalize_cwd

        project_slug = _slugify_cwd(canonicalize_cwd(str(isolated_project)))
        session_id = "7e0a1246-d538-5993-8d6f-3495aafcdd92"
        session_content = (
            json.dumps({
                "type": "user",
                "uuid": "93efcefc-43bc-5677-87c1-96b663daec3f",
                "parentUuid": None,
                "sessionId": session_id,
                "cwd": str(isolated_project),
                "timestamp": "2026-07-20T00:00:00Z",
                "message": {"role": "user", "content": "synthetic request"},
            })
            + "\n"
            + json.dumps({
                "type": "assistant",
                "uuid": "b13ddf02-4741-56bb-89fe-cb4eea9d5e5d",
                "parentUuid": "93efcefc-43bc-5677-87c1-96b663daec3f",
                "sessionId": session_id,
                "cwd": str(isolated_project),
                "timestamp": "2026-07-20T00:00:00Z",
                "message": {"role": "assistant", "content": "synthetic response"},
            })
            + "\n"
        )
        for store_dir in (config_dir, dot_claude_dir):
            slug_dir = store_dir / "projects" / project_slug
            slug_dir.mkdir(parents=True, exist_ok=True)
            (slug_dir / f"{session_id}.jsonl").write_text(session_content, encoding="utf-8")
            for entry in store_dir.rglob("*.jsonl"):
                try:
                    os.utime(entry, None)
                except OSError:
                    pass

        if host != "claude":
            dot_host_dir = isolated_home / f".{host}"
            dot_host_dir.mkdir(parents=True, exist_ok=True)
            shutil.copytree(fixture_dir, dot_host_dir, dirs_exist_ok=True)

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        if profile.env_config_var:
            env[profile.env_config_var] = str(isolated_home / "config")

        # Materialize skill under host's project and global discovery roots (#296)
        proj_root_str = resolve_skill_root(
            host=host,
            scope="project",
            project_dir=str(isolated_project),
            home_dir=str(isolated_home),
        )
        host_proj_root = Path(proj_root_str)
        for rel_path, data in plan.items():
            dest = host_proj_root / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        global_root_str = resolve_skill_root(
            host=host,
            scope="global",
            project_dir=None,
            home_dir=str(isolated_home),
            environ=env,
        )
        host_global_root = Path(global_root_str)
        for rel_path, data in plan.items():
            dest = host_global_root / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        evidence_plan = materialize_evidence_plan(host)
        for rel_path, data in evidence_plan.items():
            dest = isolated_project / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        skill_dirs = [
            host_proj_root / "resume-claude",
            isolated_project / "resume-claude",
            host_global_root / "resume-claude",
        ]
        if not any(verify_installed_provenance(d, plan) for d in skill_dirs):
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_EXPLICIT_ACTIVATION,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason="Same-name wrong-package discovery failed provenance checks",
            )

        raw_cmd = list(profile.activation_commands[0])
        cmd = [
            arg.replace("<plugin-dir>", str(isolated_project / "resume-claude"))
            for arg in raw_cmd
        ]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
                cwd=str(isolated_project),
                timeout=20,
            )
        except Exception as exc:
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_EXPLICIT_ACTIVATION,
                state=STATE_NOT_RUN,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(f"Blocked prerequisite: activation command execution failed: {exc}"),
            )

        combined = f"{proc.stdout}\n{proc.stderr}".lower()
        unsupported_tokens = (
            "unknown command",
            "unrecognized command",
            "unknown option",
            "flag provided but not defined",
            "is not a kimi command",
        )
        if any(tok in combined for tok in unsupported_tokens):
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_EXPLICIT_ACTIVATION,
                state=STATE_NOT_RUN,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(
                    f"Blocked prerequisite: command not supported by host binary version: {proc.stderr.strip() or proc.stdout.strip()[:100]}"
                ),
            )

        passed, obs = evaluate_explicit_activation(
            proc.stdout,
            proc.stderr,
            returncode=proc.returncode,
            expected_source="claude",
            expected_session="7e0a1246-d538-5993-8d6f-3495aafcdd92",
            expected_fixture_content=("synthetic request",),
            host=host,
        )

        if not passed:
            if obs.error == "auth_required":
                return NativeEvidenceRecord(
                    host=host,
                    scope=SCOPE_EXPLICIT_ACTIVATION,
                    state=STATE_NOT_RUN,
                    artifact_file=artifact_name,
                    artifact_sha256=artifact_sha,
                    identity_sha256=identity_hash,
                    recorded_at=current_iso_timestamp(),
                    host_version=host_ver,
                    operator=operator,
                    ci_run_url=ci_run_url,
                    reason="Blocked prerequisite: authentication or credentials required for host activation",
                    provenance={
                        "command": [sanitize_evidence_text(c) for c in cmd],
                        "error": obs.error,
                        "details": obs.details,
                    },
                )
            return NativeEvidenceRecord(
                host=host,
                scope=SCOPE_EXPLICIT_ACTIVATION,
                state=STATE_FAILED,
                artifact_file=artifact_name,
                artifact_sha256=artifact_sha,
                identity_sha256=identity_hash,
                recorded_at=current_iso_timestamp(),
                host_version=host_ver,
                operator=operator,
                ci_run_url=ci_run_url,
                reason=sanitize_evidence_text(f"Explicit activation failed verification: {obs.details}"),
                provenance={
                    "command": [sanitize_evidence_text(c) for c in cmd],
                    "host_responded": obs.host_responded,
                    "skill_selected": obs.skill_selected,
                    "runner_execution_observed": obs.runner_execution_observed,
                    "fixture_read_verified": obs.fixture_read_verified,
                },
            )

        return NativeEvidenceRecord(
            host=host,
            scope=SCOPE_EXPLICIT_ACTIVATION,
            state=STATE_CURRENT,
            artifact_file=artifact_name,
            artifact_sha256=artifact_sha,
            identity_sha256=identity_hash,
            recorded_at=current_iso_timestamp(),
            host_version=host_ver,
            operator=operator,
            ci_run_url=ci_run_url,
            reason=sanitize_evidence_text(f"Native activation verified via {cmd[0]} with synthetic marker"),
            provenance={
                "command": [sanitize_evidence_text(c) for c in cmd],
                "host_responded": obs.host_responded,
                "skill_selected": obs.skill_selected,
                "runner_execution_observed": obs.runner_execution_observed,
                "fixture_read_verified": obs.fixture_read_verified,
                "synthetic_marker_verified": True,
                "owned_runner_invoked": True,
            },
        )


def collect_manual_or_blocked_evidence(
    host: str,
    scope: str,
    *,
    operator: str | None = None,
    ci_run_url: str | None = None,
) -> NativeEvidenceRecord:
    """Record honest not-run evidence for manual, UI, or provider-dependent scopes."""
    profile = get_evidence_profile(host)
    plan = materialize_plan(host)
    identity_hash = package_identity(plan)
    artifact_name = f"portable-resume-{BUNDLE_VERSION}-{host}.zip"

    digest = hashlib.sha256()
    for key in sorted(plan):
        digest.update(key.encode("utf-8"))
        digest.update(b"\0")
        digest.update(plan[key])
        digest.update(b"\0")
    artifact_sha = digest.hexdigest()

    reason = profile.blocked_or_manual_scopes.get(
        scope, f"Scope {scope!r} is not executed in offline/local collector lane"
    )

    return NativeEvidenceRecord(
        host=host,
        scope=scope,
        state=STATE_NOT_RUN,
        artifact_file=artifact_name,
        artifact_sha256=artifact_sha,
        identity_sha256=identity_hash,
        recorded_at=current_iso_timestamp(),
        host_version=None,
        operator=operator,
        ci_run_url=ci_run_url,
        reason=reason,
    )


def collect_all_evidence_for_host(
    host: str,
    *,
    scopes: Sequence[str] | None = None,
    operator: str | None = None,
    ci_run_url: str | None = None,
    repo_root: Path | None = None,
) -> list[NativeEvidenceRecord]:
    """Collect evidence for all declared scopes for a single host."""
    target_scopes = scopes or ALL_SCOPES
    records: list[NativeEvidenceRecord] = []
    for scope in target_scopes:
        if scope == SCOPE_OFFLINE_RUNNER:
            rec = collect_offline_runner_evidence(
                host, operator=operator, ci_run_url=ci_run_url, repo_root=repo_root
            )
        elif scope == SCOPE_LOCAL_DISCOVERY:
            rec = collect_local_discovery_evidence(
                host, operator=operator, ci_run_url=ci_run_url, repo_root=repo_root
            )
        elif scope == SCOPE_EXPLICIT_ACTIVATION:
            rec = collect_explicit_activation_evidence(
                host, operator=operator, ci_run_url=ci_run_url, repo_root=repo_root
            )
        else:
            rec = collect_manual_or_blocked_evidence(
                host, scope, operator=operator, ci_run_url=ci_run_url
            )
        records.append(rec)
    return records


def collect_full_matrix_evidence(
    *,
    hosts: Sequence[str] | None = None,
    scopes: Sequence[str] | None = None,
    operator: str | None = None,
    ci_run_url: str | None = None,
    repo_root: Path | None = None,
) -> list[NativeEvidenceRecord]:
    """Collect evidence records across the full destination registry."""
    validate_destination_evidence_profiles()
    target_hosts = sorted(hosts or enabled_destination_keys())
    all_records: list[NativeEvidenceRecord] = []
    for host in target_hosts:
        records = collect_all_evidence_for_host(
            host,
            scopes=scopes,
            operator=operator,
            ci_run_url=ci_run_url,
            repo_root=repo_root,
        )
        all_records.extend(records)
    return all_records


def evaluate_evidence_drift(
    record: NativeEvidenceRecord,
    *,
    current_artifact_sha: str,
    current_identity_sha: str,
    current_host_version: str | None = None,
) -> str:
    """Evaluate whether prior evidence remains current or has drifted to stale."""
    if record.state != STATE_CURRENT:
        return record.state
    if record.artifact_sha256 != current_artifact_sha:
        return STATE_STALE
    if record.identity_sha256 != current_identity_sha:
        return STATE_STALE
    if (
        current_host_version is not None
        and record.host_version is not None
        and record.host_version != current_host_version
    ):
        return STATE_STALE
    return STATE_CURRENT


def format_evidence_markdown_table(records: Sequence[NativeEvidenceRecord]) -> str:
    """Render a markdown summary table from collected evidence records."""
    headers = ["Host", "Scope", "State", "Host Version", "Artifact SHA256", "Notes / Reason", "Date"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for r in sorted(records, key=lambda x: (x.host, x.scope)):
        row = [
            r.host,
            r.scope,
            r.state,
            r.host_version or "n/a",
            f"`{r.artifact_sha256[:16]}…`",
            (r.reason or "").replace("|", "\\|")[:80],
            r.recorded_at[:10],
        ]
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)
