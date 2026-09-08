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
from portable_resume.diagnostics import SOURCE_KEYS
from portable_resume.registry import (
    DESTINATION_PROFILES,
    enabled_destination_keys,
    enabled_source_keys,
)
from portable_resume.install.catalog import HOST_PROFILES
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
        "discovery_commands": (("agy", "plugin", "validate", "."),),
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
        "discovery_commands": (("grok", "plugin", "validate"),),
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
        repo_root = Path(__file__).resolve().parents[3]

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

        evidence_plan = materialize_evidence_plan(host)
        for rel_path, data in evidence_plan.items():
            dest = isolated_project / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        if profile.env_config_var:
            env[profile.env_config_var] = str(isolated_home / "config")

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

        combined_err = f"{proc.stdout}\n{proc.stderr}".lower()
        # Check for authentication or prerequisite blocks
        auth_tokens = ("auth", "login", "api key", "unauthorized", "sign in", "token", "permission")
        if any(tok in combined_err for tok in auth_tokens):
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

        unsupported_tokens = (
            "unknown command",
            "unrecognized command",
            "unknown option",
            "flag provided but not defined",
            "is not a kimi command",
        )
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

        out_lower = proc.stdout.lower()
        valid_discovery = (
            "resume-claude" in out_lower
            or "portable-resume" in out_lower
            or "skills" in out_lower
            or "[ok]" in out_lower
        )
        if not valid_discovery:
            # If the command succeeded but the host did not list skills because registration is required
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
                reason="Host discovery executed in isolated environment; skill not yet registered in isolated profile",
            )

        # Provenance check: verify discovered skill matches expected package
        if not verify_installed_provenance(isolated_project / "resume-claude", plan):
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
        repo_root = Path(__file__).resolve().parents[3]

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

        evidence_plan = materialize_evidence_plan(host)
        for rel_path, data in evidence_plan.items():
            dest = isolated_project / rel_path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)

        if not verify_installed_provenance(isolated_project / "resume-claude", plan):
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

        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(isolated_home),
            "USERPROFILE": str(isolated_home),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        }
        if profile.env_config_var:
            env[profile.env_config_var] = str(isolated_home / "config")

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
        auth_tokens = ("auth", "login", "api key", "unauthorized", "sign in", "token", "permission")
        if any(tok in combined for tok in auth_tokens):
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
            )

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

        if proc.returncode != 0:
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
                reason=sanitize_evidence_text(f"Activation command exited {proc.returncode}: {proc.stderr[:200]}"),
            )

        synthetic_marker = "synthetic request"
        if synthetic_marker not in proc.stdout.lower() and "untrusted" not in proc.stdout.lower():
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
                reason="Activation output did not contain expected synthetic marker or untrusted banner",
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
                "command": cmd,
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
