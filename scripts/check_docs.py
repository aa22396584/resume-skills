#!/usr/bin/env python3
"""Validate multilingual quick-start coverage and canonical install commands."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
if str(SRC) in sys.path:
    sys.path.remove(str(SRC))
sys.path.insert(0, str(SRC))
if str(REPO) not in sys.path:
    sys.path.insert(1, str(REPO))

from portable_resume import __version__  # noqa: E402
from portable_resume.diagnostics import ERROR_EXIT_CODES, WARNING_CODES  # noqa: E402
from portable_resume.install.catalog import host_catalog_snapshot  # noqa: E402
from portable_resume.registry import (  # noqa: E402
    enabled_destination_keys,
    enabled_source_keys,
)
try:  # Direct script execution puts scripts/ rather than the repo root on sys.path.
    from scripts import render_docs  # type: ignore[no-redef]  # noqa: E402
except (ImportError, ModuleNotFoundError):
    import render_docs  # type: ignore[no-redef]  # noqa: E402

LOCALES = {
    "ar": "العربية",
    "de": "Deutsch",
    "en": "English",
    "es": "Español",
    "fr": "Français",
    "hi": "हिन्दी",
    "ja": "日本語",
    "ko": "한국어",
    "pt-BR": "Português (Brasil)",
    "ru": "Русский",
    "zh-CN": "简体中文",
    "zh-TW": "繁體中文",
}
REQUIRED_COMMANDS = (
    "pipx install portable-resume",
    "install-resume-skills quick-install qwen",
    "install-resume-skills quick-install all",
    "claude plugin marketplace add ImL1s/portable-resume-marketplace",
    "python3 scripts/self_verify.py",
)
REQUIRED_LINKS = (
    "../install-hosts.md",
    "../STATUS.md",
    "https://github.com/ImL1s/portable-resume-marketplace",
)
# Plan 042 generates registry structure/counts only. These evidence claims remain
# human-recorded truth and must never be inferred by scripts/render_docs.py.
REQUIRED_EVIDENCE_MARKERS = (
    "8/8",
    "7/7",
    "6/6",
)
EVIDENCE_SCOPE_MARKER = (
    "<!-- portable-resume-evidence-scope: "
    "v0.3.2-hosts v0.4.1-host-reinstall-not-run -->"
)
ROOT_INSTALLED_COMMANDS = (
    "portable-resume --version",
    "install-resume-skills --version",
    "portable-resume self-check --json",
    "install-resume-skills matrix",
    "install-resume-skills hosts --json",
    "install-resume-skills install \\",
    "install-resume-skills verify \\",
)
_COUNT_TOKEN = re.compile(
    r"\b(?:zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|"
    r"twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|"
    r"twenty|hundred|thousand|\d+)\b",
    re.IGNORECASE,
)
_COUNTS_MARKER = re.compile(
    r"<!-- portable-resume-counts: sources=(\d+) destinations=(\d+) -->"
)
_CURRENT_REGISTRY_BEGIN = "<!-- portable-resume-current-registry:begin -->"
_CURRENT_REGISTRY_END = "<!-- portable-resume-current-registry:end -->"
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)


def _host_names() -> tuple[str, ...]:
    return tuple(host["display_name"] for host in host_catalog_snapshot()["hosts"])


def _current_registry_facts(text: str) -> str | None:
    if (
        text.count(_CURRENT_REGISTRY_BEGIN) != 1
        or text.count(_CURRENT_REGISTRY_END) != 1
    ):
        return None
    pattern = re.compile(
        re.escape(_CURRENT_REGISTRY_BEGIN)
        + r"(.*?)"
        + re.escape(_CURRENT_REGISTRY_END),
        re.DOTALL,
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        return None
    return _HTML_COMMENT.sub("", matches[0])


def _check_root_docs(failures: list[str], root_readme: str) -> None:
    source_count = len(enabled_source_keys())
    destination_count = len(enabled_destination_keys())
    current_counts = f"{source_count} sources × {destination_count} hosts"
    if f"{current_counts} (derived from registries)" not in root_readme:
        failures.append(
            f"README.md: current registry counts must be {current_counts}"
        )

    hero_match = re.search(
        r'<img\s+src="docs/assets/portable-resume-skills-hero-v2\.jpg"\s+'
        r'alt="([^"]*)"',
        root_readme,
    )
    if hero_match is None or _COUNT_TOKEN.search(hero_match.group(1)):
        failures.append("README.md: hero alt text must be count-free")

    installed_heading = "Installed (pipx/pip):"
    checkout_heading = "From a source checkout (no install):"
    installed_start = root_readme.find(installed_heading)
    checkout_start = root_readme.find(checkout_heading)
    if installed_start < 0 or checkout_start <= installed_start:
        failures.append("README.md: missing installed (pipx/pip) command section")
    else:
        installed_section = root_readme[installed_start:checkout_start]
        for command in ROOT_INSTALLED_COMMANDS:
            if command not in installed_section:
                failures.append(
                    f"README.md: installed command section missing {command!r}"
                )

    install_hosts = (REPO / "docs" / "install-hosts.md").read_text(encoding="utf-8")
    quick_install_line = next(
        (
            line
            for line in install_hosts.splitlines()
            if "install-resume-skills quick-install all" in line
        ),
        "",
    )
    comment = quick_install_line.partition("#")[2]
    if not comment or "registry" not in comment.lower() or _COUNT_TOKEN.search(comment):
        failures.append(
            "docs/install-hosts.md: quick-install all comment must be registry-derived"
        )

    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = [line for line in changelog.splitlines() if line.startswith("#")]
    if (
        not headings
        or headings[0] != "# Changelog"
        or headings.count("# Changelog") != 1
        or headings.count("## Unreleased") != 1
        or headings.index("# Changelog") > headings.index("## Unreleased")
    ):
        failures.append(
            "CHANGELOG.md: expected one H1 followed by one Unreleased section"
        )


def _check_diagnostics_reference(failures: list[str]) -> None:
    path = REPO / "docs" / "diagnostics.md"
    if not path.is_file():
        failures.append("docs/diagnostics.md: missing")
        return
    text = path.read_text(encoding="utf-8")
    missing = [
        code
        for code in (*ERROR_EXIT_CODES, *sorted(WARNING_CODES))
        if code not in text
    ]
    if missing:
        failures.append(f"docs/diagnostics.md: missing codes: {missing}")


def _check_status_current_matrix(failures: list[str]) -> None:
    """Require STATUS packaging/installed-runner rows match live registry counts.

    Historical products (e.g. published ``0.3.4`` **9×9=81**) may remain in the
    same row when labeled historical; only the *current main tip* product is gated.
    """

    path = REPO / "docs" / "STATUS.md"
    if not path.is_file():
        failures.append("docs/STATUS.md: missing")
        return
    text = path.read_text(encoding="utf-8")
    source_count = len(enabled_source_keys())
    destination_count = len(enabled_destination_keys())
    cells = source_count * destination_count
    expected_ratio = f"{cells}/{cells}"
    expected_product = f"{source_count}×{destination_count}"
    for label in ("Packaging matrix", "Installed runner matrix"):
        row = next(
            (
                line
                for line in text.splitlines()
                if line.startswith(f"| {label} |")
            ),
            None,
        )
        if row is None:
            failures.append(f"docs/STATUS.md: missing gate row for {label}")
            continue
        if expected_ratio not in row:
            failures.append(
                f"docs/STATUS.md: {label} row must claim current "
                f"{expected_ratio} (live registry cells)"
            )
        if expected_product not in row:
            failures.append(
                f"docs/STATUS.md: {label} row must include current product "
                f"{expected_product}"
            )
        lowered = row.lower()
        if "derived from registries" not in lowered and "registry-derived" not in lowered:
            failures.append(
                f"docs/STATUS.md: {label} row must note registry-derived counts"
            )
        if "current main" not in lowered and "on main" not in lowered:
            failures.append(
                f"docs/STATUS.md: {label} row must scope the live product to current main"
            )


def _check_repository_metadata(failures: list[str]) -> None:
    path = REPO / "docs" / "metadata" / "repository-metadata.json"
    if not path.is_file():
        failures.append("docs/metadata/repository-metadata.json: missing")
        return
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        failures.append(f"docs/metadata/repository-metadata.json: invalid JSON: {exc}")
        return

    if data.get("schema_version") != "portable-resume/repo-metadata-v1":
        failures.append(
            "docs/metadata/repository-metadata.json: expected schema_version 'portable-resume/repo-metadata-v1'"
        )

    description = data.get("description", "")
    if not isinstance(description, str) or not description.strip():
        failures.append(
            "docs/metadata/repository-metadata.json: description must be a non-empty string"
        )
    else:
        stale_patterns = (
            r"\b9\s*[x×]\s*9\b",
            r"\b81\b",
            r"\b9\s+sources\b",
            r"\b9\s+destinations\b",
            r"\b81\s+cells\b",
        )
        for pat in stale_patterns:
            if re.search(pat, description, re.IGNORECASE):
                failures.append(
                    f"docs/metadata/repository-metadata.json: description contains stale claim: {pat}"
                )
        desc_lower = description.lower()
        for boundary in ("offline", "fresh session", "not live"):
            if boundary not in desc_lower:
                failures.append(
                    f"docs/metadata/repository-metadata.json: description missing boundary phrase {boundary!r}"
                )
        if "kilo" in desc_lower and "source" in desc_lower:
            failures.append(
                "docs/metadata/repository-metadata.json: description must not claim Kilo as an enabled source"
            )

    homepage = data.get("homepage", "")
    if not isinstance(homepage, str) or not homepage.startswith(
        "https://github.com/ImL1s/resume-skills"
    ):
        failures.append(
            "docs/metadata/repository-metadata.json: homepage must point to repository"
        )

    topics = data.get("topics")
    if (
        not isinstance(topics, list)
        or not topics
        or not all(isinstance(t, str) and t.strip() for t in topics)
    ):
        failures.append(
            "docs/metadata/repository-metadata.json: topics must be a non-empty list of strings"
        )
    else:
        for topic in topics:
            if not re.match(r"^[a-z0-9-]+$", topic):
                failures.append(
                    f"docs/metadata/repository-metadata.json: topic must be kebab-case: {topic!r}"
                )


def _check_current_release_prose(failures: list[str], root_readme: str) -> None:
    latest_release_path = REPO / "src" / "portable_resume" / "resources" / "latest-release.json"
    published_ver = None
    if latest_release_path.is_file():
        try:
            rel_data = json.loads(latest_release_path.read_text(encoding="utf-8"))
            published_ver = rel_data.get("version")
        except Exception:
            pass

    match = re.search(
        r"\*\*Current release:\*\*\s+\[`([^`]+)`\]\(https://github\.com/[^/]+/[^/]+/releases/tag/v([^)]+)\)",
        root_readme,
    )
    if not match:
        failures.append("README.md: missing Current release link marker")
        return
    current_ver, tag_ver = match.group(1), match.group(2)
    if current_ver != tag_ver:
        failures.append(
            f"README.md: current release link text {current_ver} does not match tag v{tag_ver}"
        )
    if published_ver and current_ver != published_ver:
        failures.append(
            f"README.md: current release link version {current_ver} does not match published version {published_ver} from latest-release.json"
        )

    target_ver = published_ver or current_ver
    expected_tag_url = f"https://github.com/ImL1s/resume-skills/releases/tag/v{target_ver}"
    index_path = REPO / "docs" / "i18n" / "README.md"
    if index_path.is_file():
        text = index_path.read_text(encoding="utf-8")
        if expected_tag_url not in text:
            failures.append(
                f"docs/i18n/README.md: must link to current published release v{target_ver}"
            )
    for locale in LOCALES:
        loc_path = REPO / "docs" / "i18n" / f"{locale}.md"
        if not loc_path.is_file():
            continue
        text = loc_path.read_text(encoding="utf-8")
        if expected_tag_url not in text:
            failures.append(
                f"docs/i18n/{locale}.md: must link to current published release v{target_ver}"
            )


def _check_source_formats_summary(failures: list[str]) -> None:
    path = REPO / "docs" / "source-formats.md"
    if not path.is_file():
        failures.append("docs/source-formats.md: missing")
        return
    text = path.read_text(encoding="utf-8")
    source_name_markers = {
        "claude": "Claude",
        "codex": "Codex",
        "cursor": "Cursor",
        "opencode": "OpenCode",
        "antigravity": "Antigravity",
        "grok": "Grok",
        "qwen": "Qwen",
        "kimi": "Kimi",
        "pi": "Pi",
        "openclaw": "OpenClaw",
        "goose": "goose",
        "crush": "Crush",
        "cline": "Cline",
        "openhands": "OpenHands",
        "hermes": "Hermes",
        "github-copilot": "GitHub Copilot",
        "gemini": "Gemini",
    }
    for src in enabled_source_keys():
        name = source_name_markers.get(src, src)
        row_match = re.search(rf"\|\s*{re.escape(name)}\b", text)
        if not row_match:
            failures.append(
                f"docs/source-formats.md: summary table missing enabled source {src!r}"
            )

    lowered = text.lower()
    if (
        "kilo" in lowered
        and "destination-only" not in lowered
        and "research" not in lowered
    ):
        failures.append(
            "docs/source-formats.md: Kilo must be marked research/destination-only"
        )


def _check_native_activation_policy(failures: list[str]) -> None:
    path = REPO / "docs" / "evidence" / "native-activation-policy-v1.md"
    if not path.is_file():
        failures.append("docs/evidence/native-activation-policy-v1.md: missing")
        return
    text = path.read_text(encoding="utf-8").lower()
    if "is not shipped" in text or "until #125 lands" in text:
        failures.append(
            "docs/evidence/native-activation-policy-v1.md: active policy must not claim Windows mutating install is unimplemented"
        )


def check_live_metadata() -> list[str]:
    """Optional maintainer check comparing live GitHub About to tracked metadata."""
    metadata_path = REPO / "docs" / "metadata" / "repository-metadata.json"
    if not metadata_path.is_file():
        return ["docs/metadata/repository-metadata.json: missing"]
    try:
        tracked = json.loads(metadata_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"docs/metadata/repository-metadata.json: invalid JSON: {exc}"]

    import shutil
    import subprocess

    if not shutil.which("gh"):
        print("INFO: 'gh' CLI not found; skipping live repository check", file=sys.stderr)
        return []

    res = subprocess.run(
        ["gh", "repo", "view", "--json", "description,homepageUrl,repositoryTopics"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        print(
            f"INFO: 'gh repo view' failed ({res.stderr.strip()}); skipping live check",
            file=sys.stderr,
        )
        return []

    try:
        live = json.loads(res.stdout)
    except Exception as exc:
        return [f"live repo metadata: failed to parse JSON: {exc}"]

    failures: list[str] = []
    tracked_desc = tracked.get("description", "").strip()
    live_desc = live.get("description", "").strip()
    if tracked_desc != live_desc:
        failures.append(
            f"live description mismatch:\n  tracked: {tracked_desc}\n  live:    {live_desc}"
        )

    tracked_home = tracked.get("homepage", "").strip().rstrip("/")
    live_home = (live.get("homepageUrl") or "").strip().rstrip("/")
    if tracked_home != live_home:
        failures.append(
            f"live homepage mismatch:\n  tracked: {tracked_home}\n  live:    {live_home}"
        )

    tracked_topics = set(tracked.get("topics") or [])
    live_topics = {t["name"] for t in (live.get("repositoryTopics") or [])}
    if tracked_topics != live_topics:
        missing = sorted(tracked_topics - live_topics)
        unexpected = sorted(live_topics - tracked_topics)
        failures.append(
            f"live topics mismatch:\n  missing from live:   {missing}\n  unexpected on live: {unexpected}"
        )

    return failures


def check() -> dict[str, object]:
    failures: list[str] = []
    root_readme = (REPO / "README.md").read_text(encoding="utf-8")
    _check_root_docs(failures, root_readme)
    _check_diagnostics_reference(failures)
    _check_status_current_matrix(failures)
    _check_repository_metadata(failures)
    _check_current_release_prose(failures, root_readme)
    _check_source_formats_summary(failures)
    _check_native_activation_policy(failures)
    if "docs/i18n/README.md" not in root_readme:
        failures.append("README.md: missing multilingual documentation link")

    index_path = REPO / "docs" / "i18n" / "README.md"
    if not index_path.is_file():
        failures.append("docs/i18n/README.md: missing")
        index = ""
    else:
        index = index_path.read_text(encoding="utf-8")

    source_count = len(enabled_source_keys())
    destination_count = len(enabled_destination_keys())
    host_names = _host_names()
    checked: list[str] = []
    for locale, label in LOCALES.items():
        relative = f"./{locale}.md"
        if relative not in index or label not in index:
            failures.append(f"docs/i18n/README.md: missing {locale} index entry")
        path = REPO / "docs" / "i18n" / f"{locale}.md"
        if not path.is_file():
            failures.append(f"docs/i18n/{locale}.md: missing")
            continue
        text = path.read_text(encoding="utf-8")
        checked.append(locale)
        rel = path.relative_to(REPO).as_posix()
        marker = f"<!-- portable-resume-i18n: {locale} v{__version__} -->"
        if marker not in text:
            failures.append(f"{rel}: missing current version marker")
        count_markers = _COUNTS_MARKER.findall(text)
        expected_counts = (str(source_count), str(destination_count))
        if count_markers != [expected_counts]:
            failures.append(
                f"{rel}: counts marker must be "
                f"sources={source_count} destinations={destination_count}"
            )
        current_facts = _current_registry_facts(text)
        if current_facts is None:
            failures.append(
                f"{rel}: expected exactly one current registry facts region"
            )
        else:
            if re.search(
                rf"(?<!\d){destination_count}(?!\d)", current_facts
            ) is None:
                failures.append(
                    f"{rel}: current registry facts must mention "
                    f"destination count {destination_count}"
                )
            for host in host_names:
                if host not in current_facts:
                    failures.append(
                        f"{rel}: current registry facts missing host {host}"
                    )
        for command in REQUIRED_COMMANDS:
            if command not in text:
                failures.append(f"{rel}: missing command {command!r}")
        for link in REQUIRED_LINKS:
            if link not in text:
                failures.append(f"{rel}: missing link {link!r}")
        for marker in REQUIRED_EVIDENCE_MARKERS:
            if marker not in text:
                failures.append(
                    f"{rel}: missing evidence marker {marker!r}"
                )
        if EVIDENCE_SCOPE_MARKER not in text:
            failures.append(
                f"{rel}: missing version-scoped host evidence marker"
            )

    for failure in render_docs.assert_matrix_consistent(REPO):
        # assert_matrix_consistent already prefixes generated-region failures.
        if failure.startswith("generated docs drift"):
            failures.append(failure)
        else:
            failures.append(f"matrix consistency: {failure}")

    return {
        "ok": not failures,
        "version": __version__,
        "required_locale_count": len(LOCALES),
        "source_count": len(enabled_source_keys()),
        "destination_count": len(enabled_destination_keys()),
        "matrix_cells": len(enabled_source_keys()) * len(enabled_destination_keys()),
        "checked_locales": checked,
        "failures": failures,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--check-live-metadata",
        action="store_true",
        help="Compare live GitHub About against tracked repository-metadata.json",
    )
    namespace = parser.parse_args(argv)
    report = check()
    live_failures: list[str] = []
    if namespace.check_live_metadata:
        live_failures = check_live_metadata()
        if live_failures:
            report["failures"].extend(live_failures)
            report["ok"] = False
    if namespace.json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    elif report["ok"]:
        print(
            "DOCS_CHECK PASS "
            f"locales={report['required_locale_count']} version={report['version']}"
        )
    else:
        print("DOCS_CHECK FAIL", file=sys.stderr)
        for failure in report["failures"]:
            print(f" - {failure}", file=sys.stderr)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
