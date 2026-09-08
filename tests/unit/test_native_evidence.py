"""Unit tests for native host install and activation evidence collector.

Policy: docs/evidence/native-activation-policy-v1.md
Issue: #286
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scripts.native_evidence import (
    ALL_SCOPES,
    ALLOWED_STATES,
    EVIDENCE_SCHEMA_VERSION,
    SCOPE_EXPLICIT_ACTIVATION,
    SCOPE_LOCAL_DISCOVERY,
    SCOPE_MARKETPLACE_INSTALL,
    SCOPE_NL_SELECTION,
    SCOPE_OFFLINE_RUNNER,
    SCOPE_VISUAL_PICKER,
    STATE_CURRENT,
    STATE_FAILED,
    STATE_NOT_RUN,
    STATE_STALE,
    _PROFILE_SPECS,
    NativeEvidenceRecord,
    evaluate_evidence_drift,
    format_evidence_markdown_table,
    get_evidence_profile,
    materialize_evidence_plan,
    safe_temporary_directory,
    sanitize_evidence_text,
    validate_destination_evidence_profiles,
    verify_installed_provenance,
)
from portable_resume.registry import enabled_destination_keys


class NativeEvidenceTests(unittest.TestCase):
    def test_registry_coverage_all_destinations_profiled(self) -> None:
        """Every enabled destination from the registry must have an evidence profile."""
        enabled = enabled_destination_keys()
        self.assertEqual(len(enabled), 18)
        # Must not raise
        validate_destination_evidence_profiles()

    def test_profile_declaration_missing_host_fails(self) -> None:
        """Removing a host profile must fail closed."""
        with mock.patch.dict(_PROFILE_SPECS):
            del _PROFILE_SPECS["claude"]
            with self.assertRaises(ValueError) as ctx:
                validate_destination_evidence_profiles()
            self.assertIn("claude", str(ctx.exception))

    def test_profile_declaration_missing_scope_fails(self) -> None:
        """Profile missing an explicit scope declaration must fail closed."""
        with mock.patch.dict(_PROFILE_SPECS):
            spec = dict(_PROFILE_SPECS["claude"])
            # Remove a scope from both supported and blocked
            spec["supported_automated_scopes"] = (SCOPE_OFFLINE_RUNNER,)
            spec["blocked_or_manual_scopes"] = {}
            _PROFILE_SPECS["claude"] = spec
            with self.assertRaises(ValueError) as ctx:
                validate_destination_evidence_profiles()
            self.assertIn("claude", str(ctx.exception))
            self.assertIn("missing scope", str(ctx.exception).lower())

    def test_profile_archive_surfaces_honesty(self) -> None:
        """Only the 7 reviewed archive destinations declare native package profiles."""
        archive_hosts = {"claude", "codex", "cursor", "antigravity", "grok", "qwen", "kimi"}
        for host in enabled_destination_keys():
            prof = get_evidence_profile(host)
            if host in archive_hosts:
                self.assertTrue(prof.has_native_package, f"{host} must have native package")
                self.assertIsNotNone(prof.native_package_profile)
            else:
                self.assertFalse(prof.has_native_package, f"{host} must be direct-skill only")
                self.assertIsNone(prof.native_package_profile)

        # Kilo must be direct-skill destination-only
        kilo_prof = get_evidence_profile("kilo")
        self.assertFalse(kilo_prof.has_native_package)
        self.assertIn("Destination-only", kilo_prof.notes)

    def test_record_validation_states_and_scopes(self) -> None:
        """NativeEvidenceRecord enforces schema, closed state enum, and scopes."""
        record = NativeEvidenceRecord(
            host="claude",
            scope=SCOPE_OFFLINE_RUNNER,
            state=STATE_CURRENT,
            artifact_file="test.zip",
            artifact_sha256="a" * 64,
            identity_sha256="b" * 64,
            recorded_at="2026-09-08T00:00:00Z",
        )
        record.validate()
        d = record.to_dict()
        self.assertEqual(d["schema_version"], EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(d["state"], STATE_CURRENT)

        # Invalid state
        bad_state = NativeEvidenceRecord(
            host="claude",
            scope=SCOPE_OFFLINE_RUNNER,
            state="passed",  # not in closed enum
            artifact_file="test.zip",
            artifact_sha256="a" * 64,
            identity_sha256="b" * 64,
            recorded_at="2026-09-08T00:00:00Z",
        )
        with self.assertRaises(ValueError):
            bad_state.validate()

        # Invalid scope
        bad_scope = NativeEvidenceRecord(
            host="claude",
            scope="arbitrary_scope",
            state=STATE_CURRENT,
            artifact_file="test.zip",
            artifact_sha256="a" * 64,
            identity_sha256="b" * 64,
            recorded_at="2026-09-08T00:00:00Z",
        )
        with self.assertRaises(ValueError):
            bad_scope.validate()

    def test_record_sanitization_rejects_raw_home_paths(self) -> None:
        """Fail closed if private home absolute paths leak into reason or provenance."""
        leak_mac = "/" + "Users" + "/alice/repo"
        leak_linux = "/" + "home" + "/bob/project"
        leak_win = "C:" + "\\Users" + "\\charlie\\code"
        for leak in (leak_mac, leak_linux, leak_win):
            record = NativeEvidenceRecord(
                host="claude",
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_CURRENT,
                artifact_file="test.zip",
                artifact_sha256="a" * 64,
                identity_sha256="b" * 64,
                recorded_at="2026-09-08T00:00:00Z",
                reason=f"Failed at {leak}",
            )
            with self.assertRaises(ValueError):
                record.validate()

    def test_sanitize_evidence_text(self) -> None:
        """Sanitization replaces local paths with safe generic tokens."""
        leak_linux = "/" + "home" + "/developer/code/test"
        leak_win = "C:" + "\\Users" + "\\user\\test\\file.txt"
        raw = f"Error at {leak_linux} and {leak_win} in /tmp/scratch"
        sanitized = sanitize_evidence_text(raw)
        self.assertNotIn("/" + "home" + "/", sanitized)
        self.assertNotIn("C:" + "\\Users" + "\\", sanitized)
        self.assertIn("<isolated-path>", sanitized)

    def test_evidence_drift_invalidation(self) -> None:
        """Different package SHA or host version invalidates a current pass to stale."""
        base_record = NativeEvidenceRecord(
            host="claude",
            scope=SCOPE_OFFLINE_RUNNER,
            state=STATE_CURRENT,
            artifact_file="test.zip",
            artifact_sha256="a" * 64,
            identity_sha256="b" * 64,
            recorded_at="2026-09-08T00:00:00Z",
            host_version="1.0.0",
        )

        # Unchanged => remains current
        self.assertEqual(
            evaluate_evidence_drift(
                base_record,
                current_artifact_sha="a" * 64,
                current_identity_sha="b" * 64,
                current_host_version="1.0.0",
            ),
            STATE_CURRENT,
        )

        # Changed artifact SHA => drifts to stale
        self.assertEqual(
            evaluate_evidence_drift(
                base_record,
                current_artifact_sha="c" * 64,
                current_identity_sha="b" * 64,
                current_host_version="1.0.0",
            ),
            STATE_STALE,
        )

        # Changed identity SHA => drifts to stale
        self.assertEqual(
            evaluate_evidence_drift(
                base_record,
                current_artifact_sha="a" * 64,
                current_identity_sha="c" * 64,
                current_host_version="1.0.0",
            ),
            STATE_STALE,
        )

        # Changed host version => drifts to stale
        self.assertEqual(
            evaluate_evidence_drift(
                base_record,
                current_artifact_sha="a" * 64,
                current_identity_sha="b" * 64,
                current_host_version="2.0.0",
            ),
            STATE_STALE,
        )

        # Non-current record retains its state and does not drift
        not_run_rec = NativeEvidenceRecord(
            host="claude",
            scope=SCOPE_VISUAL_PICKER,
            state=STATE_NOT_RUN,
            artifact_file="test.zip",
            artifact_sha256="a" * 64,
            identity_sha256="b" * 64,
            recorded_at="2026-09-08T00:00:00Z",
        )
        self.assertEqual(
            evaluate_evidence_drift(
                not_run_rec,
                current_artifact_sha="different" * 4,
                current_identity_sha="different" * 4,
            ),
            STATE_NOT_RUN,
        )

    def test_verify_installed_provenance_rejects_tampered_or_wrong_package(self) -> None:
        """Same-name wrong-package discovery must fail provenance checks."""
        with safe_temporary_directory() as tmp_root:
            skill_dir = tmp_root / "resume-claude"
            skill_dir.mkdir()
            (skill_dir / "scripts").mkdir()
            (skill_dir / "SKILL.md").write_bytes(b"# Legitimate Skill")
            (skill_dir / "scripts" / "run_reader.py").write_bytes(b"# Legitimate Runner")

            expected_plan = {
                "resume-claude/SKILL.md": b"# Legitimate Skill",
                "resume-claude/scripts/run_reader.py": b"# Legitimate Runner",
            }

            # Matching content passes
            self.assertTrue(verify_installed_provenance(skill_dir, expected_plan))

            # Tampered content fails
            (skill_dir / "SKILL.md").write_bytes(b"# Attacker Replacement")
            self.assertFalse(verify_installed_provenance(skill_dir, expected_plan))

            # Missing file fails
            (skill_dir / "SKILL.md").unlink()
            self.assertFalse(verify_installed_provenance(skill_dir, expected_plan))

    def test_format_evidence_markdown_table(self) -> None:
        """Rendered table must have correct columns and entry count."""
        records = [
            NativeEvidenceRecord(
                host="claude",
                scope=SCOPE_OFFLINE_RUNNER,
                state=STATE_CURRENT,
                artifact_file="test.zip",
                artifact_sha256="1234567890abcdef" * 4,
                identity_sha256="abcdef1234567890" * 4,
                recorded_at="2026-09-08T00:00:00Z",
                reason="All tests passed",
            ),
            NativeEvidenceRecord(
                host="kilo",
                scope=SCOPE_VISUAL_PICKER,
                state=STATE_NOT_RUN,
                artifact_file="test.zip",
                artifact_sha256="1234567890abcdef" * 4,
                identity_sha256="abcdef1234567890" * 4,
                recorded_at="2026-09-08T00:00:00Z",
                reason="Destination-only host",
            ),
        ]
        table = format_evidence_markdown_table(records)
        self.assertIn("| Host | Scope | State |", table)
        self.assertIn("claude", table)
        self.assertIn("kilo", table)
        self.assertIn("Destination-only host", table)

    def test_cli_check_only_and_json_invocation(self) -> None:
        """CLI invocations for --check-only and single host scoped query work."""
        script = REPO / "scripts" / "collect_native_evidence.py"

        # check-only
        res = subprocess.run(
            [sys.executable, str(script), "--check-only"],
            cwd=str(REPO),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("EVIDENCE_PROFILE_CHECK PASS", res.stdout)

        # single host offline_runner query
        res_json = subprocess.run(
            [
                sys.executable,
                str(script),
                "--host",
                "claude",
                "--scope",
                "offline_runner",
                "--json",
            ],
            cwd=str(REPO),
            capture_output=True,
            text=True,
        )
        self.assertEqual(res_json.returncode, 0, res_json.stderr)
        data = json.loads(res_json.stdout)
        self.assertEqual(data["schema_version"], EVIDENCE_SCHEMA_VERSION)
        self.assertEqual(data["record_count"], 1)
        self.assertEqual(data["records"][0]["host"], "claude")
        self.assertEqual(data["records"][0]["scope"], "offline_runner")
        self.assertEqual(data["records"][0]["state"], STATE_CURRENT)


if __name__ == "__main__":
    unittest.main()
