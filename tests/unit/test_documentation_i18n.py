from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts import check_docs


REPO = Path(__file__).resolve().parents[2]


class DocumentationI18nTests(unittest.TestCase):
    def test_multilingual_quickstarts_are_complete_and_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "check_docs.py"), "--json"],
            cwd=REPO,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertTrue(report["ok"])
        self.assertEqual(report["required_locale_count"], 12)
        self.assertEqual(len(report["checked_locales"]), 12)
        self.assertEqual(report["failures"], [])

    def test_docs_check_rejects_broken_root_onboarding_and_count_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(REPO / "README.md", root / "README.md")
            shutil.copy2(REPO / "CHANGELOG.md", root / "CHANGELOG.md")
            shutil.copytree(REPO / "docs", root / "docs")

            readme_path = root / "README.md"
            readme = readme_path.read_text(encoding="utf-8")
            readme = readme.replace(
                'alt="Local coding-agent session stores flow into a sealed context '
                'archive, then into fresh destination sessions"',
                'alt="Nine coding-agent sources flow into nine destination sessions"',
            )
            readme = readme.replace("Installed (pipx/pip):", "Lower-level commands:")
            readme = readme.replace(
                "\nportable-resume --version",
                "\nPYTHONPATH=src python3 scripts/portable-resume --version",
            )
            readme = readme.replace(
                "17 sources × 18 hosts (derived from registries)",
                "17 sources × 9 hosts (derived from registries)",
                1,
            )
            readme_path.write_text(readme, encoding="utf-8")

            install_hosts_path = root / "docs" / "install-hosts.md"
            install_hosts = install_hosts_path.read_text(encoding="utf-8").replace(
                "# all user-global profiles (count derives from the registry)",
                "# all thirteen user-global profiles",
            )
            install_hosts_path.write_text(install_hosts, encoding="utf-8")

            changelog_path = root / "CHANGELOG.md"
            changelog_path.write_text(
                "## Unreleased\n\n- misplaced entry\n\n"
                + changelog_path.read_text(encoding="utf-8"),
                encoding="utf-8",
            )

            locale_path = root / "docs" / "i18n" / "en.md"
            locale = locale_path.read_text(encoding="utf-8").replace(
                "portable-resume-counts: sources=17 destinations=18",
                "portable-resume-counts: sources=17 destinations=9",
            )
            locale_path.write_text(locale, encoding="utf-8")

            with mock.patch.object(check_docs, "REPO", root):
                report = check_docs.check()

        failures = report["failures"]
        self.assertIn("README.md: hero alt text must be count-free", failures)
        self.assertIn("README.md: missing installed (pipx/pip) command section", failures)
        self.assertIn(
            "docs/install-hosts.md: quick-install all comment must be registry-derived",
            failures,
        )
        self.assertIn(
            "CHANGELOG.md: expected one H1 followed by one Unreleased section",
            failures,
        )
        self.assertIn(
            "README.md: current registry counts must be 17 sources × 18 hosts",
            failures,
        )
        self.assertIn(
            "docs/i18n/en.md: counts marker must be sources=17 destinations=18",
            failures,
        )

    def test_docs_check_rejects_stale_visible_current_locale_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(REPO / "README.md", root / "README.md")
            shutil.copy2(REPO / "CHANGELOG.md", root / "CHANGELOG.md")
            shutil.copytree(REPO / "docs", root / "docs")
            locale_path = root / "docs" / "i18n" / "en.md"
            locale = locale_path.read_text(encoding="utf-8").replace(
                "Install all 18 destination profiles",
                "Install all nine destination profiles",
                1,
            )
            locale_path.write_text(locale, encoding="utf-8")

            with mock.patch.object(check_docs, "REPO", root):
                report = check_docs.check()

        self.assertIn(
            "docs/i18n/en.md: current registry facts must mention destination count 18",
            report["failures"],
        )

    def test_context7_is_not_a_product_feature(self) -> None:
        product_docs = [
            REPO / "README.md",
            REPO / "docs" / "STATUS.md",
            REPO / "docs" / "clean-room-attestation.md",
            REPO / "docs" / "i18n" / "README.md",
            REPO / "src" / "portable_resume" / "resources" / "skill" / "SKILL.md.tmpl",
        ]
        product_docs.extend(sorted((REPO / "docs" / "i18n").glob("*.md")))
        for path in product_docs:
            self.assertNotIn("context7", path.read_text(encoding="utf-8").lower(), str(path))
        self.assertFalse((REPO / "docs" / "network-integrations.md").exists())


    def test_repository_metadata_file_valid_and_offline(self) -> None:
        meta_path = REPO / "docs" / "metadata" / "repository-metadata.json"
        self.assertTrue(meta_path.is_file())
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], "portable-resume/repo-metadata-v1")
        self.assertIn("offline", data["description"].lower())
        self.assertIn("fresh session", data["description"].lower())
        self.assertIn("not live", data["description"].lower())
        self.assertNotIn("81", data["description"])
        self.assertNotIn("9x9", data["description"].lower())
        self.assertNotIn("9×9", data["description"])
        self.assertTrue(data["homepage"].startswith("https://github.com/ImL1s/resume-skills"))
        self.assertTrue(len(data["topics"]) > 0)
        for t in data["topics"]:
            self.assertRegex(t, r"^[a-z0-9-]+$")

    def test_repository_metadata_rejects_stale_matrix_or_missing_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(REPO / "README.md", root / "README.md")
            shutil.copy2(REPO / "CHANGELOG.md", root / "CHANGELOG.md")
            shutil.copytree(REPO / "docs", root / "docs")
            meta_path = root / "docs" / "metadata" / "repository-metadata.json"

            # Stale matrix claim
            meta_path.write_text(
                json.dumps({
                    "schema_version": "portable-resume/repo-metadata-v1",
                    "description": "Offline 9x9/81 matrix migration. Fresh sessions, not live.",
                    "homepage": "https://github.com/ImL1s/resume-skills",
                    "topics": ["cli"],
                }),
                encoding="utf-8",
            )
            with mock.patch.object(check_docs, "REPO", root):
                report = check_docs.check()
            self.assertTrue(
                any("stale claim" in f for f in report["failures"]),
                f"Expected stale claim failure, got: {report['failures']}",
            )

            # Missing boundaries
            meta_path.write_text(
                json.dumps({
                    "schema_version": "portable-resume/repo-metadata-v1",
                    "description": "A tool for coding agents.",
                    "homepage": "https://github.com/ImL1s/resume-skills",
                    "topics": ["cli"],
                }),
                encoding="utf-8",
            )
            with mock.patch.object(check_docs, "REPO", root):
                report = check_docs.check()
            self.assertTrue(
                any("missing boundary phrase" in f for f in report["failures"]),
                f"Expected missing boundary phrase failure, got: {report['failures']}",
            )

    def test_docs_check_rejects_stale_current_release_link(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(REPO / "README.md", root / "README.md")
            shutil.copy2(REPO / "CHANGELOG.md", root / "CHANGELOG.md")
            shutil.copytree(REPO / "docs", root / "docs")
            published = json.loads(
                (REPO / "src" / "portable_resume" / "resources" / "latest-release.json")
                .read_text(encoding="utf-8")
            )["tag"]
            current_link = f"releases/tag/{published}"
            stale_link = "releases/tag/v0.0.1"
            zh_path = root / "docs" / "i18n" / "zh-TW.md"
            self.assertIn(current_link, zh_path.read_text(encoding="utf-8"))
            zh_text = zh_path.read_text(encoding="utf-8").replace(
                current_link, stale_link
            )
            zh_path.write_text(zh_text, encoding="utf-8")
            with mock.patch.object(check_docs, "REPO", root):
                report = check_docs.check()
            self.assertTrue(
                any("docs/i18n/zh-TW.md: must link to current published release" in f for f in report["failures"]),
                f"Expected stale release link failure, got: {report['failures']}",
            )

            # Test index README.md stale link
            zh_path.write_text(
                zh_text.replace(stale_link, current_link),
                encoding="utf-8",
            )
            idx_path = root / "docs" / "i18n" / "README.md"
            self.assertIn(current_link, idx_path.read_text(encoding="utf-8"))
            idx_text = idx_path.read_text(encoding="utf-8").replace(
                current_link, stale_link
            )
            idx_path.write_text(idx_text, encoding="utf-8")
            with mock.patch.object(check_docs, "REPO", root):
                report = check_docs.check()
            self.assertTrue(
                any("docs/i18n/README.md: must link to current published release" in f for f in report["failures"]),
                f"Expected stale index release link failure, got: {report['failures']}",
            )

    def test_docs_check_rejects_stale_windows_unimplemented_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            shutil.copy2(REPO / "README.md", root / "README.md")
            shutil.copy2(REPO / "CHANGELOG.md", root / "CHANGELOG.md")
            shutil.copytree(REPO / "docs", root / "docs")
            policy_path = root / "docs" / "evidence" / "native-activation-policy-v1.md"
            policy_path.write_text(
                policy_path.read_text(encoding="utf-8")
                + "\nA full Windows implementation is not shipped; until #125 lands.",
                encoding="utf-8",
            )
            with mock.patch.object(check_docs, "REPO", root):
                report = check_docs.check()
            self.assertTrue(
                any("active policy must not claim Windows mutating install is unimplemented" in f for f in report["failures"]),
                f"Expected Windows policy failure, got: {report['failures']}",
            )


if __name__ == "__main__":
    unittest.main()
