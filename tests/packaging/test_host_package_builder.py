from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path, PurePosixPath

from portable_resume import __version__
from portable_resume.diagnostics import SOURCE_KEYS
from portable_resume.install.catalog import HOST_KEYS
from portable_resume.registry import enabled_package_keys

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


class HostPackageBuilderTests(unittest.TestCase):
    def build(self, output: Path) -> dict:
        env = os.environ.copy()
        # Pre-tag release candidates pin exact X.Y.Z before vX.Y.Z exists.
        # Checkout-default packaging smoke may use a development-channel pin;
        # release.yml never sets this env and still requires exact release identity.
        if re.fullmatch(r"\d+\.\d+\.\d+", __version__):
            env["PORTABLE_RESUME_ALLOW_STABLE_DEVELOPMENT_IDENTITY"] = "1"
        completed = subprocess.run(
            [
                sys.executable,
                str(REPO / "scripts" / "build_host_packages.py"),
                "--output-dir",
                str(output),
                "--json",
            ],
            cwd=REPO,
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_builds_safe_complete_deterministic_host_archives(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first"
            second = Path(temporary) / "second"
            report = self.build(first)
            repeated = self.build(second)
            self.assertEqual(report["host_count"], len(HOST_KEYS))
            # #121: one direct archive per payload profile (all hosts currently share one).
            self.assertGreaterEqual(report["direct_package_count"], 1)
            self.assertLessEqual(report["direct_package_count"], len(HOST_KEYS))
            self.assertEqual(report["plugin_package_count"], len(enabled_package_keys()))
            expected_artifact_count = report["direct_package_count"] + len(
                enabled_package_keys()
            )
            self.assertEqual(len(report["artifacts"]), expected_artifact_count)
            direct_items = [a for a in report["artifacts"] if a["type"] == "direct-skills"]
            self.assertEqual(len(direct_items), report["direct_package_count"])
            # Universal payload covers every destination host exactly once across profiles.
            covered = set()
            for item in direct_items:
                covered.update(item.get("hosts") or [item.get("host")])
            self.assertEqual(covered, set(HOST_KEYS))
            artifact_files = [item["file"] for item in report["artifacts"]]
            self.assertEqual(len(artifact_files), len(set(artifact_files)))
            self.assertEqual(
                {path.name for path in first.glob("*.zip")},
                set(artifact_files),
            )
            self.assertEqual(
                set(report["package_surfaces"]),
                set(enabled_package_keys()),
            )
            self.assertEqual(report["schema_version"], "portable-resume/host-packages-v2")
            self.assertEqual(report["version"], __version__)
            self.assertEqual(
                report["build_identity"]["base_version"],
                __version__,
            )
            self.assertEqual(
                report["artifact_version"],
                report["build_identity"]["version"],
            )
            self.assertEqual(report["live_host_installation"], "not-run")
            self.assertEqual(report["native_package_activation"], "not-run")
            self.assertIn("package_contracts_schema", report)
            self.assertIn("contracts", report)
            self.assertEqual(
                {item["file"]: item["sha256"] for item in report["artifacts"]},
                {item["file"]: item["sha256"] for item in repeated["artifacts"]},
            )
            for item in report["artifacts"]:
                self.assertIn(report["artifact_version"], item["file"])
                self.assertIn("contract_id", item)
                self.assertEqual(item["offline_validation"], "pass")
                self.assertEqual(item["native_evidence_status"], "not-run")
                archive = first / item["file"]
                self.assertEqual(
                    hashlib.sha256(archive.read_bytes()).hexdigest(),
                    item["sha256"],
                )
                with zipfile.ZipFile(archive) as zipped:
                    names = zipped.namelist()
                    self.assertTrue(names)
                    self.assertTrue(
                        all(
                            not PurePosixPath(name).is_absolute()
                            and ".." not in PurePosixPath(name).parts
                            and "\\" not in name
                            for name in names
                        )
                    )
                    self.assertEqual(
                        len([name for name in names if name.endswith("/SKILL.md")]),
                        len(SOURCE_KEYS),
                    )
                    self.assertTrue(
                        any(
                            name.endswith(
                                "resources/portable-resume-v1.schema.json"
                            )
                            for name in names
                        )
                    )
                    self.assertFalse(
                        any("/portable_resume/install/" in name for name in names)
                    )
                    identity_members = [
                        name
                        for name in names
                        if name.endswith(
                            "/portable_resume/resources/build-identity.json"
                        )
                    ]
                    self.assertEqual(len(identity_members), 1)
                    self.assertEqual(
                        json.loads(zipped.read(identity_members[0]).decode("utf-8")),
                        report["build_identity"],
                    )

    def test_plugin_archives_have_required_root_manifests(self) -> None:
        expected = {
            "antigravity-plugin": "plugin.json",
            "claude-marketplace": ".claude-plugin/marketplace.json",
            "codex-marketplace": ".agents/plugins/marketplace.json",
            "codex-plugin": ".codex-plugin/plugin.json",
            "cursor-marketplace": ".cursor-plugin/marketplace.json",
            "grok-plugin": ".grok-plugin/plugin.json",
            "qwen-extension": "qwen-extension.json",
            "kimi-plugin": "kimi.plugin.json",
        }
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packages"
            report = self.build(output)
            for item in report["artifacts"]:
                if item["type"] not in expected:
                    continue
                with zipfile.ZipFile(output / item["file"]) as zipped:
                    manifest = json.loads(
                        zipped.read(expected[item["type"]]).decode("utf-8")
                    )
                if item["type"] not in {
                    "antigravity-plugin",
                    "claude-marketplace",
                    "codex-marketplace",
                    "cursor-marketplace",
                }:
                    self.assertEqual(manifest["name"], "portable-resume")
                    self.assertEqual(manifest["version"], __version__)

    def test_plugin_layouts_match_public_specs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "packages"
            report = self.build(output)
            artifacts = {item["type"]: item for item in report["artifacts"]}

            codex = output / artifacts["codex-marketplace"]["file"]
            with zipfile.ZipFile(codex) as zipped:
                marketplace = json.loads(
                    zipped.read(".agents/plugins/marketplace.json").decode("utf-8")
                )
                entry = marketplace["plugins"][0]
                self.assertEqual(
                    entry["source"],
                    {
                        "source": "local",
                        "path": "./plugins/portable-resume",
                    },
                )
                self.assertEqual(entry["policy"]["installation"], "AVAILABLE")
                self.assertEqual(entry["policy"]["authentication"], "ON_INSTALL")
                plugin = json.loads(
                    zipped.read(
                        "plugins/portable-resume/.codex-plugin/plugin.json"
                    ).decode("utf-8")
                )
                self.assertEqual(plugin["skills"], "./skills/")
                self.assertEqual(plugin["version"], __version__)
                self.assertEqual(plugin["author"]["url"], "https://github.com/ImL1s")
                self._assert_directory_interface(plugin["interface"])
                for asset in ("icon.png", "logo.png"):
                    self._assert_square_png(
                        zipped.read(f"plugins/portable-resume/assets/{asset}"),
                        minimum=48 if asset == "icon.png" else 256,
                    )
                codex_plugin_subtree = {
                    name[len("plugins/portable-resume/") :]: zipped.read(name)
                    for name in zipped.namelist()
                    if name.startswith("plugins/portable-resume/")
                }

            # OpenAI plugin-root bundle: the codex marketplace plugin subtree
            # lifted to the archive top level plus the repository documents.
            codex_plugin = output / artifacts["codex-plugin"]["file"]
            with zipfile.ZipFile(codex_plugin) as zipped:
                names = set(zipped.namelist())
                for document in ("LICENSE", "NOTICE", "README.md"):
                    self.assertEqual(
                        zipped.read(document),
                        (REPO / document).read_bytes(),
                    )
                self.assertFalse(any(name.startswith("plugins/") for name in names))
                self.assertFalse(any("marketplace.json" in name for name in names))
                bundled = {
                    name: zipped.read(name)
                    for name in names
                    if name not in {"LICENSE", "NOTICE", "README.md"}
                }
                self.assertEqual(bundled, codex_plugin_subtree)
                manifest = json.loads(
                    zipped.read(".codex-plugin/plugin.json").decode("utf-8")
                )
                self.assertEqual(manifest["interface"]["composerIcon"], "./assets/icon.png")
                self.assertEqual(manifest["interface"]["logo"], "./assets/logo.png")
                self.assertIn("assets/icon.png", names)
                self.assertIn("assets/logo.png", names)

            claude = output / artifacts["claude-marketplace"]["file"]
            with zipfile.ZipFile(claude) as zipped:
                marketplace = json.loads(
                    zipped.read(".claude-plugin/marketplace.json").decode("utf-8")
                )
                self.assertEqual(
                    marketplace["$schema"],
                    "https://code.claude.com/schemas/marketplace.json",
                )
                self.assertEqual(marketplace["owner"]["url"], "https://github.com/ImL1s")
                entry = marketplace["plugins"][0]
                self.assertEqual(entry["source"], "./plugins/portable-resume")
                self.assertEqual(entry["displayName"], "Portable Resume")
                self.assertEqual(entry["license"], "Apache-2.0")
                self.assertEqual(
                    entry["repository"], "https://github.com/ImL1s/resume-skills"
                )
                self.assertEqual(entry["version"], __version__)

            grok = output / artifacts["grok-plugin"]["file"]
            with zipfile.ZipFile(grok) as zipped:
                names = set(zipped.namelist())
                self.assertNotIn("plugin.json", names)
                manifest = json.loads(
                    zipped.read(".grok-plugin/plugin.json").decode("utf-8")
                )
                self.assertEqual(manifest["skills"], "./skills/")
                self.assertEqual(manifest["version"], __version__)
                self.assertEqual(manifest["license"], "Apache-2.0")
                self.assertEqual(
                    manifest["repository"], "https://github.com/ImL1s/resume-skills"
                )
                self.assertEqual(manifest["author"]["url"], "https://github.com/ImL1s")
                self.assertIn("assets/icon.png", names)
                self.assertIn("assets/logo.png", names)
                self.assertTrue(
                    any(
                        name.startswith("skills/") and name.endswith("/SKILL.md")
                        for name in names
                    )
                )

            cursor = output / artifacts["cursor-marketplace"]["file"]
            with zipfile.ZipFile(cursor) as zipped:
                marketplace = json.loads(
                    zipped.read(".cursor-plugin/marketplace.json").decode("utf-8")
                )
                source = marketplace["plugins"][0]["source"]
                plugin = json.loads(
                    zipped.read(
                        f"{source}/.cursor-plugin/plugin.json"
                    ).decode("utf-8")
                )
                self.assertEqual(plugin["skills"], "./skills/")
                self.assertEqual(plugin["version"], __version__)
                self.assertTrue(
                    any(
                        name.startswith(f"{source}/skills/")
                        and name.endswith("/SKILL.md")
                        for name in zipped.namelist()
                    )
                )

            antigravity = output / artifacts["antigravity-plugin"]["file"]
            with zipfile.ZipFile(antigravity) as zipped:
                self.assertEqual(
                    json.loads(zipped.read("plugin.json").decode("utf-8")),
                    {"name": "portable-resume"},
                )
                self.assertTrue(
                    any(
                        name.startswith("skills/")
                        and name.endswith("/SKILL.md")
                        for name in zipped.namelist()
                    )
                )

            qwen = output / artifacts["qwen-extension"]["file"]
            with zipfile.ZipFile(qwen) as zipped:
                manifest = json.loads(
                    zipped.read("qwen-extension.json").decode("utf-8")
                )
                self.assertEqual(manifest["skills"], "skills")
                self.assertEqual(manifest["version"], __version__)
                self.assertTrue(
                    any(
                        name.startswith("skills/")
                        and name.endswith("/SKILL.md")
                        for name in zipped.namelist()
                    )
                )

            kimi = output / artifacts["kimi-plugin"]["file"]
            with zipfile.ZipFile(kimi) as zipped:
                manifest = json.loads(
                    zipped.read("kimi.plugin.json").decode("utf-8")
                )
                self.assertEqual(manifest["skills"], "./skills/")
                self.assertEqual(manifest["version"], __version__)
                self.assertTrue(
                    any(
                        name.startswith("skills/")
                        and name.endswith("/SKILL.md")
                        for name in zipped.namelist()
                    )
                )

    def _assert_square_png(self, data: bytes, *, minimum: int) -> None:
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(data[12:16], b"IHDR")
        width, height = struct.unpack(">II", data[16:24])
        self.assertEqual(width, height)
        self.assertGreaterEqual(width, minimum)

    def _assert_directory_interface(self, interface: dict) -> None:
        """OpenAI plugin directory ``interface`` block requirements."""

        self.assertEqual(interface["displayName"], "Portable Resume")
        self.assertLessEqual(len(interface["shortDescription"]), 30)
        self.assertEqual(interface["developerName"], "ImL1s")
        self.assertEqual(interface["category"], "Developer Tools")
        self.assertEqual(interface["capabilities"], ["Interactive", "Read"])
        site = "https://iml1s.github.io/resume-skills/"
        self.assertEqual(interface["websiteURL"], site)
        self.assertEqual(interface["supportURL"], f"{site}support/")
        self.assertEqual(interface["privacyPolicyURL"], f"{site}privacy/")
        self.assertEqual(interface["termsOfServiceURL"], f"{site}terms/")
        prompts = interface["defaultPrompt"]
        self.assertEqual(len(prompts), 3)
        self.assertNotIn("$", prompts[0])
        self.assertTrue(all(isinstance(p, str) and p.strip() for p in prompts))
        self.assertRegex(interface["brandColor"], r"^#[0-9A-Fa-f]{6}$")
        long_description = interface["longDescription"]
        self.assertIn(f"{len(SOURCE_KEYS)} sources", long_description)
        for phrase in ("never contacts the network", "never modifies the source store",
                       "no MCP server", "best-effort", "not live session restore"):
            self.assertIn(phrase, long_description)
        self.assertEqual(interface["composerIcon"], "./assets/icon.png")
        self.assertEqual(interface["logo"], "./assets/logo.png")

    def test_committed_brand_assets_meet_directory_size_floors(self) -> None:
        self._assert_square_png((REPO / "assets" / "logo.png").read_bytes(), minimum=256)
        self._assert_square_png((REPO / "assets" / "icon.png").read_bytes(), minimum=48)

    def test_png_validation_rejects_truncated_or_corrupt_assets(self) -> None:
        from scripts.build_host_packages import _png_dimensions

        logo = (REPO / "assets" / "logo.png").read_bytes()
        self.assertEqual(_png_dimensions(logo), (512, 512))
        iend_at = logo.rfind(b"IEND")
        idat_at = logo.find(b"IDAT")
        corrupt_idat = bytearray(logo)
        corrupt_idat[idat_at + 40] ^= 0xFF
        bad_crc = bytearray(logo)
        bad_crc[-1] ^= 0x01  # last byte is part of the IEND CRC
        cases = {
            "signature": b"\x89PNX" + logo[4:],
            "truncated before IEND": logo[: iend_at - 4],
            "truncated mid-IDAT": logo[: idat_at + 100],
            "corrupt IDAT byte (CRC mismatch)": bytes(corrupt_idat),
            "bad IEND CRC": bytes(bad_crc),
            "trailing bytes": logo + b"\x00",
            "header only": logo[:33],
        }
        for label, data in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(ValueError):
                    _png_dimensions(data)

    def test_render_brand_assets_reproduces_committed_pixels(self) -> None:
        """The committed PNGs decode to exactly what scripts/render_brand_assets.py renders.

        Pixel data is compared rather than compressed bytes because deflate
        output may differ between zlib implementations across CI platforms.
        """

        from scripts import render_brand_assets

        self.assertEqual(render_brand_assets.check(), [])
        width, height, raw = render_brand_assets.decode_png(
            (REPO / "assets" / "icon.png").read_bytes()
        )
        self.assertEqual((width, height), (256, 256))
        self.assertEqual(raw, render_brand_assets.render_raw(256))
        self.assertEqual(
            (REPO / "site" / "assets" / "logo-512.png").read_bytes(),
            (REPO / "assets" / "logo.png").read_bytes(),
        )

    def test_offline_contract_rejects_archive_missing_manifest(self) -> None:
        from portable_resume.install.package_contracts import validate_archive_bytes
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as archive:
            archive.writestr("skills/resume-claude/SKILL.md", b"---\nname: x\n---\n")
        report = validate_archive_bytes(buf.getvalue(), package_type="grok-plugin")
        self.assertFalse(report["ok"])
        self.assertTrue(any("missing required member" in f for f in report["failures"]))


if __name__ == "__main__":
    unittest.main()
