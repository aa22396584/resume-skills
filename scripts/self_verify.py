#!/usr/bin/env python3
"""Deterministic self-verify for a checkout (no absolute home paths).

Stages are named and selectable via ``--profile`` / ``--only`` so local and CI
can share one source of truth without re-running the same expensive work twice
in a single matrix cell (issue #67).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

REPO = Path(__file__).resolve().parents[1]

# Closed allowlist of stage names (unknown names fail closed).
STAGE_NAMES = (
    "compile",
    "version_state",
    "docs",
    "secrets",
    "unit",
    "unit_portable",
    "packaging",
    "reader_self_check",
    "installer_matrix",
    "fixture_list_show",
    "windows_source_fixtures",
    "windows_negative_diagnostics",
)

PROFILES: dict[str, tuple[str, ...]] = {
    # Comprehensive pre-commit verification (docs + secrets + suite).
    "local": (
        "compile",
        "version_state",
        "docs",
        "secrets",
        "unit",
        "packaging",
        "reader_self_check",
        "installer_matrix",
        "fixture_list_show",
    ),
    # Per OS/Python matrix cell: interpreter-sensitive work only.
    "ci-compat": (
        "compile",
        "unit",
        "reader_self_check",
        "installer_matrix",
        "fixture_list_show",
    ),
    # Native Windows: full adapters/e2e/integration still have residual
    # path-separator / symlink-privilege unit asserts; product surfaces are
    # gated by self-check + 17-source fixture list/show + portable units.
    "ci-compat-windows": (
        "compile",
        "unit_portable",
        "reader_self_check",
        "installer_matrix",
        "fixture_list_show",
        "windows_source_fixtures",
        "windows_negative_diagnostics",
    ),
    # Once per push/PR: version-independent quality gates.
    "ci-quality": ("version_state", "docs", "secrets"),
}


def run(argv: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = dict(env) if env is not None else {**os.environ, "PYTHONPATH": os.pathsep.join((str(REPO / "src"), str(REPO)))}
    merged_env["PYTHONNOUSERSITE"] = "1"
    return subprocess.run(
        argv,
        cwd=str(REPO),
        env=merged_env,
        text=True,
        capture_output=True,
        check=False,
    )


def _stage_compile() -> tuple[int, str]:
    completed = run([sys.executable, "-m", "compileall", "-q", "src", "scripts", "tests"])
    return completed.returncode, (completed.stderr or completed.stdout or "")[-400:]


def _stage_version_state() -> tuple[int, str]:
    completed = run(
        [
            sys.executable,
            str(REPO / "scripts" / "check_version_state.py"),
            "--require-git",
            "--json",
        ]
    )
    return completed.returncode, (completed.stdout or completed.stderr or "").strip()


def _stage_docs() -> tuple[int, str]:
    completed = run([sys.executable, str(REPO / "scripts" / "check_docs.py"), "--json"])
    return completed.returncode, (completed.stdout or "").strip()


def _stage_secrets() -> tuple[int, str]:
    completed = run([sys.executable, str(REPO / "scripts" / "check_secrets.py")])
    tail = ((completed.stdout or "") + (completed.stderr or ""))[-400:]
    return completed.returncode, tail.strip()


def _format_unit_failure(suite: str, output: str, max_chars: int = 4000) -> str:
    cleaned = (output or "").strip()
    prefix = f"FAILED_SUITE: {suite}\n"
    if len(cleaned) <= max_chars:
        return prefix + cleaned
    head_len = max_chars // 2
    tail_len = max_chars - head_len - len("\n[...truncated...]\n")
    return prefix + cleaned[:head_len] + "\n[...truncated...]\n" + cleaned[-tail_len:]


def _stage_unit() -> tuple[int, str]:
    details: list[str] = []
    for suite in ("adapters", "e2e", "integration", "security", "unit"):
        completed = run(
            [sys.executable, "-m", "unittest", "discover", "-s", f"tests/{suite}", "-q"]
        )
        if completed.returncode != 0:
            return completed.returncode, _format_unit_failure(
                suite, completed.stderr or completed.stdout or ""
            )
        details.append(completed.stderr or completed.stdout or "")
    return 0, "".join(details)[-400:]


def _stage_unit_portable() -> tuple[int, str]:
    """Unit + security only (no adapters/e2e/integration path-string suite)."""
    details: list[str] = []
    for suite in ("security", "unit"):
        completed = run(
            [sys.executable, "-m", "unittest", "discover", "-s", f"tests/{suite}", "-q"]
        )
        if completed.returncode != 0:
            return completed.returncode, _format_unit_failure(
                suite, completed.stderr or completed.stdout or ""
            )
        details.append(completed.stderr or completed.stdout or "")
    return 0, "".join(details)[-400:]


def _content_free_reader_output(stdout: str, stderr: str) -> bool:
    """True when stdout/stderr is inert list/show envelope or diagnostic-v1 JSON."""
    for text in (stdout or "", stderr or ""):
        text = text.strip()
        if not text:
            continue
        # Prefer first JSON object if present.
        start = text.find("{")
        if start < 0:
            continue
        try:
            payload = json.loads(text[start:])
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        schema = str(payload.get("schema_version") or "")
        if schema == "portable-resume/diagnostic-v1":
            return True
        if schema.startswith("portable-resume/") and payload.get("inert") is True:
            return True
        if schema.startswith("portable-resume/") and "code" in payload and "exit_code" in payload:
            return True
    return False


WINDOWS_SOURCE_FIXTURES: dict[str, tuple[str, str, str, tuple[str, ...]]] = {
    "antigravity": (
        "tests/fixtures/antigravity/s-ant-01/root",
        "/workspace/project",
        "conv-one",
        ("Antigravity prompt", "Antigravity answer"),
    ),
    "claude": (
        "tests/fixtures/claude/s-cla-01-ordered-parent-chain/root",
        "/workspace/project",
        "7e0a1246-d538-5993-8d6f-3495aafcdd92",
        ("synthetic request", "synthetic response"),
    ),
    "cline": (
        "tests/fixtures/cline/s-cl-01-user-basic",
        "/tmp/project",
        "cl000101-0101-4101-8101-010101010101",
        ("synthetic cline user prompt", "synthetic cline assistant reply"),
    ),
    "codex": (
        "tests/fixtures/codex/s-cod-01-state-generation-selection/root",
        "/workspace/project",
        "0493207e-6039-5026-81d4-e75c0efff76a",
        ("synthetic request", "synthetic response"),
    ),
    "crush": (
        "tests/fixtures/crush/s-cr-01-user-basic",
        "/tmp/project",
        "cr000101-0101-4101-8101-010101010101",
        ("synthetic crush user prompt", "synthetic crush assistant reply"),
    ),
    "cursor": (
        "tests/fixtures/cursor/s-cur-01-cli-cwd-hash/root",
        "/workspace/project",
        "418306f5-3983-5ab7-b8e0-fa47843e83aa",
        ("synthetic request", "synthetic response"),
    ),
    "gemini": (
        "tests/fixtures/gemini/s-gm-01-user-basic",
        "/tmp/project",
        "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        ("synthetic gemini user prompt", "synthetic gemini assistant reply"),
    ),
    "github-copilot": (
        "tests/fixtures/github-copilot/s-gcp-01-user-basic",
        "/tmp/project",
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        ("synthetic copilot user prompt", "synthetic copilot assistant reply"),
    ),
    "goose": (
        "tests/fixtures/goose/s-go-01-user-basic",
        "/tmp/project",
        "go000101-0101-4101-8101-010101010101",
        ("synthetic goose user prompt", "synthetic goose assistant reply"),
    ),
    "grok": (
        "tests/fixtures/grok/s-gro-01/root",
        "/workspace/project",
        "grok-one",
        ("Grok prompt", "Grok answer"),
    ),
    "hermes": (
        "tests/fixtures/hermes/s-hm-01-user-basic",
        "/tmp/project",
        "hm000101-0101-4101-8101-010101010101",
        ("synthetic hermes user prompt", "synthetic hermes assistant reply"),
    ),
    "kimi": (
        "tests/fixtures/kimi/s-kim-01/root",
        "/workspace/project",
        "11111111-1111-4111-8111-111111111111",
        ("Current Kimi prompt", "Current Kimi answer"),
    ),
    "openclaw": (
        "tests/fixtures/openclaw/s-oc-01-basic",
        "/tmp/project",
        "main:sess-basic-0001",
        ("Resume context from /tmp/project", "Synthetic assistant reply"),
    ),
    "opencode": (
        "tests/fixtures/opencode/s-ope-01/root",
        "/workspace/project",
        "ses-sql",
        (
            "Please inspect the synthetic parser.",
            "I inspected only synthetic evidence.",
            "synthetic tool output",
        ),
    ),
    "openhands": (
        "tests/fixtures/openhands/s-oh-01-user-basic",
        "/tmp/project",
        "oh000101010141018101010101010101",
        ("synthetic openhands user prompt", "synthetic openhands assistant reply"),
    ),
    "pi": (
        "tests/fixtures/pi/s-pi-01-basic-v3/agent",
        "/tmp/project",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        (
            "synthetic user request for basic v3 branch",
            "synthetic assistant reply on the active branch",
        ),
    ),
    "qwen": (
        "tests/fixtures/qwen/s-qwe-01/root",
        "/workspace/project",
        "qwen-one",
        (
            "Inspect the synthetic Qwen store.",
            "Only public answer text.",
            "synthetic tool output",
        ),
    ),
}


def _validate_positive_list_envelope(stdout: str, expected_session_id: str) -> str | None:
    text = (stdout or "").strip()
    if not text:
        return "empty_stdout"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "invalid_json"
    if not isinstance(data, dict):
        return "not_dict"
    if data.get("schema_version") != "portable-resume/v1":
        return f"bad_schema:{data.get('schema_version')}"
    if data.get("operation") != "list":
        return f"bad_operation:{data.get('operation')}"
    if data.get("inert") is not True or data.get("untrusted_content") is not True:
        return "missing_inert_untrusted"
    sessions = data.get("sessions")
    if not isinstance(sessions, list) or not sessions:
        return "no_sessions"
    found = any(isinstance(s, dict) and s.get("session_id") == expected_session_id for s in sessions)
    if not found:
        return f"session_id_mismatch:{expected_session_id}"
    return None


def _validate_positive_show_envelope(
    stdout: str,
    expected_source: str,
    expected_session_id: str,
    expected_turn_marker: str,
) -> str | None:
    text = (stdout or "").strip()
    if not text:
        return "empty_stdout"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return "invalid_json"
    if not isinstance(data, dict):
        return "not_dict"
    if data.get("schema_version") != "portable-resume/v1":
        return f"bad_schema:{data.get('schema_version')}"
    if data.get("operation") != "show":
        return f"bad_operation:{data.get('operation')}"
    if data.get("inert") is not True or data.get("untrusted_content") is not True:
        return "missing_inert_untrusted"
    sessions = data.get("sessions")
    if not isinstance(sessions, list) or len(sessions) != 1:
        return f"unexpected_sessions_count:{len(sessions) if isinstance(sessions, list) else 'not_list'}"
    sess = sessions[0]
    if not isinstance(sess, dict):
        return "session_not_dict"
    if sess.get("source") != expected_source:
        return f"source_mismatch:{sess.get('source')}!={expected_source}"
    if sess.get("session_id") != expected_session_id:
        return f"session_id_mismatch:{sess.get('session_id')}!={expected_session_id}"
    turns = sess.get("turns")
    if not isinstance(turns, list) or not turns:
        return "no_turns"
    for turn in turns:
        if not isinstance(turn, dict) or turn.get("inert") is not True or turn.get("untrusted_content") is not True:
            return "turn_missing_inert_untrusted"
    has_marker = any(expected_turn_marker in str(t.get("content") or "") for t in turns)
    if not has_marker:
        return f"missing_expected_turn_marker:{expected_turn_marker}"
    return None


def _stage_windows_source_fixtures() -> tuple[int, str]:
    """List+show one positive fixture per enabled source on Windows nt.

    Hard gate: every enabled source in SOURCE_KEYS must have an exact fixture
    mapping, execute list and show with exit code 0, return valid inert/untrusted
    portable-resume/v1 envelopes, contain the expected session id, and contain
    the expected synthetic public turn marker. No diagnostic or nonzero exit
    code satisfies this positive qualification stage.
    """
    try:
        sys.path.insert(0, str(REPO / "src"))
        from portable_resume.diagnostics import SOURCE_KEYS  # type: ignore

        sources = sorted(SOURCE_KEYS)
    finally:
        if str(REPO / "src") in sys.path:
            try:
                sys.path.remove(str(REPO / "src"))
            except ValueError:
                pass

    if set(sources) != set(WINDOWS_SOURCE_FIXTURES.keys()):
        missing = sorted(set(sources) - set(WINDOWS_SOURCE_FIXTURES.keys()))
        extra = sorted(set(WINDOWS_SOURCE_FIXTURES.keys()) - set(sources))
        detail = f"registry_fixture_mismatch: missing={missing} extra={extra}"
        return 1, detail

    notes: list[str] = []
    failures = 0

    for source in sources:
        fix_rel, declared_cwd, expected_session_id, expected_turns = WINDOWS_SOURCE_FIXTURES[source]
        fixture_path = REPO / fix_rel
        if not fixture_path.exists():
            notes.append(f"{source}:MISSING_FIXTURE_PATH")
            failures += 1
            continue

        if source == "crush":
            query_cwd = str(fixture_path.resolve())
        else:
            query_cwd = os.path.realpath(os.path.abspath(declared_cwd))

        list_run = run(
            [
                sys.executable,
                str(REPO / "scripts" / "portable-resume"),
                source,
                "list",
                "--cwd",
                query_cwd,
                "--source-root",
                str(fixture_path),
                "--within-min",
                "0",
                "--json",
            ]
        )
        if list_run.returncode != 0:
            notes.append(f"{source}:list_exit_{list_run.returncode}")
            failures += 1
            continue

        list_err = _validate_positive_list_envelope(list_run.stdout, expected_session_id)
        if list_err is not None:
            notes.append(f"{source}:list_invalid_{list_err}")
            failures += 1
            continue

        show_run = run(
            [
                sys.executable,
                str(REPO / "scripts" / "portable-resume"),
                source,
                "show",
                "latest",
                "--cwd",
                query_cwd,
                "--source-root",
                str(fixture_path),
                "--within-min",
                "0",
                "--format",
                "json",
            ]
        )
        if show_run.returncode != 0:
            notes.append(f"{source}:show_exit_{show_run.returncode}")
            failures += 1
            continue

        show_err = _validate_positive_show_envelope(
            show_run.stdout, source, expected_session_id, expected_turns[0]
        )
        if show_err is not None:
            notes.append(f"{source}:show_invalid_{show_err}")
            failures += 1
            continue

        notes.append(f"{source}:list=0:show=0:ok")

    total = len(sources)
    ok_count = total - failures
    code = 0 if failures == 0 and ok_count == total else 1
    return code, f"ok={ok_count}/{total} failures={failures} " + " ".join(notes)


def _stage_windows_negative_diagnostics() -> tuple[int, str]:
    """Verify safe diagnostic-v1 rejection (exit != 0) on invalid query paths."""
    notes: list[str] = []
    failures = 0
    test_cases = (
        (
            "claude",
            [
                "show",
                "latest",
                "--cwd",
                "/nonexistent/cwd",
                "--source-root",
                str(REPO / "tests/fixtures/claude/s-cla-01-ordered-parent-chain/root"),
                "--within-min",
                "0",
            ],
            "E_NO_MATCH",
            3,
        ),
        (
            "gemini",
            [
                "show",
                "latest",
                "--cwd",
                "/nonexistent/cwd",
                "--source-root",
                str(REPO / "tests/fixtures/gemini/s-gm-01-user-basic"),
                "--within-min",
                "0",
            ],
            "E_NO_MATCH",
            3,
        ),
        (
            "cursor",
            [
                "show",
                "00000000-0000-0000-0000-000000000000",
                "--cwd",
                "/workspace/project",
                "--source-root",
                str(REPO / "tests/fixtures/cursor/s-cur-01-cli-cwd-hash/root"),
                "--within-min",
                "0",
            ],
            "E_UNSUPPORTED_FORMAT",
            5,
        ),
    )
    for source, args, expected_code, expected_exit in test_cases:
        res = run(
            [
                sys.executable,
                str(REPO / "scripts" / "portable-resume"),
                source,
                *args,
            ]
        )
        if res.returncode != expected_exit:
            notes.append(f"{source}:exit={res.returncode}!={expected_exit}")
            failures += 1
            continue
        try:
            raw_text = (res.stderr or res.stdout or "").strip()
            # Diagnostic JSON is emitted on stderr, but might have markdown banner on stdout
            start = raw_text.find("{")
            diag = json.loads(raw_text[start:]) if start >= 0 else {}
        except json.JSONDecodeError:
            notes.append(f"{source}:malformed_diagnostic_json")
            failures += 1
            continue
        if diag.get("schema_version") != "portable-resume/diagnostic-v1" or diag.get("code") != expected_code:
            notes.append(f"{source}:bad_code:{diag.get('code')}!={expected_code}")
            failures += 1
            continue
        notes.append(f"{source}:neg_diag={diag.get('code')}:ok")
    code = 0 if failures == 0 else 1
    return code, f"failures={failures} " + " ".join(notes)


def _stage_packaging() -> tuple[int, str]:
    completed = run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests/packaging", "-q"]
    )
    return completed.returncode, (completed.stderr or completed.stdout or "")[-400:]


def _stage_reader_self_check() -> tuple[int, str]:
    completed = run(
        [sys.executable, str(REPO / "scripts" / "portable-resume"), "self-check", "--json"]
    )
    return completed.returncode, (completed.stdout or "").strip()


def _stage_installer_matrix() -> tuple[int, str]:
    completed = run(
        [sys.executable, str(REPO / "scripts" / "install-resume-skills"), "matrix"]
    )
    if completed.returncode != 0:
        return completed.returncode, (completed.stderr or completed.stdout or "")[-400:]
    matrix = json.loads(completed.stdout)
    # #32: install-result-v1 wraps matrix in results[]
    if isinstance(matrix, dict) and matrix.get("schema_version") == "portable-resume/install-result-v1":
        results = matrix.get("results") or []
        matrix = results[0] if results else {}
    summary = {
        "ok": matrix.get("ok"),
        "cell_count": matrix.get("cell_count"),
        "live_cells_supported": matrix.get("live_cells_supported"),
    }
    return completed.returncode, json.dumps(summary, sort_keys=True)


def _stage_fixture_list_show() -> tuple[int, str]:
    fixture = (
        REPO
        / "tests"
        / "fixtures"
        / "claude"
        / "s-cla-01-ordered-parent-chain"
        / "root"
    )
    list_run = run(
        [
            sys.executable,
            str(REPO / "scripts" / "portable-resume"),
            "claude",
            "list",
            "--cwd",
            "/workspace/project",
            "--source-root",
            str(fixture),
            "--within-min",
            "0",
            "--json",
        ]
    )
    show_run = run(
        [
            sys.executable,
            str(REPO / "scripts" / "portable-resume"),
            "claude",
            "show",
            "latest",
            "--cwd",
            "/workspace/project",
            "--source-root",
            str(fixture),
            "--within-min",
            "0",
            "--format",
            "handoff",
        ]
    )
    code = 0 if list_run.returncode == 0 and show_run.returncode == 0 else 1
    note = (
        f"list={list_run.returncode} show={show_run.returncode} "
        f"untrusted={'untrusted' in (show_run.stdout or '').lower()}"
    )
    return code, note


STAGE_RUNNERS: dict[str, Callable[[], tuple[int, str]]] = {
    "compile": _stage_compile,
    "version_state": _stage_version_state,
    "docs": _stage_docs,
    "secrets": _stage_secrets,
    "unit": _stage_unit,
    "unit_portable": _stage_unit_portable,
    "packaging": _stage_packaging,
    "reader_self_check": _stage_reader_self_check,
    "installer_matrix": _stage_installer_matrix,
    "fixture_list_show": _stage_fixture_list_show,
    "windows_source_fixtures": _stage_windows_source_fixtures,
    "windows_negative_diagnostics": _stage_windows_negative_diagnostics,
}


def resolve_stages(*, profile: str | None, only: list[str] | None) -> list[str]:
    if only:
        unknown = [name for name in only if name not in STAGE_NAMES]
        if unknown:
            raise SystemExit(f"unknown stage(s): {', '.join(unknown)}")
        # Preserve allowlist order, not CLI order, for deterministic reports.
        selected = [name for name in STAGE_NAMES if name in set(only)]
        if not selected:
            raise SystemExit("no stages selected")
        return selected
    if profile is None:
        profile = "local"
    if profile not in PROFILES:
        raise SystemExit(
            f"unknown profile: {profile!r} (choose from {', '.join(sorted(PROFILES))})"
        )
    return list(PROFILES[profile])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default=None,
        help="named stage set (default: local when --only is omitted)",
    )
    parser.add_argument(
        "--only",
        action="append",
        dest="only",
        metavar="STAGE",
        help="run only named stage(s); may be repeated; closed allowlist",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable stage results on stdout",
    )
    args = parser.parse_args(argv)
    if args.profile is not None and args.only:
        raise SystemExit("use either --profile or --only, not both")

    stages = resolve_stages(profile=args.profile, only=args.only)
    print("repo", REPO)
    print("profile", args.profile or ("only" if args.only else "local"))
    print("stages", " ".join(stages))

    results: list[dict[str, object]] = []
    overall_ok = True
    for name in stages:
        started = time.monotonic()
        code, detail = STAGE_RUNNERS[name]()
        elapsed_ms = int((time.monotonic() - started) * 1000)
        ok = code == 0
        overall_ok = overall_ok and ok
        results.append(
            {
                "stage": name,
                "ok": ok,
                "exit_code": code,
                "elapsed_ms": elapsed_ms,
                "detail": detail[:2000],
            }
        )
        if name == "version_state":
            print(detail)
            print("version-state", code)
        elif name == "docs":
            print(detail)
            print("docs", code)
        elif name == "unit":
            print(detail)
            print("unittest", code)
        elif name == "packaging":
            print(detail)
            print("packaging", code)
        elif name == "reader_self_check":
            print(detail)
            print("self-check", code)
        elif name == "installer_matrix":
            print("matrix", code, detail)
        elif name == "fixture_list_show":
            print("fixture", detail)
        elif name == "windows_source_fixtures":
            # Always print ok=N/17 detail so Actions logs prove the all-sources gate.
            print("windows_source_fixtures", code, detail)
        elif name == "unit_portable":
            print("unit_portable", code)
            if detail and code != 0:
                print(detail[-800:])
        elif name == "secrets":
            print("secrets", code)
            if detail:
                print(detail)
        else:
            print(name, code)

    print("OVERALL_SELF_VERIFY", "PASS" if overall_ok else "FAIL")
    if args.json:
        report = {
            "schema_version": "portable-resume/self-verify-v1",
            "ok": overall_ok,
            "profile": args.profile or ("only" if args.only else "local"),
            "stages": results,
        }
        print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
