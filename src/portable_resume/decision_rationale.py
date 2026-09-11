"""Best-effort recovery of rejected approaches and decision 'why'.

Phrase-scan of persisted user/assistant text only. Not a reconstructed
decision tree and not live session restore (#299).
"""

from __future__ import annotations

from .model import Turn

MAX_SNIPPETS = 8
MAX_SNIPPET_CHARS = 240

# Frozen, lowercase cues. Keep this list conservative: a lone "don't" is too noisy.
_CUES: tuple[str, ...] = (
    "instead of ",
    "rather than ",
    "already tried",
    "we tried ",
    "tried that",
    "rejected ",
    "won't work",
    "will not work",
    "do not use ",
    "don't use ",
    "do not set ",
    "don't set ",
    "abandoned ",
    "dropped because",
    "not going to ",
    "does not override",
    "cannot rewrite",
    "dead end",
    "false start",
    "went with ",
    "chose this because",
    "that failed",
    "did not work",
    "doesn't work",
)


def _line_matches(line: str) -> bool:
    lower = line.casefold()
    return any(cue in lower for cue in _CUES)


def _first_cue_index(line: str) -> int:
    lower = line.casefold()
    hits = [lower.find(cue) for cue in _CUES if cue in lower]
    return min(hits) if hits else -1


def _capped_snippet(line: str) -> str:
    """Keep a 240-char window that still contains the matched cue."""

    if len(line) <= MAX_SNIPPET_CHARS:
        return line
    idx = _first_cue_index(line)
    if idx < 0:
        return line[:MAX_SNIPPET_CHARS]
    start = idx
    end = start + MAX_SNIPPET_CHARS
    if end > len(line):
        start = max(0, len(line) - MAX_SNIPPET_CHARS)
        end = len(line)
    return line[start:end]


def _fence_run(stripped: str) -> tuple[str, int] | None:
    """Return (fence char, run length) for a CommonMark-style fence line."""

    if not stripped:
        return None
    ch = stripped[0]
    if ch not in {"`", "~"}:
        return None
    n = 0
    for c in stripped:
        if c != ch:
            break
        n += 1
    if n < 3:
        return None
    return ch, n


def extract_decision_snippets(turns: tuple[Turn, ...]) -> tuple[str, ...]:
    """Return newest-first unique snippets from user/assistant turns."""

    found: list[str] = []
    seen: set[str] = set()
    for turn in reversed(turns):
        if turn.role not in {"user", "assistant"}:
            continue
        open_fence: tuple[str, int] | None = None
        for raw in turn.content.splitlines():
            stripped = raw.strip()
            fence = _fence_run(stripped)
            if open_fence is None:
                if fence is not None:
                    open_fence = fence
                    continue
            else:
                if fence is not None and fence[0] == open_fence[0] and fence[1] >= open_fence[1]:
                    open_fence = None
                continue
            if len(stripped) < 12:
                continue
            if not _line_matches(stripped):
                continue
            snippet = _capped_snippet(stripped)
            key = snippet.casefold()
            if key in seen:
                continue
            seen.add(key)
            found.append(snippet)
            if len(found) >= MAX_SNIPPETS:
                return tuple(found)
    return tuple(found)
