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


def extract_decision_snippets(turns: tuple[Turn, ...]) -> tuple[str, ...]:
    """Return newest-first unique snippets from user/assistant turns."""

    found: list[str] = []
    seen: set[str] = set()
    for turn in reversed(turns):
        if turn.role not in {"user", "assistant"}:
            continue
        in_fence = False
        for raw in turn.content.splitlines():
            stripped = raw.strip()
            if stripped.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence or len(stripped) < 12:
                continue
            if not _line_matches(stripped):
                continue
            snippet = stripped[:MAX_SNIPPET_CHARS]
            key = snippet.casefold()
            if key in seen:
                continue
            seen.add(key)
            found.append(snippet)
            if len(found) >= MAX_SNIPPETS:
                return tuple(found)
    return tuple(found)
