from __future__ import annotations

import unittest

from portable_resume.decision_rationale import MAX_SNIPPETS, extract_decision_snippets
from portable_resume.handoff import RATIONALE_HEADING, render_handoff
from portable_resume.model import Envelope, Query, Session, Turn


class DecisionRationaleTests(unittest.TestCase):
    def test_newest_matching_user_and_assistant_lines_are_kept(self) -> None:
        turns = (
            Turn(0, "user", "Please try sqlite first."),
            Turn(1, "assistant", "We tried sqlite; it will not work on this dump."),
            Turn(2, "tool", "instead of this tool noise", tool_name="Bash"),
            Turn(3, "assistant", "Went with a file snapshot instead of sqlite."),
        )
        snippets = extract_decision_snippets(turns)
        self.assertEqual(
            snippets,
            (
                "Went with a file snapshot instead of sqlite.",
                "We tried sqlite; it will not work on this dump.",
            ),
        )

    def test_code_fences_and_short_lines_are_ignored(self) -> None:
        turns = (
            Turn(
                0,
                "assistant",
                "```\ninstead of matching this\n```\nok\nDo not use GIT_AUTHOR_EMAIL=codex@example.com.",
            ),
        )
        snippets = extract_decision_snippets(turns)
        self.assertEqual(
            snippets,
            ("Do not use GIT_AUTHOR_EMAIL=codex@example.com.",),
        )

    def test_cap_and_dedupe_are_deterministic(self) -> None:
        turns = tuple(
            Turn(i, "assistant", f"Instead of option {i} we keep going.")
            for i in range(MAX_SNIPPETS + 4)
        ) + (Turn(99, "assistant", "Instead of option 3 we keep going."),)
        snippets = extract_decision_snippets(turns)
        self.assertEqual(len(snippets), MAX_SNIPPETS)
        self.assertEqual(snippets[0], "Instead of option 3 we keep going.")
        self.assertEqual(snippets[1], f"Instead of option {MAX_SNIPPETS + 3} we keep going.")
        self.assertEqual(len(set(s.casefold() for s in snippets)), MAX_SNIPPETS)

    def test_handoff_quotes_rationale_and_keeps_empty_honest(self) -> None:
        with_why = Session(
            source="claude",
            session_id="session-1",
            last_user_request="continue",
            last_assistant_action="ok",
            turns=(
                Turn(0, "user", "continue"),
                Turn(1, "assistant", "Don't use --no-verify; that failed on the last pass."),
            ),
        )
        empty = Session(
            source="claude",
            session_id="session-2",
            last_user_request="continue",
            last_assistant_action="ok",
            turns=(Turn(0, "user", "continue"), Turn(1, "assistant", "ok")),
        )
        why_doc = render_handoff(
            Envelope.create(
                operation="show",
                query=Query("claude"),
                sessions=(with_why,),
                generated_at="2026-07-20T00:00:00Z",
            )
        )
        empty_doc = render_handoff(
            Envelope.create(
                operation="show",
                query=Query("claude"),
                sessions=(empty,),
                generated_at="2026-07-20T00:00:00Z",
            )
        )
        self.assertIn(RATIONALE_HEADING, why_doc)
        self.assertLess(why_doc.index("## Warnings"), why_doc.index(RATIONALE_HEADING))
        self.assertLess(
            why_doc.index(RATIONALE_HEADING),
            why_doc.index("### Bounded transcript evidence"),
        )
        containing = [
            line
            for line in why_doc.splitlines()
            if "Don't use --no-verify; that failed on the last pass." in line
        ]
        self.assertTrue(containing)
        self.assertTrue(all(line.startswith(">") for line in containing))
        self.assertIn("_(no rejection/rationale phrases recovered)_", empty_doc)
        action = empty_doc[
            empty_doc.index("### Latest recorded action") : empty_doc.index("## Warnings")
        ]
        self.assertNotIn(RATIONALE_HEADING, action)


if __name__ == "__main__":
    unittest.main()
