# Repository metadata policy and maintenance

Tracked source of truth for public GitHub metadata (About description, homepage URL, repository topics).

## File

- [`repository-metadata.json`](./repository-metadata.json): Schema `portable-resume/repo-metadata-v1`.

## Fields

| Field | Purpose | Validation |
|---|---|---|
| `schema_version` | Schema identifier (`portable-resume/repo-metadata-v1`) | Must match exact schema identifier |
| `description` | Public GitHub About text | Must be count-free (no stale 9×9/81 claims), describe offline context handoff into fresh sessions, and preserve the not-live-restore boundary |
| `homepage` | Canonical documentation URL | Must point to repository documentation |
| `topics` | Bounded list of public repository topics | Bounded set of kebab-case search tags |

## Maintenance procedure

1. **Who updates:** The repository maintainer with administrative or repository settings access.
2. **When to update:**
   - On release or when capabilities change, update `docs/metadata/repository-metadata.json` via PR.
   - After merging to `main`, the maintainer applies the change to GitHub settings or runs:
     ```bash
     # Update description and homepage
     gh repo edit --description "<description>" --homepage "<homepage>"

     # Reconcile topics using GitHub API:
     gh api --method PUT repos/:owner/:repo/topics --input docs/metadata/repository-metadata.json --jq .names
     # or update topics interactively:
     # gh repo edit --add-topic "<topic>" --remove-topic "<stale-topic>"
     ```
3. **Validation:**
   - Offline CI validates `docs/metadata/repository-metadata.json` via `python3 scripts/check_docs.py`.
   - Normal PR CI requires no GitHub API tokens or write credentials.
   - Optional maintainer check:
     ```bash
     python3 scripts/check_docs.py --check-live-metadata
     ```
