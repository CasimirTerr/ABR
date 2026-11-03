"""The web playground embeds a copy of the catalog. Make sure it hasn't drifted."""

import json
import re
from pathlib import Path

from abr import catalog

PAGE = Path(__file__).resolve().parent.parent / "docs" / "index.html"


def test_web_catalog_matches_python():
    html = PAGE.read_text(encoding="utf-8")
    match = re.search(r"/\*CATALOG_START\*/(.*?)/\*CATALOG_END\*/", html, re.DOTALL)
    assert match, "catalog markers missing from docs/index.html"
    embedded = json.loads(match.group(1))
    assert embedded["risky_actions"] == catalog.RISKY_ACTIONS
    assert embedded["escalation_paths"] == [[n, r, w] for n, r, w in catalog.ESCALATION_PATHS]
    assert embedded["labels"] == catalog.CATEGORY_LABELS, (
        "Run `python scripts/sync_web_catalog.py` after editing abr/catalog.py")
