"""Copy the action catalog from abr/catalog.py into docs/index.html.

Run this after editing abr/catalog.py so the web playground uses the same rules:

    python scripts/sync_web_catalog.py
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from abr import catalog  # noqa: E402

PAGE = ROOT / "docs" / "index.html"
MARKER = re.compile(r"/\*CATALOG_START\*/.*?/\*CATALOG_END\*/", re.DOTALL)


def catalog_json():
    return json.dumps({
        "risky_actions": catalog.RISKY_ACTIONS,
        "escalation_paths": [[n, r, w] for n, r, w in catalog.ESCALATION_PATHS],
        "labels": catalog.CATEGORY_LABELS,
    }, separators=(",", ":"))


def main():
    html = PAGE.read_text(encoding="utf-8")
    if not MARKER.search(html):
        sys.exit("catalog markers not found in docs/index.html")
    new = MARKER.sub(lambda _: f"/*CATALOG_START*/{catalog_json()}/*CATALOG_END*/", html)
    PAGE.write_text(new, encoding="utf-8")
    print("docs/index.html catalog updated")


if __name__ == "__main__":
    main()
