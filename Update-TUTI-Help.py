from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HELP_PATH = ROOT / "TUTI-Help.html"
UPDATED = "2026-11-08"
GENERATED_AT = "2026-11-08"

ARTICLES = [
    ("docs/OIDC-DISCOVERY.md", "BaaS-Contractor", "authentication"),
    ("tools/TUTI-OPERATIONS-DESKTOP.md", "XreaOperationsDesktop", "operations"),
    ("tools/POWERSHELL-OPERATIONS.md", "Xrea-Operations", "operations"),
    ("docs/SSO-CONTRACTOR-INVITE.md", "BaaS-Contractor", "authentication"),
    ("docs/SSO-HEALTH-READINESS.md", "SSO-INITIAL-SETUP", "operations"),
    ("docs/SSO-DATABASE-OPERATIONS.md", "sso-service", "database"),
    ("docs/PRODUCT-KEY-ISSUANCE-V8.md", "BaaS-Contractor", "api"),
    ("docs/MNSL-SSO-ISSUE-HELP.md", "MyNumberSmartLogin", "operations"),
]


def load_articles() -> list[dict[str, object]]:
    articles = []
    for relative_path, project, category in ARTICLES:
        source = ROOT / relative_path
        if not source.is_file():
            raise SystemExit(f"Markdown source not found: {source}")
        content = source.read_text(encoding="utf-8-sig")
        heading = re.search(r"^#\s+(.+?)\s*$", content, re.MULTILINE)
        if not heading:
            raise SystemExit(f"Markdown has no top-level heading: {source}")
        articles.append({
            "path": relative_path,
            "title": heading.group(1),
            "project": project,
            "category": category,
            "content": content,
            "historical": False,
            "updated": UPDATED,
        })
    return articles


def main() -> None:
    if not HELP_PATH.is_file():
        raise SystemExit(f"Help page not found: {HELP_PATH}")
    page = HELP_PATH.read_text(encoding="utf-8")
    pattern = re.compile(
        r'(<script id="documents-data" type="application/json">)(.*?)(</script>)',
        re.DOTALL,
    )
    match = pattern.search(page)
    if not match:
        raise SystemExit("Embedded documents-data block was not found.")

    documents = json.loads(match.group(2))
    replacements = {article["path"]: article for article in load_articles()}
    known_paths = set(replacements)
    updated_documents = []
    found_paths = set()
    for document in documents:
        path = document.get("path")
        if path in replacements:
            updated_documents.append(replacements[path])
            found_paths.add(path)
        else:
            # Verification snapshots are archived evidence, not current help.
            if path == "8888/_organized_archive_20260916/.verification/android-uiux-r33/MyNumberSmartLogin-Project/FACE-LIVENESS-V2.md":
                document["historical"] = True
            updated_documents.append(document)
    for path, article in replacements.items():
        if path not in found_paths:
            updated_documents.append(article)

    serialized = json.dumps(updated_documents, ensure_ascii=False, separators=(",", ":"))
    serialized = serialized.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    page = page[: match.start(2)] + serialized + page[match.end(2) :]
    page = re.sub(
        r"<footer>.*?</footer>",
        f"<footer>資料 {len(updated_documents)} 件<br>更新日 {UPDATED}・オフライン閲覧対応</footer>",
        page,
        count=1,
        flags=re.DOTALL,
    )
    HELP_PATH.write_text(page, encoding="utf-8", newline="")
    print(f"Updated {HELP_PATH} from {len(ARTICLES)} Markdown source files ({len(updated_documents)} total articles).")


if __name__ == "__main__":
    main()
