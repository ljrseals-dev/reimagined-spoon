"""resolve_citation: the only access to the manuscript.

Returns a verified locator, a verbatim quote (<= 40 words), a page or None,
and an APA reference. A quote that is not found is a forbidden fact.
"""
from __future__ import annotations
import json
import re
from pathlib import Path

TITLE = ("AI systems for IGCSE and AS Level computer science: "
         "Building and testing reliable AI applications")
MAX_QUOTE_WORDS = 40


def _norm(s: str) -> str:
    s = re.sub(r"[*_`#>]", "", s or "")
    s = re.sub(r"\s+", " ", s)
    return s.strip().lower()


class Resolver:
    def __init__(self, index_path: str | Path):
        self.entries = json.loads(Path(index_path).read_text(encoding="utf-8"))
        for e in self.entries:
            e["_norm"] = _norm(e["text"])

    # -- tool ---------------------------------------------------------------
    def resolve_citation(self, phrase: str, chapter: int | None = None) -> dict:
        if not 6 <= len(phrase) <= 200:
            return self._miss("phrase length out of range (6-200 characters)")

        p = _norm(phrase)
        candidates = [e for e in self.entries
                      if chapter is None or e["chapter"] == chapter]

        hits = [e for e in candidates if p in e["_norm"]]
        if not hits:
            return self._miss(f"no match for {phrase!r}")

        # prefer the shortest containing sentence (least context, most precision)
        e = min(hits, key=lambda x: len(x["text"]))
        quote, truncated = _window(e["text"], phrase)

        return {
            "found": True,
            "locator": e["locator"],
            "chapter": e["chapter"],
            "chapter_title": e["chapter_title"],
            "page": e.get("page"),                       # None until paginated
            "pagination_status": e.get("pagination_status", "pending"),
            "quote": quote,
            "truncated": truncated,
            "apa": self._apa(e),
            "error": None,
        }

    # -- helpers ------------------------------------------------------------
    @staticmethod
    def _miss(reason: str) -> dict:
        return {"found": False, "locator": "", "chapter": None,
                "chapter_title": "", "page": None,
                "pagination_status": "pending", "quote": "", "truncated": False,
                "apa": "", "error": reason}

    def _apa(self, e: dict) -> str:
        sec = ".".join(e["locator"].split(".")[:2])
        para = e["locator"].split(".")[-1]
        if e.get("page") is not None:
            loc = f"p. {e['page']}"
        else:
            loc = f"Ch. {e['chapter']}, §{sec}, para. {para}"
        return (f"Seals, L. J., Jr., & Seals, L. S. (2026). {e['chapter_title']}. "
                f"In *{TITLE}* ({loc}). Lewis Seals Publishing L3C.")

    def verbatim_at(self, locator: str, quote: str) -> bool:
        for e in self.entries:
            if e["locator"] == locator:
                return _norm(quote) in e["_norm"]
        return False

    def chapter_of(self, locator: str) -> int | None:
        for e in self.entries:
            if e["locator"] == locator:
                return e["chapter"]
        return None


def _window(sentence: str, phrase: str) -> tuple[str, bool]:
    """Trim to <= MAX_QUOTE_WORDS at a word boundary, keeping the phrase."""
    words = sentence.split()
    if len(words) <= MAX_QUOTE_WORDS:
        return sentence.strip(), False
    p = _norm(phrase)
    # find the window that contains the phrase
    for start in range(0, len(words) - MAX_QUOTE_WORDS + 1):
        chunk = " ".join(words[start:start + MAX_QUOTE_WORDS])
        if p in _norm(chunk):
            return chunk.strip() + " …", True
    return " ".join(words[:MAX_QUOTE_WORDS]).strip() + " …", True
