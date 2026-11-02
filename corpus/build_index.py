"""Build corpus/index.json from manuscript.md.

Locator = chapter.section.paragraph. Pagination is not assigned here; the
resolver returns page=null and pagination_status="pending".
"""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

CH = re.compile(r"^##\s+Chapter\s+(\d+)\s+[—-]\s+(.+?)\s*\{#ch\d+\}", re.M)
SEC = re.compile(r"^###\s+(\d+)\.(\d+)\s+(.+?)\s*\{#ch\d+-s\d+\}", re.M)
NOISE = re.compile(r"^(:::|\||```|!\[|\s*$)")


def clean(s: str) -> str:
    s = re.sub(r"\{#[^}]*\}", "", s)
    s = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", s)
    s = re.sub(r"[*_`#>]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s.strip()


def sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z“\"(])", text)
    return [p.strip() for p in parts if len(p.split()) >= 4]


def build(path: Path) -> list[dict]:
    md = path.read_text(encoding="utf-8")
    chapters = [(m.start(), int(m.group(1)), clean(m.group(2))) for m in CH.finditer(md)]
    out: list[dict] = []

    for i, (start, ch_no, ch_title) in enumerate(chapters):
        end = chapters[i + 1][0] if i + 1 < len(chapters) else len(md)
        block = md[start:end]
        for j, sm in enumerate(SEC.finditer(block)):
            s_end = SEC.search(block, sm.end())
            s_end = s_end.start() if s_end else len(block)
            body = block[sm.end():s_end]

            paras = [p for p in re.split(r"\n\s*\n", body)
                     if p.strip() and not NOISE.match(p.strip())]
            k = 0
            for para in paras:
                txt = clean(para)
                if len(txt.split()) < 4:
                    continue
                for s in sentences(txt):
                    k += 1
                    out.append({
                        "locator": f"{ch_no}.{int(sm.group(2))}.{k}",
                        "chapter": ch_no,
                        "chapter_title": ch_title,
                        "text": s,
                        "page": None,
                        "pagination_status": "pending",
                    })
    return out


if __name__ == "__main__":
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "manuscript.md")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else "corpus/index.json")
    idx = build(src)
    dst.write_text(json.dumps(idx, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"indexed {len(idx)} sentences from {src} -> {dst}")
