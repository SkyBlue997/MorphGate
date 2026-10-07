#!/usr/bin/env python3
"""Check relative Markdown links and #anchors the way GitHub renders them.

Default scope: root project Markdown files and docs/**/*.md.
Pass file or directory paths to check something else.

For every inline link / image ``[text](target)``, reference definition
``[label]: target`` and HTML ``href``/``src`` attribute:

* external targets (``https:``, ``mailto:``, ``//host`` ...) are ignored;
* the path part must exist relative to the linking file, with exact letter
  case (macOS file systems are case-insensitive, GitHub is not) and without
  escaping the repository;
* a ``#fragment`` pointing into a Markdown file must equal the GitHub slug of
  one of its headings (github-slugger rules, including ``-1`` suffixes for
  duplicates) or an explicit ``id``/``name`` attribute.

Fenced code blocks and inline code spans are ignored. Exit status: 0 when all
links resolve, 1 when any is broken, 2 on usage errors.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FILES = ("README.md", "CLAUDE.md", "SECURITY.md", "MAINTAINERS.md", "THIRD_PARTY_NOTICES.md")
DEFAULT_DIRS = ("docs",)
MARKDOWN_SUFFIXES = {".md", ".markdown"}

# scheme: (RFC 3986) or protocol-relative //host
EXTERNAL_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.\-]*:|//)")
# Fences are matched at any indentation so code blocks nested in list items count.
FENCE_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})(.*)$")
ATX_HEADING_RE = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")
SETEXT_UNDERLINE_RE = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
# Reference definition "[label]: target"; footnotes "[^1]: text" are not links.
REF_DEF_RE = re.compile(r"^ {0,3}\[(?!\^)((?:[^\[\]\\]|\\.)+)\]:[ \t]*(<[^>\n]*>|\S+)")
# Start of an inline link: "[" label "](" -- the label may contain one level of
# nested brackets, e.g. [see [03]](docs/03.md).
LINK_OPEN_RE = re.compile(r"!?\[(?:[^\[\]\\]|\\.|\[(?:[^\[\]\\]|\\.)*\])*\]\(")
HTML_ATTR_RE = re.compile(r"""<(?:a|img|source)\b[^>]*?\s(?:href|src)\s*=\s*["']([^"']+)["']""", re.I)
HTML_ID_RE = re.compile(r"""<[A-Za-z][^>]*?\s(?:id|name)\s*=\s*["']([^"']+)["']""")
HTML_TAG_RE = re.compile(r"<[^>]+>")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
CODE_SPAN_RE = re.compile(r"(?<!`)(`+)(?!`)(.+?)(?<!`)\1(?!`)")


# ---------------------------------------------------------------------------
# Markdown scanning
# ---------------------------------------------------------------------------


def strip_code_spans(line: str) -> str:
    """Replace inline code spans with spaces so links inside them are ignored."""
    return CODE_SPAN_RE.sub(lambda m: " " * len(m.group(0)), line)


def iter_prose_lines(text: str):
    """Yield (line_number, line) for lines outside fenced code blocks.

    HTML comments are blanked first (line count preserved) because GitHub does
    not render links or headings inside them.
    """
    text = HTML_COMMENT_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if fence is None:
            if match and not (match.group(1)[0] == "`" and "`" in match.group(2)):
                fence = match.group(1)
                continue
            yield number, line
        elif match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence) \
                and not match.group(2).strip():
            fence = None


def heading_text(raw: str) -> str:
    """Approximate the rendered text of a heading (what GitHub slugs)."""
    text = re.sub(r"[ \t]+#+[ \t]*$", "", raw)          # closing ATX sequence
    text = re.sub(r"^#+$", "", text)
    text = CODE_SPAN_RE.sub(lambda m: m.group(2).strip(), text)
    text = re.sub(r"!\[([^\]]*)\]\([^)]*\)", "", text)  # images contribute nothing
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # inline links -> text
    text = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", text)  # reference links -> text
    text = HTML_TAG_RE.sub("", text)
    text = re.sub(r"\\(.)", r"\1", text)                 # backslash escapes
    # Emphasis markers disappear when rendered; "_" inside words stays.
    text = re.sub(r"(\*{1,3}|(?<!\w)_{1,3}|_{1,3}(?!\w)|~~)", "", text)
    return text.strip()


def github_slug(text: str) -> str:
    """github-slugger: lowercase, drop everything except letters, marks,
    numbers, connector punctuation, spaces and '-', then spaces -> '-'."""
    kept = []
    for ch in text.lower():
        if ch in (" ", "-"):
            kept.append(ch)
            continue
        category = unicodedata.category(ch)
        if category[0] in ("L", "M", "N") or category == "Pc":
            kept.append(ch)
    return "".join(kept).replace(" ", "-")


class Slugger:
    """Stateful slugger that de-duplicates like github-slugger."""

    def __init__(self) -> None:
        self.occurrences: dict[str, int] = {}

    def slug(self, text: str) -> str:
        base = github_slug(text)
        result = base
        while result in self.occurrences:
            self.occurrences[base] += 1
            result = f"{base}-{self.occurrences[base]}"
        self.occurrences[result] = 0
        return result


def collect_anchors(text: str) -> set[str]:
    """All fragment ids a Markdown file exposes on GitHub."""
    slugger = Slugger()
    anchors: set[str] = set()
    previous: str | None = None  # previous prose line, for setext headings
    last_number = 0
    for number, line in iter_prose_lines(text):
        if number != last_number + 1:
            previous = None  # a fenced block sat in between
        last_number = number
        for match in HTML_ID_RE.finditer(line):
            anchors.add(match.group(1))
        stripped = re.sub(r"^ {0,3}(?:> ?)+", "", line)  # headings inside quotes count
        atx = ATX_HEADING_RE.match(stripped)
        setext = SETEXT_UNDERLINE_RE.match(line)
        if atx:
            anchors.add(slugger.slug(heading_text(atx.group(2) or "")))
            previous = None
            continue
        if setext and previous is not None and previous.strip() \
                and not re.match(r"^ {0,3}([-*+]|\d+[.)])\s", previous):
            anchors.add(slugger.slug(heading_text(previous.strip())))
            previous = None
            continue
        previous = line
    anchors.discard("")
    return anchors


def parse_destination(line: str, start: int) -> str | None:
    """Parse a link destination beginning at line[start] (just after '(')."""
    i = start
    while i < len(line) and line[i] in " \t":
        i += 1
    if i < len(line) and line[i] == "<":
        end = line.find(">", i + 1)
        return None if end == -1 else line[i + 1:end]
    depth = 0
    out = []
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            out.append(line[i + 1])
            i += 2
            continue
        if ch in " \t":
            break
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        out.append(ch)
        i += 1
    return "".join(out)


def iter_links(text: str):
    """Yield (line_number, target) for every link-like reference in prose."""
    for number, line in iter_prose_lines(text):
        prose = strip_code_spans(line)
        ref = REF_DEF_RE.match(prose)
        if ref:
            yield number, ref.group(2).strip("<>")
        for match in LINK_OPEN_RE.finditer(prose):
            target = parse_destination(prose, match.end())
            if target is not None:
                yield number, target
        for match in HTML_ATTR_RE.finditer(prose):
            yield number, match.group(1)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def exists_exact_case(path: Path, root: Path) -> bool:
    """True if every component of `path` below `root` exists with this exact case."""
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return False
    current = root
    for part in parts:
        try:
            if part not in os.listdir(current):
                return False
        except (NotADirectoryError, FileNotFoundError):
            return False
        current = current / part
    return True


@dataclass(frozen=True)
class Problem:
    file: str  # path relative to the repository root
    line: int
    target: str
    reason: str

    def __str__(self) -> str:
        return f"{self.file}:{self.line}: {self.target} -> {self.reason}"


class Checker:
    """Resolves link targets against one repository root; caches anchors per file."""

    def __init__(self, root: Path = REPO_ROOT) -> None:
        self.root = root.resolve()
        self._anchor_cache: dict[Path, set[str]] = {}
        self.links_checked = 0

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix() if path.is_relative_to(self.root) else str(path)

    def anchors_of(self, path: Path) -> set[str]:
        if path not in self._anchor_cache:
            self._anchor_cache[path] = collect_anchors(path.read_text(encoding="utf-8"))
        return self._anchor_cache[path]

    def check_target(self, source: Path, target: str) -> str | None:
        """Return why `target` (as written in `source`) is broken, or None.

        External and empty targets are never broken.
        """
        target = target.strip()
        if not target or EXTERNAL_RE.match(target):
            return None
        self.links_checked += 1
        source = source.resolve()
        path_part, _, fragment = target.partition("#")
        path_part = unquote(path_part.split("?", 1)[0])
        fragment = unquote(fragment)

        if path_part:
            if path_part.startswith("/"):  # GitHub resolves these from the repo root
                resolved = (self.root / path_part.lstrip("/")).resolve()
            else:
                resolved = (source.parent / path_part).resolve()
            if not resolved.is_relative_to(self.root):
                return "points outside the repository"
            if not resolved.exists():
                return "file not found"
            if not exists_exact_case(resolved, self.root):
                return "letter case differs from the file on disk (breaks on GitHub)"
        else:
            resolved = source

        if not fragment or resolved.is_dir() or resolved.suffix.lower() not in MARKDOWN_SUFFIXES:
            return None  # e.g. #L10 line anchors on source files are not checked
        if fragment not in self.anchors_of(resolved):
            where = "this file" if resolved == source else self.rel(resolved)
            return f"no heading or id '#{fragment}' in {where}"
        return None

    def check_file(self, path: Path) -> list[Problem]:
        problems = []
        for line, target in iter_links(path.read_text(encoding="utf-8")):
            reason = self.check_target(path, target)
            if reason:
                problems.append(Problem(self.rel(path.resolve()), line, target, reason))
        return problems


def default_files(root: Path = REPO_ROOT) -> list[Path]:
    files = [root / name for name in DEFAULT_FILES if (root / name).is_file()]
    for directory in DEFAULT_DIRS:
        files.extend(sorted((root / directory).rglob("*.md")))
    return files


def expand(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw).resolve()
        if path.is_dir():
            files.extend(sorted(path.rglob("*.md")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(raw)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="*", help="Markdown files or directories (default: root project Markdown files and docs/)")
    args = parser.parse_args(argv)
    try:
        files = expand(args.paths) if args.paths else default_files()
    except FileNotFoundError as err:
        print(f"check_doc_links: no such file or directory: {err}", file=sys.stderr)
        return 2
    files = [f for f in files if "node_modules" not in f.parts]

    checker = Checker()
    problems: list[Problem] = []
    for path in files:
        problems.extend(checker.check_file(path))

    for problem in problems:
        print(problem)
    summary = f"{len(files)} files, {checker.links_checked} relative links checked"
    if problems:
        print(f"check_doc_links: FAILED - {len(problems)} broken link(s); {summary}", file=sys.stderr)
        return 1
    print(f"check_doc_links: OK - {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
