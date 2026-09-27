"""Tests for check_doc_links.py. Run: python3 -m unittest discover -s scripts -p 'test_*.py'"""

from __future__ import annotations

import contextlib
import io
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_doc_links as cdl  # noqa: E402


class SlugTest(unittest.TestCase):
    def test_github_slugs_for_existing_doc_headings(self):
        # Anchors that other MorphGate docs link to (revision brief, section D).
        cases = {
            "2. 分类（BotClass）": "2-分类botclass",
            "5. 分级处置": "5-分级处置",
            "7. 客户端信号采集（Web / Mobile SDK）": "7-客户端信号采集web--mobile-sdk",
            "8. Morph 动态变形": "8-morph-动态变形",
            "7. 隐私与合规": "7-隐私与合规",
        }
        for heading, slug in cases.items():
            with self.subTest(heading=heading):
                self.assertEqual(cdl.github_slug(cdl.heading_text(heading)), slug)

    def test_punctuation_underscore_and_markup(self):
        self.assertEqual(cdl.github_slug(cdl.heading_text("3.4 Cloudflare 边缘 TLS（EDGE_TLS）")),
                         "34-cloudflare-边缘-tlsedge_tls")
        self.assertEqual(cdl.github_slug(cdl.heading_text("Use `mgctl cf audit` **now**!")),
                         "use-mgctl-cf-audit-now")
        self.assertEqual(cdl.github_slug(cdl.heading_text("See [ADR 7](adr/0007.md) ##")), "see-adr-7")

    def test_duplicate_headings_get_numbered(self):
        slugger = cdl.Slugger()
        self.assertEqual([slugger.slug("参考") for _ in range(3)], ["参考", "参考-1", "参考-2"])

    def test_anchors_skip_fenced_code_and_include_setext_and_ids(self):
        text = textwrap.dedent("""\
            # Title

            ```bash
            # not a heading
            ```

            Setext Heading
            --------------

            <a id="custom-anchor"></a>
            """)
        anchors = cdl.collect_anchors(text)
        self.assertEqual(anchors, {"title", "setext-heading", "custom-anchor"})


class LinkExtractionTest(unittest.TestCase):
    def test_extracts_inline_reference_and_html_links_but_not_code(self):
        text = textwrap.dedent("""\
            See [a](docs/a.md#x "title") and ![img](img/p.png) and <a href="b.md">b</a>.
            Nested [label [x]](c.md) and parens [p](d_(1).md) and <angle>: [q](<e f.md>).
            Code `[no](nope.md)` is ignored.
            [ref]: ref.md
            [^1]: A footnote, not a link.

            ~~~
            [no](fenced.md)
            ~~~
            """)
        targets = [t for _, t in cdl.iter_links(text)]
        self.assertEqual(targets, ["docs/a.md#x", "img/p.png", "b.md", "c.md", "d_(1).md", "e f.md", "ref.md"])


class CheckerTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name).resolve()
        (self.root / "docs").mkdir()
        (self.root / "docs" / "target.md").write_text("# Target\n\n## 2. 分类（BotClass）\n", encoding="utf-8")
        (self.root / "docs" / "code.rs").write_text("fn main() {}\n", encoding="utf-8")
        self.checker = cdl.Checker(self.root)

    def tearDown(self):
        self._tmp.cleanup()

    def check(self, body: str) -> list[str]:
        source = self.root / "README.md"
        source.write_text(body, encoding="utf-8")
        return [p.reason for p in self.checker.check_file(source)]

    def test_valid_links_pass(self):
        body = textwrap.dedent("""\
            # Intro
            [t](docs/target.md) [a](docs/target.md#2-分类botclass) [enc](docs/target.md#2-%E5%88%86%E7%B1%BBbotclass)
            [self](#intro) [dir](docs/) [src](docs/code.rs#L1) [ext](https://example.com/x.md#nope)
            [root](/docs/target.md#target)
            """)
        self.assertEqual(self.check(body), [])
        self.assertEqual(self.checker.links_checked, 7)  # the https link is not counted

    def test_missing_file(self):
        self.assertEqual(self.check("[x](docs/missing.md)\n"), ["file not found"])

    def test_missing_anchor(self):
        reasons = self.check("[x](docs/target.md#nope) [y](#also-nope)\n")
        self.assertEqual(len(reasons), 2)
        self.assertIn("no heading or id '#nope' in docs/target.md", reasons[0])
        self.assertIn("in this file", reasons[1])

    def test_wrong_case_is_reported_even_on_case_insensitive_fs(self):
        self.assertEqual(len(self.check("[x](docs/Target.md)\n")), 1)

    def test_escaping_the_repository(self):
        self.assertEqual(self.check("[x](../outside.md)\n"), ["points outside the repository"])

    def test_separate_files_and_usage_error(self):
        good = self.root / "good.md"
        good.write_text("[t](docs/target.md)\n", encoding="utf-8")
        bad = self.root / "bad.md"
        bad.write_text("[t](docs/nope.md)\n", encoding="utf-8")
        self.assertEqual(cdl.Checker(self.root).check_file(good), [])
        self.assertEqual(len(cdl.Checker(self.root).check_file(bad)), 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cdl.main([str(self.root / "missing-dir")]), 2)


if __name__ == "__main__":
    unittest.main()
