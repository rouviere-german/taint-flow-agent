"""Repository guard: no dynamic code execution in the shipped package, benches or scripts.

The restricted plan language exists precisely so that plan text is *interpreted* against a node
whitelist and never handed to CPython. A stray ``eval``/``exec``/``compile``/``__import__``
anywhere in first-party code would undo that, so this test greps for them. The same ban is
enforced repo-wide in CI by `.semgrep/rules.yml`; this test is the local half, so the claim does
not rest on a job that cannot run on this machine.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

# ``(?<![\w.])`` keeps ``re.compile(``, ``self._eval(`` and ``evaluate(`` out of the match.
BANNED = re.compile(r"(?<![\w.])(?:eval|exec|execfile|compile)\s*\(|__import__|globals\s*\(")
SCANNED_DIRECTORIES = ("src", "bench", "scripts")

# Text that must match, so a broken regex cannot make this test pass by accident.
POSITIVE_CONTROLS = (
    "eval(source)",
    "x = exec (code)",
    "compile(src, '<plan>', 'exec')",
    "__import__('os')",
    "globals()['read_inbox']",
)
NEGATIVE_CONTROLS = (
    "_NAME = re.compile(r'x')",
    "self._eval(node)",
    "evaluate(call)",
    "outcome = self.evaluator.evaluate(task)",
)


@pytest.mark.parametrize("sample", POSITIVE_CONTROLS)
def test_the_guard_matches_dynamic_code(sample: str) -> None:
    assert BANNED.search(sample) is not None


@pytest.mark.parametrize("sample", NEGATIVE_CONTROLS)
def test_the_guard_ignores_ordinary_code(sample: str) -> None:
    assert BANNED.search(sample) is None


def test_no_first_party_module_uses_eval_exec_compile_or_import(repo_root: Path) -> None:
    offenders: list[str] = []
    for directory in SCANNED_DIRECTORIES:
        for path in sorted((repo_root / directory).rglob("*.py")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if BANNED.search(line):
                    offenders.append(f"{path.relative_to(repo_root).as_posix()}:{number}")
    assert offenders == []


def test_the_guard_actually_scanned_the_package(repo_root: Path) -> None:
    scanned = [p for d in SCANNED_DIRECTORIES for p in (repo_root / d).rglob("*.py")]
    assert len(scanned) > 50
