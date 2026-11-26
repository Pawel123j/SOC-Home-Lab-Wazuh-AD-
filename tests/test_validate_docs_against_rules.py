"""CLI `scripts/validate_docs_against_rules.py` uruchamiany na izolowanej kopii.

Każdy test kopiuje skrypt, plik reguł i `docs/` do `tmp_path`, więc pliki
repozytorium nigdy nie są modyfikowane.
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = "scripts/validate_docs_against_rules.py"
RULES = "detection-rules/custom-wazuh-rules.xml"


def make_copy(tmp_path: Path) -> Path:
    for rel in (SCRIPT, RULES):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / rel, tmp_path / rel)
    shutil.copytree(ROOT / "docs", tmp_path / "docs")
    return tmp_path


def run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(root / SCRIPT)],
        capture_output=True, text=True, encoding="utf-8", cwd=root,
    )


def test_unchanged_copy_passes(tmp_path):
    result = run(make_copy(tmp_path))
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("OK")


def test_empty_docs_dir_fails(tmp_path):
    root = make_copy(tmp_path)
    shutil.rmtree(root / "docs")
    (root / "docs").mkdir()
    result = run(root)
    assert result.returncode == 1
    assert "Nie znaleziono żadnego dokumentu w docs/" in result.stderr
    assert "OK" not in result.stdout
