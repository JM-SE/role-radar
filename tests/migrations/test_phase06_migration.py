from pathlib import Path


def test_phase06_revision_is_chained_from_f5() -> None:
    revisions = list(Path("alembic/versions").glob("*_phase06_deep_evaluation.py"))
    assert len(revisions) == 1
    assert 'down_revision: str | None = "9c6e1f4a2b70"' in revisions[0].read_text()
