from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def samples() -> Path:
    return ROOT / "samples"


@pytest.fixture
def offline() -> Path:
    return ROOT / "tests" / "fixtures" / "offline"
