import json
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def load_fixture(name: str):
    return json.loads((FIXTURES_DIR / name).read_text())


@pytest.fixture
def data_url_payload():
    return load_fixture("payload_data_url.json")


@pytest.fixture
def thumbnail_url_payload():
    return load_fixture("payload_thumbnail_url.json")


@pytest.fixture
def multi_subject_vision_json() -> str:
    return (FIXTURES_DIR / "vision_response_multi_subject.json").read_text()
