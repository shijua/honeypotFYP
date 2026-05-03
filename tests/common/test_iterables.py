from __future__ import annotations

import pytest

from libs.common.iterables import dedupe_preserve_by


pytestmark = pytest.mark.unit


def test_dedupe_preserve_by_keeps_first_value_for_each_key() -> None:
    values = [
        {"name": "first", "technique_id": "T1033"},
        {"name": "first", "technique_id": "T1033"},
        {"name": "second", "technique_id": "T1105"},
    ]

    result = dedupe_preserve_by(values, lambda item: (item["name"], item["technique_id"]))

    assert result == [values[0], values[2]]
