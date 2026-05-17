from __future__ import annotations

import pytest

from libs.common.iterables import dedupe_preserve_by
from libs.common.iterables import string_items


pytestmark = pytest.mark.unit


def test_dedupe_preserve_by_keeps_first_value_for_each_key() -> None:
    values = [
        {"name": "first", "technique_id": "T1033"},
        {"name": "first", "technique_id": "T1033"},
        {"name": "second", "technique_id": "T1105"},
    ]

    result = dedupe_preserve_by(values, lambda item: (item["name"], item["technique_id"]))

    assert result == [values[0], values[2]]


def test_string_items_keeps_only_strings_from_json_list() -> None:
    assert string_items(["e-1", 2, "e-2", None, {"bad": True}]) == ["e-1", "e-2"]
    assert string_items("not-a-list") == []
