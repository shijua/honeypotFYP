from __future__ import annotations

import pytest

from libs.common.json_utils import mutable_nested_dict


pytestmark = pytest.mark.unit


def test_mutable_nested_dict_creates_and_repairs_path() -> None:
    payload = {"contexts": "bad"}

    group = mutable_nested_dict(payload, ("contexts", "T1005", "asset_groups", "finance"))
    group["useful"] = 1

    assert payload == {
        "contexts": {
            "T1005": {
                "asset_groups": {
                    "finance": {
                        "useful": 1,
                    }
                }
            }
        }
    }
