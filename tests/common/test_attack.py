from __future__ import annotations

import pytest

from libs.common.attack import attack_technique_ids_from_text
from libs.common.attack import same_technique_family
from libs.common.attack import technique_family_set


pytestmark = pytest.mark.unit


def test_attack_technique_ids_from_text_extracts_parent_and_subtechniques() -> None:
    assert attack_technique_ids_from_text("attack.t1552.001 then T1105") == ["T1552.001", "T1105"]


def test_technique_family_helpers_compare_parent_and_subtechniques() -> None:
    assert same_technique_family("T1552", "T1552.001")
    assert not same_technique_family("T1552", "T1105")
    assert technique_family_set(["T1552.001", "T1105", None]) == {"T1552", "T1105"}
