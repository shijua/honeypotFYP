from __future__ import annotations

import re
from pathlib import Path

import pytest

from libs.common.sigma import (
    sigma_attack_profile_tags,
    sigma_attack_techniques,
    sigma_files,
    sigma_keyword_to_regex,
    sigma_selection_plans,
    sigma_string_values,
    sigma_values,
    split_sigma_field,
)


pytestmark = pytest.mark.unit


def test_sigma_files_returns_yaml_files_in_deterministic_order(tmp_path: Path) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    ignored = tmp_path / "ignored.txt"
    first = tmp_path / "a.yml"
    second = nested / "b.yaml"
    ignored.write_text("ignore", encoding="utf-8")
    second.write_text("title: second", encoding="utf-8")
    first.write_text("title: first", encoding="utf-8")

    assert sigma_files(tmp_path) == [first, second]
    assert sigma_files(first) == [first]
    assert sigma_files(ignored) == []


def test_sigma_files_raises_with_custom_label_for_missing_paths(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="HTTP Sigma rule path does not exist"):
        sigma_files(tmp_path / "missing", label="HTTP Sigma rule path")


def test_sigma_selection_plans_expands_and_or_wildcards_and_filters() -> None:
    detection = {
        "selection_netcat": {"Image|endswith": "/nc"},
        "selection_curl": {"Image|endswith": "/curl"},
        "selection_url": {"CommandLine|contains": "http://"},
        "filter_localhost": {"CommandLine|contains": "127.0.0.1"},
        "condition": "(selection_netcat and not filter_localhost) or (all of selection_*)",
    }

    plans = sigma_selection_plans(detection)

    assert [(plan.name, plan.positives, plan.negatives) for plan in plans] == [
        (
            "selection_netcat_and_filter_localhost",
            ({"Image|endswith": "/nc"},),
            ({"CommandLine|contains": "127.0.0.1"},),
        ),
        (
            "selection_netcat_and_selection_curl_and_selection_url",
            (
                {"Image|endswith": "/nc"},
                {"Image|endswith": "/curl"},
                {"CommandLine|contains": "http://"},
            ),
            (),
        ),
    ]


def test_sigma_selection_plans_expands_one_of_and_omits_filters_without_condition() -> None:
    detection = {
        "selection_whoami": {"Image|endswith": "/whoami"},
        "selection_id": {"Image|endswith": "/id"},
        "filter_noise": {"Image|endswith": "/uptime"},
        "condition": "1 of selection_*",
    }

    assert [
        (plan.name, plan.positives, plan.negatives)
        for plan in sigma_selection_plans(detection)
    ] == [
        ("selection_whoami", ({"Image|endswith": "/whoami"},), ()),
        ("selection_id", ({"Image|endswith": "/id"},), ()),
    ]

    no_condition = {
        "selection": {"CommandLine|contains": "secret"},
        "filter": {"CommandLine|contains": "healthcheck"},
    }
    assert [
        (plan.name, plan.positives, plan.negatives)
        for plan in sigma_selection_plans(no_condition)
    ] == [("selection", ({"CommandLine|contains": "secret"},), ())]


def test_sigma_selection_plans_returns_no_plan_for_unsupported_filter_expansion() -> None:
    detection = {
        "selection": {"CommandLine|contains": "curl"},
        "filter_one": {"CommandLine|contains": "127.0.0.1"},
        "filter_two": {"CommandLine|contains": "localhost"},
        "condition": "selection and not filter_*",
    }

    assert sigma_selection_plans(detection) == []


def test_split_sigma_field_and_value_helpers_normalize_common_shapes() -> None:
    assert split_sigma_field("CommandLine|contains|all") == (
        "commandline",
        {"contains", "all"},
    )
    assert split_sigma_field("process.name|re") == ("process_name", {"re"})
    assert split_sigma_field("") == ("", set())

    assert sigma_values(["Curl", 443, None, "", 1.5]) == ["curl", "443", "1.5"]
    assert sigma_values("UPPER") == ["upper"]
    assert sigma_values({"unsupported": True}) == []

    assert sigma_string_values(["one", "", 2, "two"]) == ["one", "two"]
    assert sigma_string_values("single") == ["single"]
    assert sigma_string_values(3) == []


def test_sigma_attack_tag_helpers_preserve_expected_profiler_forms() -> None:
    tags = [
        "attack.discovery",
        "attack.command-and-control",
        "attack.t1046",
        "attack.t1105",
        "not_attack.t0000",
        "attack.t1046",
    ]

    assert sigma_attack_techniques(tags) == ["T1046", "T1105"]
    assert sigma_attack_profile_tags(tags) == [
        "mitre_discovery",
        "mitre_command_and_control",
        "T1046",
        "T1105",
    ]


def test_sigma_keyword_to_regex_supports_sigma_wildcards() -> None:
    regex = sigma_keyword_to_regex("curl*agent-update.bin")

    assert re.search(regex, "curl http://host/downloads/agent-update.bin")
    assert not re.search(regex, "wget http://host/downloads/agent-update.bin")
