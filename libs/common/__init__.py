"""Common helpers shared across services."""

from libs.common.attack import attack_technique_ids_from_text
from libs.common.attack import same_technique_family
from libs.common.attack import technique_family
from libs.common.attack import technique_family_set
from libs.common.clock import parse_iso_datetime
from libs.common.clock import utc_aware
from libs.common.clock import utcnow
from libs.common.config import RuntimeConfig
from libs.common.iterables import dedupe_preserve
from libs.common.iterables import dedupe_preserve_by
from libs.common.iterables import string_items
from libs.common.json_utils import mutable_nested_dict
from libs.common.json_utils import read_json_object
from libs.common.json_utils import read_json_value

__all__ = [
    "RuntimeConfig",
    "attack_technique_ids_from_text",
    "dedupe_preserve",
    "dedupe_preserve_by",
    "mutable_nested_dict",
    "parse_iso_datetime",
    "read_json_object",
    "read_json_value",
    "same_technique_family",
    "string_items",
    "technique_family",
    "technique_family_set",
    "utc_aware",
    "utcnow",
]
