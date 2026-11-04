"""TsaEntry safety-relevant fields have no defaults (operator_id, distrust_after)."""
import pytest

from anchoring.tsa.policy import TsaEntry

_BASE = dict(tsa_id="t", role="primary", url="https://t.example", policy_oid="1.2.3",
             root_pem_path="/dev/null", root_fingerprint_sha256="aa", max_accuracy_s=1.0)


def test_complete_entry_constructs():
    e = TsaEntry(**_BASE, operator_id="op", distrust_after=None)
    assert e.distrust_after is None and e.operator_id == "op"


def test_operator_id_is_required():
    with pytest.raises(TypeError):
        TsaEntry(**_BASE, distrust_after=None)


def test_distrust_after_is_required_even_for_none():
    with pytest.raises(TypeError):
        TsaEntry(**_BASE, operator_id="op")
