"""Tests for prescryb.cce's pure helpers: row normalization, matching, and search."""

from __future__ import annotations

from prescryb import cce
from prescryb.models import CCERef


def test_clean_none_returns_empty_string() -> None:
    assert cce._clean(None) == ""


def test_clean_strips_and_unescapes_html_entities() -> None:
    assert cce._clean(" Foo &amp; Bar ") == "Foo & Bar"


def test_clean_treats_literal_none_string_as_empty() -> None:
    assert cce._clean("None") == ""
    assert cce._clean("none") == ""


def test_rows_transposes_columnar_json() -> None:
    data: dict[str, dict[str, object]] = {
        "CCE ID v5": {"0": "CCE-1", "1": "CCE-2"},
        "CCE Title": {"0": "Title A", "1": "Title B"},
    }
    assert cce._rows(data) == [
        {"CCE ID v5": "CCE-1", "CCE Title": "Title A"},
        {"CCE ID v5": "CCE-2", "CCE Title": "Title B"},
    ]


def test_normalize_usgcb_builds_refs_and_skips_blank_ids() -> None:
    data: dict[str, dict[str, object]] = {
        "CCE ID v5": {"0": "CCE-80876-6", "1": ""},
        "CCE Title": {"0": "Disable rlogin", "1": "Something"},
        "Configuration Details": {"0": "Set service to disabled", "1": ""},
        "Rationale": {"0": "Reduces attack surface", "1": ""},
        "Impact": {"0": "Medium", "1": ""},
        "Configuration Group": {"0": "Services", "1": ""},
    }

    refs = cce._normalize_usgcb(cce._rows(data), "rhel8")

    assert len(refs) == 1
    ref = refs[0]
    assert ref.cce_id == "CCE-80876-6"
    assert ref.title == "Disable rlogin"
    assert ref.target == "rhel8"
    assert ref.severity == "Medium"
    assert (
        ref.source_url == "https://konstruktoid.github.io/cce-web/cce_html/rhel8.html"
    )


def test_normalize_sles_builds_refs() -> None:
    data: dict[str, dict[str, object]] = {
        "CCE": {"0": "CCE-83000-1"},
        "Name": {"0": "Ensure firewall is enabled"},
        "Check_Fix": {"0": "Enable firewalld"},
        "Rationale": {"0": "Prevents unauthorized access"},
        "Severity": {"0": "high"},
        "SLE": {"0": "15"},
        "CIS": {"0": "3.5.1"},
        "SRG": {"0": "SRG-OS-000096"},
    }

    refs = cce._normalize_sles(cce._rows(data), "SLES15-DISA-STIG")

    assert len(refs) == 1
    ref = refs[0]
    assert ref.cce_id == "CCE-83000-1"
    assert ref.title == "Ensure firewall is enabled"
    assert ref.cis == "3.5.1"
    assert ref.disa_srg == "SRG-OS-000096"


def test_normalize_dispatches_to_usgcb_schema() -> None:
    data: dict[str, dict[str, object]] = {
        "CCE ID v5": {"0": "CCE-1"},
        "CCE Title": {"0": "T"},
    }
    refs = cce._normalize(data, "rhel8")
    assert refs is not None
    assert refs[0].cce_id == "CCE-1"


def test_normalize_dispatches_to_sles_schema() -> None:
    data: dict[str, dict[str, object]] = {"CCE": {"0": "CCE-1"}, "Name": {"0": "T"}}
    refs = cce._normalize(data, "SLES15-DISA-STIG")
    assert refs is not None
    assert refs[0].title == "T"


def test_normalize_returns_none_for_unrecognized_schema() -> None:
    data: dict[str, dict[str, object]] = {"Some Weird Column": {"0": "x"}}
    assert cce._normalize(data, "weird-target") is None


def test_normalize_hint_strips_non_alnum_and_lowercases() -> None:
    assert cce._normalize_hint("RHEL-8!") == "rhel8"


def test_match_targets_exact_match_wins_over_partial() -> None:
    targets = ["rhel8", "rhel80-extra"]
    assert cce._match_targets("rhel8", targets) == ["rhel8"]


def test_match_targets_falls_back_to_partial_matches() -> None:
    targets = ["SLES15-DISA-STIG", "SLES15-PCI-DSS", "rhel8"]
    matches = cce._match_targets("sles15", targets)
    assert set(matches) == {"SLES15-DISA-STIG", "SLES15-PCI-DSS"}


def test_match_targets_no_match_returns_empty_list() -> None:
    assert cce._match_targets("doesnotexist", ["rhel8"]) == []


def _ref(**overrides: str) -> CCERef:
    fields = {
        "cce_id": "CCE-1",
        "title": "",
        "target": "rhel8",
        "description": "",
        "rationale": "",
        "group": "",
    }
    fields.update(overrides)
    return CCERef(**fields)


def test_search_by_cce_id_is_case_insensitive_exact_match() -> None:
    entries = [_ref(cce_id="CCE-80876-6"), _ref(cce_id="CCE-80877-4")]
    result = cce.search(entries, cce_id="cce-80876-6")
    assert [e.cce_id for e in result] == ["CCE-80876-6"]


def test_search_by_keyword_matches_across_fields() -> None:
    entries = [
        _ref(cce_id="CCE-1", title="Disable rlogin"),
        _ref(cce_id="CCE-2", description="Configure firewall rules"),
        _ref(cce_id="CCE-3", rationale="Unrelated"),
    ]
    result = cce.search(entries, keyword="firewall")
    assert [e.cce_id for e in result] == ["CCE-2"]


def test_search_without_filters_returns_all_entries() -> None:
    entries = [_ref(cce_id="CCE-1"), _ref(cce_id="CCE-2")]
    assert cce.search(entries) == entries
