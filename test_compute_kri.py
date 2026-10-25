import pandas as pd
import pytest

from compute_kri import compute_kri

AS_OF = pd.Timestamp("2026-10-01")


def make_df(rows):
    return pd.DataFrame(
        rows, columns=["vuln_id", "asset_id", "region", "severity", "detected_date", "patched_date"]
    )


def test_one_row_per_region():
    df = make_df([
        ["V1", "H1", "EMEA", "Critical", "2026-09-01", None],
        ["V2", "H2", "APAC", "High", "2026-09-01", None],
        ["V3", "H3", "EMEA", "High", "2026-09-30", None],
    ])
    out = compute_kri(df, AS_OF)
    assert sorted(out["region"]) == ["APAC", "EMEA"]


def test_open_critical_past_sla_is_overdue():
    df = make_df([["V1", "H1", "EMEA", "Critical", "2026-09-20", None]])  # 11 days > 7
    out = compute_kri(df, AS_OF)
    assert out.loc[0, "overdue_vulns"] == 1
    assert out.loc[0, "kri_overdue_pct"] == 100.0


def test_open_but_within_sla_is_not_overdue():
    df = make_df([["V1", "H1", "EMEA", "High", "2026-09-20", None]])  # 11 days <= 30
    out = compute_kri(df, AS_OF)
    assert out.loc[0, "open_vulns"] == 1
    assert out.loc[0, "overdue_vulns"] == 0


def test_patched_before_as_of_is_closed():
    df = make_df([["V1", "H1", "EMEA", "Critical", "2026-08-01", "2026-08-05"]])
    out = compute_kri(df, AS_OF)
    assert out.loc[0, "open_vulns"] == 0
    assert out.loc[0, "kri_overdue_pct"] == 0.0


def test_patched_after_as_of_still_counts_as_open():
    df = make_df([["V1", "H1", "EMEA", "Critical", "2026-09-01", "2026-10-15"]])
    out = compute_kri(df, AS_OF)
    assert out.loc[0, "overdue_vulns"] == 1


def test_medium_is_excluded():
    df = make_df([
        ["V1", "H1", "EMEA", "Medium", "2026-01-01", None],
        ["V2", "H2", "EMEA", "High", "2026-09-25", None],
    ])
    out = compute_kri(df, AS_OF)
    assert out.loc[0, "total_vulns"] == 1


def test_percentage_rounding():
    df = make_df([
        ["V1", "H1", "EMEA", "Critical", "2026-09-01", None],
        ["V2", "H2", "EMEA", "Critical", "2026-09-30", None],
        ["V3", "H3", "EMEA", "Critical", "2026-09-30", None],
    ])
    out = compute_kri(df, AS_OF)
    assert out.loc[0, "kri_overdue_pct"] == pytest.approx(33.3)
