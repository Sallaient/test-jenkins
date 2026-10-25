#!/usr/bin/env python3
"""KRI: % of Critical/High vulnerabilities open beyond SLA, per region."""
import argparse
import pandas as pd

SLA_DAYS = {"Critical": 7, "High": 30}  # Medium is out of scope for this KRI


def compute_kri(df: pd.DataFrame, as_of: pd.Timestamp) -> pd.DataFrame:
    df = df[df["severity"].isin(SLA_DAYS)].copy()
    df["detected_date"] = pd.to_datetime(df["detected_date"])
    df["patched_date"] = pd.to_datetime(df["patched_date"])

    # a vuln is "open" if not patched as of the reference date
    df["is_open"] = df["patched_date"].isna() | (df["patched_date"] > as_of)
    df["age_days"] = (as_of - df["detected_date"]).dt.days
    df["overdue"] = df["is_open"] & (df["age_days"] > df["severity"].map(SLA_DAYS))

    out = (
        df.groupby("region")
        .agg(total_vulns=("vuln_id", "count"),
             open_vulns=("is_open", "sum"),
             overdue_vulns=("overdue", "sum"))
        .reset_index()
    )
    out["kri_overdue_pct"] = (100 * out["overdue_vulns"] / out["total_vulns"]).round(1)
    out.insert(0, "as_of", as_of.date().isoformat())
    return out


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--as-of", default=pd.Timestamp.today().date().isoformat())
    a = p.parse_args()

    result = compute_kri(pd.read_csv(a.input), pd.Timestamp(a.as_of))
    result.to_csv(a.output, index=False)
    print(result.to_string(index=False))
