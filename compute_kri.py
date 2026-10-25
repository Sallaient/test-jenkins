#!/usr/bin/env python3
"""KRI: % of Critical/High vulnerabilities open beyond SLA, per region."""
import argparse
import logging
import sys

import pandas as pd

log = logging.getLogger("kri")

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


def setup_logging(log_file=None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--as-of", default=pd.Timestamp.today().date().isoformat())
    p.add_argument("--log-file", default=None)
    a = p.parse_args()
    setup_logging(a.log_file)

    try:
        log.info("Start: input=%s as_of=%s", a.input, a.as_of)
        df = pd.read_csv(a.input)
        log.info("Loaded %d rows", len(df))
        result = compute_kri(df, pd.Timestamp(a.as_of))
        result.to_csv(a.output, index=False)
        log.info("KRI computed for %d regions, written to %s", len(result), a.output)
        for r in result.itertuples():
            log.info("  %s: %.1f%% overdue (%d/%d)", r.region, r.kri_overdue_pct, r.overdue_vulns, r.total_vulns)
    except Exception:
        log.exception("KRI computation failed")
        sys.exit(1)