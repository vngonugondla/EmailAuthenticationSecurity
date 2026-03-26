#!/usr/bin/env python3
"""
Comprehensive analysis of SPF, DKIM, and DMARC adoption across 1M Tranco domains.

Questions answered:
  Q1 – How many domains have valid SPF / DKIM / DMARC records (overall)?
  Q2 – How many domains (by ranking tier) have ALL THREE valid?
  Q3 – How many domains (by ranking tier) have each protocol individually?

Plus deep-dives into:
  - SPF policy strictness & misconfigurations
  - DKIM selector distribution, key algorithm, key length, revocation
  - DMARC policy, sub-domain policy, alignment modes, reporting
"""

import pandas as pd

TIER_ORDER = [
    "Tier 1 (1-1K)",
    "Tier 2 (1K-10K)",
    "Tier 3 (10K-100K)",
    "Tier 4 (100K-1M)",
]

TIER_COL = "ranking_tier_x"

SEPARATOR = "=" * 65


def load_and_clean(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)

    df["spf_present"] = df["spf_present"].astype(str).str.strip().str.lower() == "true"
    df["dkim_present"] = df["dkim_present"].astype(str).str.strip().str.lower() == "true"
    df["dmarc_valid"] = df["dmarc_valid"].astype(str).str.strip().str.lower() == "true"
    df["dmarc_isPresent"] = df["dmarc_isPresent"].astype(str).str.strip().str.lower() == "true"
    df["revoked"] = df["revoked"].astype(str).str.strip().str.lower() == "true"
    df["dns_lookup_limit_exceeded"] = df["dns_lookup_limit_exceeded"].astype(str).str.strip().str.lower() == "true"
    df["multiple_spf_records"] = df["multiple_spf_records"].astype(str).str.strip().str.lower() == "true"
    df["has_ptr_mechanism"] = df["has_ptr_mechanism"].astype(str).str.strip().str.lower() == "true"

    return df


def pct(n, total):
    return f"{100 * n / total:.2f}%" if total else "N/A"


def section(title):
    print(f"\n{SEPARATOR}")
    print(f"  {title}")
    print(SEPARATOR)


# ─────────────────────────────────────────────────────────────────
#  Q1  –  Overall adoption (SPF, DKIM, DMARC individually)
# ─────────────────────────────────────────────────────────────────
def q1_overall(df):
    section("Q1: OVERALL PROTOCOL ADOPTION")
    total = len(df)

    spf = df["spf_present"].sum()
    dkim = df["dkim_present"].sum()
    dmarc = df["dmarc_valid"].sum()
    dmarc_present = df["dmarc_isPresent"].sum()
    all_three = ((df["spf_present"]) & (df["dkim_present"]) & (df["dmarc_valid"])).sum()

    print(f"  Total domains:           {total:>10,}")
    print()
    print(f"  SPF present:             {spf:>10,}  ({pct(spf, total)})")
    print(f"  DKIM present:            {dkim:>10,}  ({pct(dkim, total)})")
    print(f"  DMARC present:           {dmarc_present:>10,}  ({pct(dmarc_present, total)})")
    print(f"  DMARC valid:             {dmarc:>10,}  ({pct(dmarc, total)})")
    print()
    print(f"  All three (SPF+DKIM+DMARC valid):")
    print(f"                           {all_three:>10,}  ({pct(all_three, total)})")


# ─────────────────────────────────────────────────────────────────
#  Q2  –  All-three-valid by ranking tier
# ─────────────────────────────────────────────────────────────────
def q2_all_three_by_tier(df):
    section("Q2: ALL THREE VALID BY RANKING TIER")

    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        total = len(t)
        valid = ((t["spf_present"]) & (t["dkim_present"]) & (t["dmarc_valid"])).sum()
        print(f"  {tier:<25} {valid:>8,} / {total:<8,}  ({pct(valid, total)})")


# ─────────────────────────────────────────────────────────────────
#  Q3  –  Per-protocol adoption by ranking tier
# ─────────────────────────────────────────────────────────────────
def q3_per_protocol_by_tier(df):
    section("Q3: INDIVIDUAL PROTOCOL ADOPTION BY RANKING TIER")

    print(f"\n  {'Tier':<25} {'SPF':>10} {'DKIM':>10} {'DMARC':>10} {'Total':>10}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        total = len(t)
        spf = t["spf_present"].sum()
        dkim = t["dkim_present"].sum()
        dmarc = t["dmarc_valid"].sum()
        print(
            f"  {tier:<25} "
            f"{pct(spf, total):>10} "
            f"{pct(dkim, total):>10} "
            f"{pct(dmarc, total):>10} "
            f"{total:>10,}"
        )


# ─────────────────────────────────────────────────────────────────
#  SPF deep-dive
# ─────────────────────────────────────────────────────────────────
def spf_deep_dive(df):
    section("SPF: POLICY STRICTNESS (overall)")
    total = len(df)
    for val, cnt in df["policy_strictness"].value_counts().items():
        print(f"  {val:<30} {cnt:>10,}  ({pct(cnt, total)})")

    section("SPF: POLICY STRICTNESS BY TIER (among SPF-present)")
    for tier in TIER_ORDER:
        t = df[(df[TIER_COL] == tier) & (df["spf_present"])]
        t_total = len(t)
        print(f"\n  {tier}  (SPF-present n={t_total:,})")
        for val, cnt in t["policy_strictness"].value_counts().items():
            print(f"    {val:<28} {cnt:>8,}  ({pct(cnt, t_total)})")

    section("SPF: MISCONFIGURATIONS BY TIER (among SPF-present)")
    for tier in TIER_ORDER:
        t = df[(df[TIER_COL] == tier) & (df["spf_present"])]
        t_total = len(t)
        multi = t["multiple_spf_records"].sum()
        exceed = t["dns_lookup_limit_exceeded"].sum()
        ptr = t["has_ptr_mechanism"].sum()
        print(f"\n  {tier}  (SPF-present n={t_total:,})")
        print(f"    Multiple SPF records:  {multi:>8,}  ({pct(multi, t_total)})")
        print(f"    Exceeded 10 lookups:   {exceed:>8,}  ({pct(exceed, t_total)})")
        print(f"    Deprecated ptr:        {ptr:>8,}  ({pct(ptr, t_total)})")


# ─────────────────────────────────────────────────────────────────
#  DKIM deep-dive  (covers every field from dkim_analysis.py)
# ─────────────────────────────────────────────────────────────────
def dkim_deep_dive(df):
    dkim_df = df[df["dkim_present"]]
    dkim_total = len(dkim_df)

    # -- Selector distribution --
    section("DKIM: MATCHED SELECTOR DISTRIBUTION")
    print(f"  (among {dkim_total:,} domains with DKIM present)\n")
    for val, cnt in dkim_df["matched_selector"].value_counts().items():
        print(f"  {val:<25} {cnt:>10,}  ({pct(cnt, dkim_total)})")

    # -- Key algorithm --
    section("DKIM: KEY ALGORITHM DISTRIBUTION")
    print(f"  (among {dkim_total:,} domains with DKIM present)\n")
    for val, cnt in dkim_df["key_algorithm"].value_counts(dropna=False).items():
        label = val if pd.notna(val) else "(unparseable)"
        print(f"  {label:<25} {cnt:>10,}  ({pct(cnt, dkim_total)})")

    # -- Key length --
    section("DKIM: KEY LENGTH DISTRIBUTION")
    print(f"  (among {dkim_total:,} domains with DKIM present)\n")
    for val, cnt in dkim_df["key_length_bits"].value_counts(dropna=False).sort_index(na_position="last").items():
        label = f"{int(val)}-bit" if pd.notna(val) else "(unknown/revoked)"
        print(f"  {label:<25} {cnt:>10,}  ({pct(cnt, dkim_total)})")

    # -- Revoked keys --
    section("DKIM: REVOKED KEYS")
    revoked = dkim_df["revoked"].sum()
    print(f"  Revoked (p= empty):    {revoked:>10,}  ({pct(revoked, dkim_total)} of DKIM-present)")

    # -- DKIM adoption by tier --
    section("DKIM: ADOPTION BY RANKING TIER")
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        total = len(t)
        present = t["dkim_present"].sum()
        print(f"  {tier:<25} {present:>8,} / {total:<8,}  ({pct(present, total)})")

    # -- Selector distribution by tier --
    section("DKIM: TOP SELECTORS BY RANKING TIER")
    for tier in TIER_ORDER:
        t = dkim_df[dkim_df[TIER_COL] == tier]
        t_total = len(t)
        print(f"\n  {tier}  (DKIM-present n={t_total:,})")
        for val, cnt in t["matched_selector"].value_counts().head(5).items():
            print(f"    {val:<23} {cnt:>8,}  ({pct(cnt, t_total)})")

    # -- Key algorithm by tier --
    section("DKIM: KEY ALGORITHM BY RANKING TIER")
    for tier in TIER_ORDER:
        t = dkim_df[dkim_df[TIER_COL] == tier]
        t_total = len(t)
        print(f"\n  {tier}  (DKIM-present n={t_total:,})")
        for val, cnt in t["key_algorithm"].value_counts(dropna=False).items():
            label = val if pd.notna(val) else "(unparseable)"
            print(f"    {label:<23} {cnt:>8,}  ({pct(cnt, t_total)})")

    # -- Key length by tier --
    section("DKIM: KEY LENGTH BY RANKING TIER")
    for tier in TIER_ORDER:
        t = dkim_df[dkim_df[TIER_COL] == tier]
        t_total = len(t)
        print(f"\n  {tier}  (DKIM-present n={t_total:,})")
        for val, cnt in t["key_length_bits"].value_counts(dropna=False).sort_index(na_position="last").items():
            label = f"{int(val)}-bit" if pd.notna(val) else "(unknown/revoked)"
            print(f"    {label:<23} {cnt:>8,}  ({pct(cnt, t_total)})")


# ─────────────────────────────────────────────────────────────────
#  DMARC deep-dive
# ─────────────────────────────────────────────────────────────────
def dmarc_deep_dive(df):
    dmarc_df = df[df["dmarc_isPresent"]]
    dmarc_total = len(dmarc_df)

    section("DMARC: POLICY DISTRIBUTION")
    print(f"  (among {dmarc_total:,} domains with DMARC present)\n")
    for val, cnt in dmarc_df["dmarc_policy"].value_counts(dropna=False).items():
        label = val if pd.notna(val) else "(none/missing)"
        print(f"  {label:<25} {cnt:>10,}  ({pct(cnt, dmarc_total)})")

    section("DMARC: SUB-DOMAIN POLICY (sp=)")
    print(f"  (among {dmarc_total:,} domains with DMARC present)\n")
    for val, cnt in dmarc_df["dmarc_sp"].value_counts(dropna=False).items():
        label = val if pd.notna(val) else "(not set / inherits p=)"
        print(f"  {label:<25} {cnt:>10,}  ({pct(cnt, dmarc_total)})")

    section("DMARC: DKIM ALIGNMENT MODE (adkim=)")
    print(f"  (among {dmarc_total:,} domains with DMARC present)\n")
    for val, cnt in dmarc_df["dmarc_adkim"].value_counts(dropna=False).items():
        label = val if pd.notna(val) else "(not set / default relaxed)"
        print(f"  {label:<25} {cnt:>10,}  ({pct(cnt, dmarc_total)})")

    section("DMARC: SPF ALIGNMENT MODE (aspf=)")
    print(f"  (among {dmarc_total:,} domains with DMARC present)\n")
    for val, cnt in dmarc_df["dmarc_aspf"].value_counts(dropna=False).items():
        label = val if pd.notna(val) else "(not set / default relaxed)"
        print(f"  {label:<25} {cnt:>10,}  ({pct(cnt, dmarc_total)})")

    section("DMARC: AGGREGATE REPORTING (rua=)")
    has_rua = dmarc_df["dmarc_rua"].notna().sum()
    print(f"  Has rua:               {has_rua:>10,}  ({pct(has_rua, dmarc_total)} of DMARC-present)")

    section("DMARC: FORENSIC REPORTING (ruf=)")
    has_ruf = dmarc_df["dmarc_ruf"].notna().sum()
    print(f"  Has ruf:               {has_ruf:>10,}  ({pct(has_ruf, dmarc_total)} of DMARC-present)")

    section("DMARC: ADOPTION BY RANKING TIER")
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        total = len(t)
        present = t["dmarc_isPresent"].sum()
        valid = t["dmarc_valid"].sum()
        print(
            f"  {tier:<25} present={present:>7,}  valid={valid:>7,}  "
            f"/ {total:<8,}  ({pct(valid, total)})"
        )

    section("DMARC: POLICY BY RANKING TIER (among DMARC-present)")
    for tier in TIER_ORDER:
        t = dmarc_df[dmarc_df[TIER_COL] == tier]
        t_total = len(t)
        print(f"\n  {tier}  (DMARC-present n={t_total:,})")
        for val, cnt in t["dmarc_policy"].value_counts(dropna=False).items():
            label = val if pd.notna(val) else "(none/missing)"
            print(f"    {label:<23} {cnt:>8,}  ({pct(cnt, t_total)})")


# ─────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────
def main():
    print("Loading merged_results.csv …")
    df = load_and_clean("merged_results.csv")
    print(f"Loaded {len(df):,} rows.\n")

    q1_overall(df)
    q2_all_three_by_tier(df)
    q3_per_protocol_by_tier(df)

    spf_deep_dive(df)
    dkim_deep_dive(df)
    dmarc_deep_dive(df)

    print(f"\n{SEPARATOR}")
    print("  ANALYSIS COMPLETE")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
