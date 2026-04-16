#!/usr/bin/env python3
"""
Comprehensive cross-protocol analysis of SPF, DKIM, and DMARC across 1M Tranco domains.

Sections:
  A. Conditional probabilities – P(X|Y) for all protocol pairs, overall and by tier
  B. Combination analysis – full 2x2x2 Venn-diagram breakdown, overall and by tier
  C. Case studies – sample domains for each protocol gap, with record details
  D. Security posture scoring – 0-to-3 score, "fully protected", "vulnerable"
  E. Protocol-specific deep cuts – DMARC policy by tier, SPF↔DMARC correlation,
     DKIM key strength by tier, DKIM selector popularity by tier
"""

import pandas as pd
import numpy as np

TIER_ORDER = [
    "Tier 1 (1-1K)",
    "Tier 2 (1K-10K)",
    "Tier 3 (10K-100K)",
    "Tier 4 (100K-1M)",
]
TIER_COL = "ranking_tier_x"
SEP = "=" * 72


def load_and_clean(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)

    bool_map = {
        "spf_present": False,
        "dkim_present": False,
        "dmarc_valid": False,
        "dmarc_isPresent": False,
        "revoked": False,
        "dns_lookup_limit_exceeded": False,
        "multiple_spf_records": False,
        "has_ptr_mechanism": False,
    }
    for col in bool_map:
        if col in df.columns:
            df[col] = df[col].astype(str).str.strip().str.lower() == "true"

    for col in ["error", "spf_raw_record", "include_chain",
                 "matched_selector", "key_algorithm", "dmarc_policy"]:
        if col in df.columns:
            df[col] = df[col].fillna("")

    return df


def pct(n, total):
    return f"{100 * n / total:.2f}%" if total else "N/A"


def section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


# ─────────────────────────────────────────────────────────────────────────
#  A. CONDITIONAL PROBABILITIES
# ─────────────────────────────────────────────────────────────────────────
def conditional_probabilities(df):
    section("A1. CONDITIONAL PROBABILITIES – OVERALL")

    pairs = [
        ("DMARC valid",  "dmarc_valid",  "SPF present",   "spf_present"),
        ("DMARC valid",  "dmarc_valid",  "DKIM present",  "dkim_present"),
        ("DMARC valid",  "dmarc_valid",  "SPF & DKIM",    None),
        ("DKIM present", "dkim_present", "SPF present",   "spf_present"),
        ("SPF present",  "spf_present",  "DMARC valid",   "dmarc_valid"),
        ("SPF present",  "spf_present",  "DKIM present",  "dkim_present"),
        ("DKIM present", "dkim_present", "DMARC valid",   "dmarc_valid"),
    ]

    print(f"\n  {'P( A | B )':<45} {'Count':>8} {'/ Given':>8} {'Prob':>10}")
    print(f"  {'-'*45} {'-'*8} {'-'*8} {'-'*10}")

    for a_label, a_col, b_label, b_col in pairs:
        if b_col is None:
            given = df[df["spf_present"] & df["dkim_present"]]
        else:
            given = df[df[b_col]]
        both = given[given[a_col]].shape[0]
        total_given = len(given)
        p = f"{100 * both / total_given:.2f}%" if total_given else "N/A"
        label = f"P( {a_label} | {b_label} )"
        print(f"  {label:<45} {both:>8,} {total_given:>8,} {p:>10}")

    section("A2. CONDITIONAL PROBABILITIES – BY TIER")

    key_pairs = [
        ("P(DMARC|SPF)",       "dmarc_valid",  "spf_present"),
        ("P(DMARC|DKIM)",      "dmarc_valid",  "dkim_present"),
        ("P(DKIM|SPF)",        "dkim_present", "spf_present"),
        ("P(SPF|DMARC)",       "spf_present",  "dmarc_valid"),
    ]

    for label, a_col, b_col in key_pairs:
        print(f"\n  {label}:")
        for tier in TIER_ORDER:
            t = df[df[TIER_COL] == tier]
            given = t[t[b_col]]
            both = given[given[a_col]].shape[0]
            total_given = len(given)
            p = pct(both, total_given)
            print(f"    {tier:<25} {both:>8,} / {total_given:<8,}  ({p})")


# ─────────────────────────────────────────────────────────────────────────
#  B. COMBINATION ANALYSIS (Venn diagram)
# ─────────────────────────────────────────────────────────────────────────
def combination_analysis(df):
    section("B1. PROTOCOL COMBINATION BREAKDOWN – OVERALL")

    total = len(df)
    combos = []
    for spf_val in [True, False]:
        for dkim_val in [True, False]:
            for dmarc_val in [True, False]:
                mask = (
                    (df["spf_present"] == spf_val) &
                    (df["dkim_present"] == dkim_val) &
                    (df["dmarc_valid"] == dmarc_val)
                )
                cnt = mask.sum()
                label_parts = []
                if spf_val: label_parts.append("SPF")
                if dkim_val: label_parts.append("DKIM")
                if dmarc_val: label_parts.append("DMARC")
                label = " + ".join(label_parts) if label_parts else "NONE"
                combos.append((label, cnt))

    combos.sort(key=lambda x: -x[1])
    print(f"\n  {'Combination':<30} {'Count':>10}  {'%':>10}")
    print(f"  {'-'*30} {'-'*10}  {'-'*10}")
    for label, cnt in combos:
        print(f"  {label:<30} {cnt:>10,}  ({pct(cnt, total)})")

    section("B2. PROTOCOL COMBINATION BREAKDOWN – BY TIER")

    combo_labels = [c[0] for c in combos]

    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        tt = len(t)
        print(f"\n  {tier}  (n={tt:,})")
        tier_combos = []
        for spf_val in [True, False]:
            for dkim_val in [True, False]:
                for dmarc_val in [True, False]:
                    mask = (
                        (t["spf_present"] == spf_val) &
                        (t["dkim_present"] == dkim_val) &
                        (t["dmarc_valid"] == dmarc_val)
                    )
                    cnt = mask.sum()
                    label_parts = []
                    if spf_val: label_parts.append("SPF")
                    if dkim_val: label_parts.append("DKIM")
                    if dmarc_val: label_parts.append("DMARC")
                    label = " + ".join(label_parts) if label_parts else "NONE"
                    tier_combos.append((label, cnt))

        tier_combos.sort(key=lambda x: -x[1])
        for label, cnt in tier_combos:
            if cnt > 0:
                print(f"    {label:<28} {cnt:>8,}  ({pct(cnt, tt)})")

    section("B3. PAIR-WISE CO-ADOPTION MATRIX – OVERALL")
    protocols = {
        "SPF": "spf_present",
        "DKIM": "dkim_present",
        "DMARC": "dmarc_valid",
    }
    print(f"\n  {'':>15}", end="")
    for name in protocols:
        print(f"  {name:>12}", end="")
    print()

    for row_name, row_col in protocols.items():
        print(f"  {row_name:>15}", end="")
        for col_name, col_col in protocols.items():
            both = (df[row_col] & df[col_col]).sum()
            print(f"  {both:>12,}", end="")
        print()

    print(f"\n  (as % of total {len(df):,} domains)")
    print(f"  {'':>15}", end="")
    for name in protocols:
        print(f"  {name:>12}", end="")
    print()
    for row_name, row_col in protocols.items():
        print(f"  {row_name:>15}", end="")
        for col_name, col_col in protocols.items():
            both = (df[row_col] & df[col_col]).sum()
            print(f"  {pct(both, len(df)):>12}", end="")
        print()


# ─────────────────────────────────────────────────────────────────────────
#  C. CASE STUDIES – FAILURE INVESTIGATION
# ─────────────────────────────────────────────────────────────────────────
def case_studies(df):
    section("C1. DOMAINS WITH DMARC BUT NO SPF")
    subset = df[df["dmarc_valid"] & ~df["spf_present"]]
    print(f"  Count: {len(subset):,}\n")
    print(f"  {'Domain':<35} {'Rank':>8} {'Tier':<22} {'DKIM':>6} {'DMARC Policy':<14} {'Error':<20}")
    print(f"  {'-'*35} {'-'*8} {'-'*22} {'-'*6} {'-'*14} {'-'*20}")
    for _, row in subset.head(10).iterrows():
        print(
            f"  {row['domain']:<35} {int(row['tranco_rank_x']):>8} "
            f"{row[TIER_COL]:<22} {str(row['dkim_present']):>6} "
            f"{row['dmarc_policy']:<14} {str(row['error'])[:20]:<20}"
        )

    section("C2. DOMAINS WITH SPF BUT NO DMARC")
    subset = df[df["spf_present"] & ~df["dmarc_valid"]]
    print(f"  Count: {len(subset):,}\n")
    print(f"  {'Domain':<35} {'Rank':>8} {'Tier':<22} {'DKIM':>6} {'SPF Policy':<18}")
    print(f"  {'-'*35} {'-'*8} {'-'*22} {'-'*6} {'-'*18}")
    for _, row in subset.head(10).iterrows():
        print(
            f"  {row['domain']:<35} {int(row['tranco_rank_x']):>8} "
            f"{row[TIER_COL]:<22} {str(row['dkim_present']):>6} "
            f"{row['policy_strictness']:<18}"
        )

    section("C3. DOMAINS WITH SPF + DMARC BUT NO DKIM")
    subset = df[df["spf_present"] & df["dmarc_valid"] & ~df["dkim_present"]]
    print(f"  Count: {len(subset):,}\n")
    print(f"  {'Domain':<35} {'Rank':>8} {'Tier':<22} {'SPF Policy':<18} {'DMARC Policy':<14}")
    print(f"  {'-'*35} {'-'*8} {'-'*22} {'-'*18} {'-'*14}")
    for _, row in subset.head(10).iterrows():
        print(
            f"  {row['domain']:<35} {int(row['tranco_rank_x']):>8} "
            f"{row[TIER_COL]:<22} {row['policy_strictness']:<18} "
            f"{row['dmarc_policy']:<14}"
        )

    section("C4. DOMAINS WITH DKIM BUT NO SPF")
    subset = df[df["dkim_present"] & ~df["spf_present"]]
    print(f"  Count: {len(subset):,}\n")
    print(f"  {'Domain':<35} {'Rank':>8} {'Tier':<22} {'DMARC':>6} {'Selector':<16} {'Error':<20}")
    print(f"  {'-'*35} {'-'*8} {'-'*22} {'-'*6} {'-'*16} {'-'*20}")
    for _, row in subset.head(10).iterrows():
        print(
            f"  {row['domain']:<35} {int(row['tranco_rank_x']):>8} "
            f"{row[TIER_COL]:<22} {str(row['dmarc_valid']):>6} "
            f"{row['matched_selector']:<16} {str(row['error'])[:20]:<20}"
        )

    section("C5. DOMAINS WITH DKIM BUT NO DMARC")
    subset = df[df["dkim_present"] & ~df["dmarc_valid"]]
    print(f"  Count: {len(subset):,}\n")
    print(f"  {'Domain':<35} {'Rank':>8} {'Tier':<22} {'SPF':>6} {'Selector':<16} {'Key Algo':<10}")
    print(f"  {'-'*35} {'-'*8} {'-'*22} {'-'*6} {'-'*16} {'-'*10}")
    for _, row in subset.head(10).iterrows():
        print(
            f"  {row['domain']:<35} {int(row['tranco_rank_x']):>8} "
            f"{row[TIER_COL]:<22} {str(row['spf_present']):>6} "
            f"{row['matched_selector']:<16} {row['key_algorithm']:<10}"
        )

    section("C6. DOMAINS WITH NONE OF SPF, DKIM, DMARC")
    subset = df[~df["spf_present"] & ~df["dkim_present"] & ~df["dmarc_valid"]]
    print(f"  Count: {len(subset):,}\n")
    sample = subset.sample(n=min(10, len(subset)), random_state=42)
    print(f"  {'Domain':<35} {'Rank':>8} {'Tier':<22} {'Error':<25}")
    print(f"  {'-'*35} {'-'*8} {'-'*22} {'-'*25}")
    for _, row in sample.iterrows():
        print(
            f"  {row['domain']:<35} {int(row['tranco_rank_x']):>8} "
            f"{row[TIER_COL]:<22} {str(row['error'])[:25]:<25}"
        )

    section("C7. SUMMARY: GAP COUNTS")
    total = len(df)
    gaps = [
        ("DMARC but no SPF",            df["dmarc_valid"] & ~df["spf_present"]),
        ("SPF but no DMARC",            df["spf_present"] & ~df["dmarc_valid"]),
        ("SPF+DMARC but no DKIM",       df["spf_present"] & df["dmarc_valid"] & ~df["dkim_present"]),
        ("DKIM but no SPF",             df["dkim_present"] & ~df["spf_present"]),
        ("DKIM but no DMARC",           df["dkim_present"] & ~df["dmarc_valid"]),
        ("DKIM only (no SPF, no DMARC)", df["dkim_present"] & ~df["spf_present"] & ~df["dmarc_valid"]),
        ("None of the three",           ~df["spf_present"] & ~df["dkim_present"] & ~df["dmarc_valid"]),
    ]
    for label, mask in gaps:
        cnt = mask.sum()
        print(f"  {label:<35} {cnt:>10,}  ({pct(cnt, total)})")


# ─────────────────────────────────────────────────────────────────────────
#  D. SECURITY POSTURE SCORING
# ─────────────────────────────────────────────────────────────────────────
def security_posture(df):
    section("D1. SECURITY SCORE (0-3) DISTRIBUTION")
    df = df.copy()
    df["security_score"] = (
        df["spf_present"].astype(int) +
        df["dkim_present"].astype(int) +
        df["dmarc_valid"].astype(int)
    )
    total = len(df)
    for score in [0, 1, 2, 3]:
        cnt = (df["security_score"] == score).sum()
        print(f"  Score {score}:  {cnt:>10,}  ({pct(cnt, total)})")

    print(f"\n  Mean score: {df['security_score'].mean():.3f}")

    section("D2. AVERAGE SECURITY SCORE BY TIER")
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        avg = t["security_score"].mean()
        print(f"  {tier:<25} mean = {avg:.3f}")

    section("D3. SECURITY SCORE DISTRIBUTION BY TIER")
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        tt = len(t)
        print(f"\n  {tier}  (n={tt:,})")
        for score in [0, 1, 2, 3]:
            cnt = (t["security_score"] == score).sum()
            print(f"    Score {score}:  {cnt:>8,}  ({pct(cnt, tt)})")

    section("D4. FULLY PROTECTED DOMAINS")
    print("  (all three present + DMARC p=reject + SPF -all)\n")
    fully = df[
        df["spf_present"] &
        df["dkim_present"] &
        df["dmarc_valid"] &
        (df["dmarc_policy"].str.lower() == "reject") &
        (df["policy_strictness"] == "strict (-all)")
    ]
    print(f"  Total fully protected: {len(fully):,}  ({pct(len(fully), total)})")
    print()
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        tt = len(t)
        f_tier = fully[fully[TIER_COL] == tier]
        print(f"  {tier:<25} {len(f_tier):>8,} / {tt:<8,}  ({pct(len(f_tier), tt)})")

    print(f"\n  Sample fully protected domains:")
    for _, row in fully.head(10).iterrows():
        print(f"    rank={int(row['tranco_rank_x']):>7,}  {row['domain']}")

    section("D5. VULNERABLE DOMAINS")
    print("  (DMARC p=none + SPF ~all — present but not enforcing)\n")
    vulnerable = df[
        df["spf_present"] &
        df["dmarc_valid"] &
        (df["dmarc_policy"].str.lower() == "none") &
        (df["policy_strictness"] == "softfail (~all)")
    ]
    print(f"  Total vulnerable: {len(vulnerable):,}  ({pct(len(vulnerable), total)})")
    print()
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        tt = len(t)
        v_tier = vulnerable[vulnerable[TIER_COL] == tier]
        print(f"  {tier:<25} {len(v_tier):>8,} / {tt:<8,}  ({pct(len(v_tier), tt)})")

    print(f"\n  Sample vulnerable domains:")
    for _, row in vulnerable.head(10).iterrows():
        print(f"    rank={int(row['tranco_rank_x']):>7,}  {row['domain']}")


# ─────────────────────────────────────────────────────────────────────────
#  E. PROTOCOL-SPECIFIC DEEP CUTS
# ─────────────────────────────────────────────────────────────────────────
def protocol_deep_cuts(df):

    # E1 – DMARC policy by tier
    section("E1. DMARC POLICY DISTRIBUTION BY TIER (among DMARC-present)")
    dmarc_df = df[df["dmarc_isPresent"]]
    policies = ["reject", "quarantine", "none"]

    print(f"\n  {'Tier':<25}", end="")
    for p in policies:
        print(f"  {p:>12}", end="")
    print(f"  {'other':>12}")
    print(f"  {'-'*25}", end="")
    for _ in range(4):
        print(f"  {'-'*12}", end="")
    print()

    for tier in TIER_ORDER:
        t = dmarc_df[dmarc_df[TIER_COL] == tier]
        tt = len(t)
        print(f"  {tier:<25}", end="")
        other = tt
        for p in policies:
            cnt = (t["dmarc_policy"].str.lower() == p).sum()
            other -= cnt
            print(f"  {pct(cnt, tt):>12}", end="")
        print(f"  {pct(other, tt):>12}")

    # E2 – SPF strictness vs DMARC policy crosstab
    section("E2. SPF STRICTNESS vs DMARC POLICY (domains with both)")
    both_df = df[df["spf_present"] & df["dmarc_isPresent"]].copy()
    both_df["dmarc_policy_clean"] = both_df["dmarc_policy"].str.lower().replace("", "missing")
    ct = pd.crosstab(
        both_df["policy_strictness"],
        both_df["dmarc_policy_clean"],
        margins=True,
    )
    print(f"  (raw counts, n={len(both_df):,})\n")
    print(ct.to_string())

    print(f"\n\n  (as % of {len(both_df):,} domains)\n")
    ct_pct = pd.crosstab(
        both_df["policy_strictness"],
        both_df["dmarc_policy_clean"],
        normalize="all",
    ) * 100
    print(ct_pct.round(2).to_string())

    # E3 – SPF strict domains: what % also have DMARC reject?
    section("E3. CORRELATION: STRICT SPF → DMARC REJECT?")
    strict_spf = df[df["policy_strictness"] == "strict (-all)"]
    strict_with_reject = strict_spf[strict_spf["dmarc_policy"].str.lower() == "reject"]
    print(f"  Domains with SPF -all:                {len(strict_spf):>10,}")
    print(f"  Of those, also DMARC p=reject:        {len(strict_with_reject):>10,}  ({pct(len(strict_with_reject), len(strict_spf))})")

    soft_spf = df[df["policy_strictness"] == "softfail (~all)"]
    soft_with_reject = soft_spf[soft_spf["dmarc_policy"].str.lower() == "reject"]
    print(f"\n  Domains with SPF ~all:                {len(soft_spf):>10,}")
    print(f"  Of those, also DMARC p=reject:        {len(soft_with_reject):>10,}  ({pct(len(soft_with_reject), len(soft_spf))})")

    # E4 – DKIM key strength by tier
    section("E4. DKIM KEY LENGTH DISTRIBUTION BY TIER (DKIM-present)")
    dkim_df = df[df["dkim_present"]]

    key_buckets = ["1024", "2048", "4096", "other/unknown"]

    print(f"\n  {'Tier':<25}", end="")
    for b in key_buckets:
        print(f"  {b+'-bit':>14}" if b != "other/unknown" else f"  {b:>14}", end="")
    print()
    print(f"  {'-'*25}", end="")
    for _ in key_buckets:
        print(f"  {'-'*14}", end="")
    print()

    for tier in TIER_ORDER:
        t = dkim_df[dkim_df[TIER_COL] == tier]
        tt = len(t)
        print(f"  {tier:<25}", end="")
        accounted = 0
        for bits in [1024, 2048, 4096]:
            cnt = (pd.to_numeric(t["key_length_bits"], errors="coerce") == bits).sum()
            accounted += cnt
            print(f"  {pct(cnt, tt):>14}", end="")
        other = tt - accounted
        print(f"  {pct(other, tt):>14}")

    # E5 – 2048-bit adoption trend
    section("E5. DKIM 2048-BIT KEY ADOPTION BY TIER")
    for tier in TIER_ORDER:
        t = dkim_df[dkim_df[TIER_COL] == tier]
        tt = len(t)
        kl = pd.to_numeric(t["key_length_bits"], errors="coerce")
        cnt_2048 = (kl == 2048).sum()
        cnt_1024 = (kl == 1024).sum()
        ratio = f"{cnt_2048/cnt_1024:.2f}" if cnt_1024 else "inf"
        print(f"  {tier:<25} 2048={cnt_2048:>5,}  1024={cnt_1024:>5,}  ratio={ratio}")

    # E6 – DKIM selector popularity by tier
    section("E6. DKIM SELECTOR POPULARITY BY TIER (top 5)")
    for tier in TIER_ORDER:
        t = dkim_df[dkim_df[TIER_COL] == tier]
        tt = len(t)
        print(f"\n  {tier}  (DKIM-present n={tt:,})")
        for sel, cnt in t["matched_selector"].value_counts().head(5).items():
            print(f"    {sel:<23} {cnt:>8,}  ({pct(cnt, tt)})")

    # E7 – DMARC alignment modes
    section("E7. DMARC ALIGNMENT MODES BY TIER (DMARC-present)")
    for tier in TIER_ORDER:
        t = dmarc_df[dmarc_df[TIER_COL] == tier]
        tt = len(t)
        adkim_strict = (t["dmarc_adkim"].astype(str).str.strip().str.lower() == "s").sum()
        aspf_strict = (t["dmarc_aspf"].astype(str).str.strip().str.lower() == "s").sum()
        print(
            f"  {tier:<25} adkim=strict: {pct(adkim_strict, tt):>8}  "
            f"aspf=strict: {pct(aspf_strict, tt):>8}  (n={tt:,})"
        )

    # E8 – DMARC reporting adoption
    section("E8. DMARC REPORTING ADOPTION BY TIER (DMARC-present)")
    print(f"\n  {'Tier':<25} {'Has rua':>12} {'Has ruf':>12} {'Both':>12} {'Neither':>12}")
    print(f"  {'-'*25} {'-'*12} {'-'*12} {'-'*12} {'-'*12}")
    for tier in TIER_ORDER:
        t = dmarc_df[dmarc_df[TIER_COL] == tier]
        tt = len(t)
        has_rua = t["dmarc_rua"].notna().sum()
        has_ruf = t["dmarc_ruf"].notna().sum()
        has_both = (t["dmarc_rua"].notna() & t["dmarc_ruf"].notna()).sum()
        has_neither = (t["dmarc_rua"].isna() & t["dmarc_ruf"].isna()).sum()
        print(
            f"  {tier:<25} {pct(has_rua, tt):>12} {pct(has_ruf, tt):>12} "
            f"{pct(has_both, tt):>12} {pct(has_neither, tt):>12}"
        )


# ─────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────
def main():
    print("Loading merged_results.csv …")
    df = load_and_clean("merged_results.csv")
    print(f"Loaded {len(df):,} rows.\n")

    conditional_probabilities(df)
    combination_analysis(df)
    case_studies(df)
    security_posture(df)
    protocol_deep_cuts(df)

    print(f"\n{SEP}")
    print("  FULL TRANCO ANALYSIS COMPLETE")
    print(SEP)


if __name__ == "__main__":
    main()
