#!/usr/bin/env python3
"""
Thorough SPF analysis across 1M Tranco domains.

Sections:
  1.  Overall SPF adoption
  2.  SPF adoption by ranking tier
  3.  Policy strictness – overall & by tier
  4.  DNS lookup count distribution & limit violations
  5.  SPF misconfigurations (multiple records, ptr, >10 lookups)
  6.  SPF mechanism usage (ip4, ip6, include, redirect, a, mx, ptr, exists)
  7.  Include-chain depth & most-included third-party domains
  8.  DNS error breakdown
  9.  SPF + DMARC aspf alignment cross-reference
  10. Domains with dangerously permissive (+all) policies
"""

import re
from collections import Counter

import pandas as pd

TIER_ORDER = [
    "Tier 1 (1-1K)",
    "Tier 2 (1K-10K)",
    "Tier 3 (10K-100K)",
    "Tier 4 (100K-1M)",
]
TIER_COL = "ranking_tier_x"
SEP = "=" * 70


def load_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, low_memory=False)

    bool_cols = [
        "spf_present", "dns_lookup_limit_exceeded",
        "multiple_spf_records", "has_ptr_mechanism",
    ]
    for col in bool_cols:
        df[col] = df[col].astype(str).str.strip().str.lower() == "true"

    df["dmarc_valid"] = df["dmarc_valid"].astype(str).str.strip().str.lower() == "true"
    df["dmarc_isPresent"] = df["dmarc_isPresent"].astype(str).str.strip().str.lower() == "true"

    df["error"] = df["error"].fillna("")
    df["spf_raw_record"] = df["spf_raw_record"].fillna("")
    df["include_chain"] = df["include_chain"].fillna("")

    return df


def pct(n, total):
    return f"{100 * n / total:.2f}%" if total else "N/A"


def section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


# ── helpers for mechanism parsing ──

MECHANISM_RE = re.compile(
    r"(?:^|\s)[+\-~?]?"
    r"(ip4|ip6|include|redirect|a|mx|ptr|exists|all)"
    r"(?:[:/=]|$|\s)",
    re.IGNORECASE,
)


def extract_mechanisms(raw: str) -> list[str]:
    """Return list of mechanism names found in a raw SPF record."""
    if not raw:
        return []
    return [m.lower() for m in MECHANISM_RE.findall(raw)]


def extract_includes(raw: str) -> list[str]:
    """Return include:/redirect= target domains."""
    targets = re.findall(r"(?:include:|redirect=)(\S+)", raw, re.IGNORECASE)
    return [t.rstrip(";") for t in targets]


# ─────────────────────────────────────────────────────────────────────
#  1. Overall SPF adoption
# ─────────────────────────────────────────────────────────────────────
def overall_adoption(df):
    section("1. OVERALL SPF ADOPTION")
    total = len(df)
    present = df["spf_present"].sum()
    missing_clean = ((~df["spf_present"]) & (df["error"] == "")).sum()
    had_error = (df["error"] != "").sum()

    print(f"  Total domains scanned:       {total:>10,}")
    print()
    print(f"  SPF record found:            {present:>10,}  ({pct(present, total)})")
    print(f"  No SPF (clean lookup):       {missing_clean:>10,}  ({pct(missing_clean, total)})")
    print(f"  DNS / lookup errors:         {had_error:>10,}  ({pct(had_error, total)})")
    print()

    resolvable = total - had_error
    print(f"  Resolvable domains:          {resolvable:>10,}")
    print(f"  SPF adoption (resolvable):   {present:>10,}  ({pct(present, resolvable)})")


# ─────────────────────────────────────────────────────────────────────
#  2. SPF adoption by ranking tier
# ─────────────────────────────────────────────────────────────────────
def adoption_by_tier(df):
    section("2. SPF ADOPTION BY RANKING TIER")
    print(f"\n  {'Tier':<25} {'Present':>10} {'Total':>10} {'Adopt%':>10}  {'Resolvable%':>12}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10}  {'-'*12}")

    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        total = len(t)
        present = t["spf_present"].sum()
        resolvable = (t["error"] == "").sum()
        print(
            f"  {tier:<25} {present:>10,} {total:>10,} {pct(present, total):>10}"
            f"  {pct(present, resolvable):>12}"
        )


# ─────────────────────────────────────────────────────────────────────
#  3. Policy strictness
# ─────────────────────────────────────────────────────────────────────
def policy_strictness(df):
    section("3a. POLICY STRICTNESS – OVERALL (all domains)")
    total = len(df)
    order = [
        "strict (-all)", "softfail (~all)", "neutral (?all)",
        "permissive (+all)", "no_all_mechanism", "missing",
    ]
    counts = df["policy_strictness"].value_counts()
    for s in order:
        cnt = counts.get(s, 0)
        print(f"  {s:<30} {cnt:>10,}  ({pct(cnt, total)})")

    section("3b. POLICY STRICTNESS – AMONG SPF-PRESENT DOMAINS ONLY")
    spf_df = df[df["spf_present"]]
    spf_total = len(spf_df)
    counts = spf_df["policy_strictness"].value_counts()
    for s in order:
        cnt = counts.get(s, 0)
        if cnt:
            print(f"  {s:<30} {cnt:>10,}  ({pct(cnt, spf_total)})")

    section("3c. POLICY STRICTNESS BY RANKING TIER (SPF-present)")
    for tier in TIER_ORDER:
        t = df[(df[TIER_COL] == tier) & (df["spf_present"])]
        t_total = len(t)
        counts = t["policy_strictness"].value_counts()
        print(f"\n  {tier}  (SPF-present n={t_total:,})")
        for s in order:
            cnt = counts.get(s, 0)
            if cnt:
                print(f"    {s:<28} {cnt:>8,}  ({pct(cnt, t_total)})")

    section("3d. STRICT (-all) vs SOFTFAIL (~all) RATIO BY TIER")
    print(f"\n  {'Tier':<25} {'Strict':>10} {'Softfail':>10} {'Ratio':>10}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10}")
    for tier in TIER_ORDER:
        t = df[(df[TIER_COL] == tier) & (df["spf_present"])]
        strict = (t["policy_strictness"] == "strict (-all)").sum()
        soft = (t["policy_strictness"] == "softfail (~all)").sum()
        ratio = f"{strict/soft:.2f}" if soft else "inf"
        print(f"  {tier:<25} {strict:>10,} {soft:>10,} {ratio:>10}")


# ─────────────────────────────────────────────────────────────────────
#  4. DNS lookup count distribution
# ─────────────────────────────────────────────────────────────────────
def dns_lookup_distribution(df):
    section("4a. DNS LOOKUP COUNT DISTRIBUTION (SPF-present)")
    spf_df = df[df["spf_present"]]
    stats = spf_df["dns_lookup_count"].describe()
    print(f"  count   {int(stats['count']):>10,}")
    print(f"  mean    {stats['mean']:>10.2f}")
    print(f"  std     {stats['std']:>10.2f}")
    print(f"  min     {int(stats['min']):>10}")
    print(f"  25%     {int(stats['25%']):>10}")
    print(f"  50%     {int(stats['50%']):>10}")
    print(f"  75%     {int(stats['75%']):>10}")
    print(f"  max     {int(stats['max']):>10}")

    section("4b. DNS LOOKUP COUNT HISTOGRAM (SPF-present)")
    bins = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 100]
    for i in range(len(bins) - 1):
        lo, hi = bins[i], bins[i + 1]
        if hi - lo == 1:
            label = f"  {lo:>2} lookups"
        else:
            label = f"  {lo:>2}-{hi-1:<2} lookups"
        cnt = ((spf_df["dns_lookup_count"] >= lo) & (spf_df["dns_lookup_count"] < hi)).sum()
        bar = "#" * max(1, int(cnt / len(spf_df) * 200))
        print(f"  {label:<18} {cnt:>8,}  ({pct(cnt, len(spf_df)):>7})  {bar}")

    section("4c. EXCEEDED 10-LOOKUP LIMIT BY TIER")
    for tier in TIER_ORDER:
        t = df[(df[TIER_COL] == tier) & (df["spf_present"])]
        t_total = len(t)
        exceeded = t["dns_lookup_limit_exceeded"].sum()
        print(f"  {tier:<25} {exceeded:>8,} / {t_total:<8,}  ({pct(exceeded, t_total)})")

    section("4d. AVERAGE DNS LOOKUP COUNT BY TIER (SPF-present)")
    for tier in TIER_ORDER:
        t = df[(df[TIER_COL] == tier) & (df["spf_present"])]
        avg = t["dns_lookup_count"].mean()
        med = t["dns_lookup_count"].median()
        mx = t["dns_lookup_count"].max()
        print(f"  {tier:<25} mean={avg:.2f}  median={med:.0f}  max={mx:.0f}")


# ─────────────────────────────────────────────────────────────────────
#  5. Misconfigurations
# ─────────────────────────────────────────────────────────────────────
def misconfigurations(df):
    section("5a. SPF MISCONFIGURATIONS – OVERALL (SPF-present)")
    spf_df = df[df["spf_present"]]
    spf_total = len(spf_df)

    multi = spf_df["multiple_spf_records"].sum()
    exceeded = spf_df["dns_lookup_limit_exceeded"].sum()
    ptr = spf_df["has_ptr_mechanism"].sum()
    permissive = (spf_df["policy_strictness"] == "permissive (+all)").sum()
    no_all = (spf_df["policy_strictness"] == "no_all_mechanism").sum()

    any_misconfig = (
        spf_df["multiple_spf_records"]
        | spf_df["dns_lookup_limit_exceeded"]
        | spf_df["has_ptr_mechanism"]
        | (spf_df["policy_strictness"] == "permissive (+all)")
    ).sum()

    print(f"  SPF-present domains:         {spf_total:>10,}")
    print()
    print(f"  Multiple SPF records:        {multi:>10,}  ({pct(multi, spf_total)})")
    print(f"  Exceeded 10-lookup limit:    {exceeded:>10,}  ({pct(exceeded, spf_total)})")
    print(f"  Deprecated ptr mechanism:    {ptr:>10,}  ({pct(ptr, spf_total)})")
    print(f"  Permissive +all policy:      {permissive:>10,}  ({pct(permissive, spf_total)})")
    print(f"  Missing all mechanism:       {no_all:>10,}  ({pct(no_all, spf_total)})")
    print()
    print(f"  Any misconfiguration*:       {any_misconfig:>10,}  ({pct(any_misconfig, spf_total)})")
    print(f"  (* multiple | exceeded | ptr | +all)")

    section("5b. MULTIPLE SPF RECORD COUNT DISTRIBUTION")
    multi_df = df[df["spf_record_count"] > 1]
    for cnt, n in df["spf_record_count"].value_counts().sort_index().items():
        if cnt > 1:
            print(f"  {cnt} SPF records:  {n:>8,} domains")

    section("5c. MISCONFIGURATIONS BY RANKING TIER (SPF-present)")
    for tier in TIER_ORDER:
        t = spf_df[spf_df[TIER_COL] == tier]
        t_total = len(t)
        m = t["multiple_spf_records"].sum()
        e = t["dns_lookup_limit_exceeded"].sum()
        p = t["has_ptr_mechanism"].sum()
        perm = (t["policy_strictness"] == "permissive (+all)").sum()
        print(f"\n  {tier}  (SPF-present n={t_total:,})")
        print(f"    Multiple SPF records:      {m:>8,}  ({pct(m, t_total)})")
        print(f"    Exceeded 10 lookups:       {e:>8,}  ({pct(e, t_total)})")
        print(f"    Deprecated ptr:            {p:>8,}  ({pct(p, t_total)})")
        print(f"    Permissive +all:           {perm:>8,}  ({pct(perm, t_total)})")


# ─────────────────────────────────────────────────────────────────────
#  6. Mechanism usage
# ─────────────────────────────────────────────────────────────────────
def mechanism_usage(df):
    section("6a. SPF MECHANISM USAGE – OVERALL (SPF-present)")
    spf_df = df[df["spf_present"]].copy()
    spf_total = len(spf_df)

    mech_counter: Counter = Counter()
    for raw in spf_df["spf_raw_record"]:
        first_record = raw.split("|||")[0].strip() if "|||" in raw else raw
        mechs = extract_mechanisms(first_record)
        mech_counter.update(set(mechs))

    print(f"  (how many SPF-present domains use each mechanism at least once)\n")
    for mech, cnt in mech_counter.most_common():
        print(f"  {mech:<20} {cnt:>10,}  ({pct(cnt, spf_total)})")

    section("6b. MECHANISM USAGE BY RANKING TIER")
    for tier in TIER_ORDER:
        t = spf_df[spf_df[TIER_COL] == tier]
        t_total = len(t)
        tier_counter: Counter = Counter()
        for raw in t["spf_raw_record"]:
            first_record = raw.split("|||")[0].strip() if "|||" in raw else raw
            tier_counter.update(set(extract_mechanisms(first_record)))
        print(f"\n  {tier}  (SPF-present n={t_total:,})")
        for mech, cnt in tier_counter.most_common():
            print(f"    {mech:<18} {cnt:>8,}  ({pct(cnt, t_total)})")


# ─────────────────────────────────────────────────────────────────────
#  7. Include chain & third-party domains
# ─────────────────────────────────────────────────────────────────────
def include_chain_analysis(df):
    section("7a. INCLUDE CHAIN DEPTH (SPF-present with includes)")
    spf_df = df[df["spf_present"] & (df["include_chain"] != "")]
    spf_with_inc = len(spf_df)
    spf_total = df["spf_present"].sum()

    print(f"  SPF-present domains with includes/redirects: {spf_with_inc:,}"
          f"  ({pct(spf_with_inc, spf_total)} of SPF-present)")

    depths = spf_df["include_chain"].str.split(";").apply(len)
    print(f"\n  Include/redirect chain length distribution:")
    for d in sorted(depths.unique()):
        cnt = (depths == d).sum()
        if cnt >= 10 or d <= 10:
            print(f"    depth {d:<3}  {cnt:>8,}  ({pct(cnt, spf_with_inc)})")

    section("7b. MOST COMMONLY INCLUDED THIRD-PARTY DOMAINS (top 30)")
    inc_counter: Counter = Counter()
    for chain in df[df["spf_present"]]["include_chain"]:
        if not chain:
            continue
        for domain in chain.split(";"):
            domain = domain.strip()
            if domain:
                inc_counter[domain] += 1

    print(f"  {'Domain':<45} {'Count':>10}  {'% of SPF':>10}")
    print(f"  {'-'*45} {'-'*10}  {'-'*10}")
    for domain, cnt in inc_counter.most_common(30):
        print(f"  {domain:<45} {cnt:>10,}  ({pct(cnt, spf_total)})")


# ─────────────────────────────────────────────────────────────────────
#  8. DNS error breakdown
# ─────────────────────────────────────────────────────────────────────
def error_breakdown(df):
    section("8a. DNS ERROR BREAKDOWN – OVERALL")
    err_df = df[df["error"] != ""]
    total_err = len(err_df)
    total = len(df)

    print(f"  Domains with errors: {total_err:,}  ({pct(total_err, total)})\n")

    def classify_error(e):
        e_lower = e.lower()
        if e_lower == "noanswer":
            return "NoAnswer"
        if e_lower == "nxdomain":
            return "NXDOMAIN"
        if "lifetimetimeout" in e_lower or "timeout" in e_lower:
            return "Timeout"
        if "nonameservers" in e_lower or "no nameservers" in e_lower:
            return "NoNameservers"
        if "nxdomain" in e_lower:
            return "Include-chain NXDOMAIN"
        if "noanswer" in e_lower:
            return "Include-chain NoAnswer"
        return "Other"

    err_types = err_df["error"].apply(classify_error)
    for val, cnt in err_types.value_counts().items():
        print(f"  {val:<30} {cnt:>10,}  ({pct(cnt, total_err)})")

    section("8b. DNS ERRORS BY RANKING TIER")
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        t_total = len(t)
        t_err = (t["error"] != "").sum()
        print(f"  {tier:<25} {t_err:>8,} / {t_total:<8,}  ({pct(t_err, t_total)})")


# ─────────────────────────────────────────────────────────────────────
#  9. SPF + DMARC alignment cross-reference
# ─────────────────────────────────────────────────────────────────────
def spf_dmarc_cross(df):
    section("9a. SPF + DMARC CO-ADOPTION")
    total = len(df)
    spf_only = (df["spf_present"] & ~df["dmarc_valid"]).sum()
    dmarc_only = (~df["spf_present"] & df["dmarc_valid"]).sum()
    both = (df["spf_present"] & df["dmarc_valid"]).sum()
    neither = (~df["spf_present"] & ~df["dmarc_valid"]).sum()

    print(f"  SPF + DMARC both valid:      {both:>10,}  ({pct(both, total)})")
    print(f"  SPF only (no valid DMARC):   {spf_only:>10,}  ({pct(spf_only, total)})")
    print(f"  DMARC only (no SPF):         {dmarc_only:>10,}  ({pct(dmarc_only, total)})")
    print(f"  Neither:                     {neither:>10,}  ({pct(neither, total)})")

    section("9b. SPF + DMARC CO-ADOPTION BY TIER")
    print(f"\n  {'Tier':<25} {'Both':>10} {'SPF only':>10} {'DMARC only':>10} {'Neither':>10}")
    print(f"  {'-'*25} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")
    for tier in TIER_ORDER:
        t = df[df[TIER_COL] == tier]
        tt = len(t)
        b = (t["spf_present"] & t["dmarc_valid"]).sum()
        s = (t["spf_present"] & ~t["dmarc_valid"]).sum()
        d = (~t["spf_present"] & t["dmarc_valid"]).sum()
        n = (~t["spf_present"] & ~t["dmarc_valid"]).sum()
        print(
            f"  {tier:<25} {pct(b,tt):>10} {pct(s,tt):>10} "
            f"{pct(d,tt):>10} {pct(n,tt):>10}"
        )

    section("9c. DMARC aspf ALIGNMENT MODE (among domains with both SPF + DMARC)")
    both_df = df[df["spf_present"] & df["dmarc_isPresent"]]
    both_total = len(both_df)
    print(f"  (n={both_total:,} domains with both SPF and DMARC)\n")
    aspf = both_df["dmarc_aspf"].fillna("(not set / default relaxed)")
    for val, cnt in aspf.value_counts().head(10).items():
        print(f"  {val:<35} {cnt:>10,}  ({pct(cnt, both_total)})")

    section("9d. DMARC POLICY vs SPF STRICTNESS (among domains with both)")
    if both_total > 0:
        ct = pd.crosstab(
            both_df["policy_strictness"],
            both_df["dmarc_policy"].fillna("(none)"),
        )
        ct_pct = ct.div(ct.sum().sum()) * 100
        print(ct_pct.round(2).to_string())


# ─────────────────────────────────────────────────────────────────────
#  10. Permissive +all deep-dive
# ─────────────────────────────────────────────────────────────────────
def permissive_deep_dive(df):
    section("10. PERMISSIVE +all DOMAINS")
    perm_df = df[df["policy_strictness"] == "permissive (+all)"]
    perm_total = len(perm_df)
    print(f"  Total domains with +all:  {perm_total:,}\n")

    print(f"  By tier:")
    for tier in TIER_ORDER:
        cnt = (perm_df[TIER_COL] == tier).sum()
        print(f"    {tier:<25} {cnt:>6,}")

    print(f"\n  Sample domains (first 15):")
    for _, row in perm_df.head(15).iterrows():
        print(f"    rank={int(row['tranco_rank_x']):>7,}  {row['domain']}")


# ─────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────
def main():
    print("Loading merged_results.csv …")
    df = load_data("../merged_results.csv")
    print(f"Loaded {len(df):,} rows.\n")

    overall_adoption(df)
    adoption_by_tier(df)
    policy_strictness(df)
    dns_lookup_distribution(df)
    misconfigurations(df)
    mechanism_usage(df)
    include_chain_analysis(df)
    error_breakdown(df)
    spf_dmarc_cross(df)
    permissive_deep_dive(df)

    print(f"\n{SEP}")
    print("  SPF ANALYSIS COMPLETE")
    print(SEP)


if __name__ == "__main__":
    main()
