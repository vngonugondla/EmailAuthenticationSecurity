#!/usr/bin/env python3
"""
Detailed analysis of email authentication results across all team members' emails.

Sections:
  F1. Overall pass rates (SPF, DKIM, DMARC, all three)
  F2. Pass rates by email category (Promotions, Updates, Social)
  F3. DMARC policy breakdown (overall and by category)
  F4. Failure investigation – which domains failed and why
  F5. Per-member comparison
  F6. Domain overlap across members
"""

import pandas as pd
from collections import Counter

SEP = "=" * 72


def pct(n, total):
    return f"{100 * n / total:.2f}%" if total else "N/A"


def section(title):
    print(f"\n{SEP}")
    print(f"  {title}")
    print(SEP)


def load_all():
    files = {
        "elizabeth": "elizabeth_email_auth_results.csv",
        "shreyashi": "shreyashi_email_auth_results.csv",
        "veena": "veena_email_auth_results.csv",
    }

    frames = {}
    for name, path in files.items():
        try:
            f = pd.read_csv(path)
            f["member"] = name
            frames[name] = f
        except Exception as e:
            print(f"  Warning: could not load {path}: {e}")

    df = pd.concat(frames.values(), axis=0, ignore_index=True)

    expected_cols = ["domain", "category", "spf_result", "dkim_result",
                     "dmarc_result", "dmarc_policy", "member"]
    for col in expected_cols:
        if col not in df.columns:
            df[col] = ""

    df["dmarc_policy"] = df["dmarc_policy"].fillna("").str.strip().str.upper()
    df["category"] = df["category"].fillna("Unknown").str.strip()

    return df


# ─────────────────────────────────────────────────────────────────────────
#  F1. Overall pass rates
# ─────────────────────────────────────────────────────────────────────────
def overall_pass_rates(df):
    section("F1. OVERALL PASS RATES")
    total = len(df)

    spf_pass = (df["spf_result"] == "pass").sum()
    dkim_pass = (df["dkim_result"] == "pass").sum()
    dmarc_pass = (df["dmarc_result"] == "pass").sum()
    all_pass = (
        (df["spf_result"] == "pass") &
        (df["dkim_result"] == "pass") &
        (df["dmarc_result"] == "pass")
    ).sum()
    any_fail = total - all_pass

    print(f"  Total emails analyzed:   {total:>6}")
    print()
    print(f"  SPF pass:                {spf_pass:>6}  ({pct(spf_pass, total)})")
    print(f"  DKIM pass:               {dkim_pass:>6}  ({pct(dkim_pass, total)})")
    print(f"  DMARC pass:              {dmarc_pass:>6}  ({pct(dmarc_pass, total)})")
    print()
    print(f"  All three pass:          {all_pass:>6}  ({pct(all_pass, total)})")
    print(f"  At least one failure:    {any_fail:>6}  ({pct(any_fail, total)})")


# ─────────────────────────────────────────────────────────────────────────
#  F2. Pass rates by category
# ─────────────────────────────────────────────────────────────────────────
def pass_rates_by_category(df):
    section("F2. PASS RATES BY EMAIL CATEGORY")

    categories = sorted(df["category"].unique())

    print(f"\n  {'Category':<20} {'n':>5} {'SPF':>10} {'DKIM':>10} {'DMARC':>10} {'All 3':>10}")
    print(f"  {'-'*20} {'-'*5} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

    for cat in categories:
        t = df[df["category"] == cat]
        tt = len(t)
        spf = (t["spf_result"] == "pass").sum()
        dkim = (t["dkim_result"] == "pass").sum()
        dmarc = (t["dmarc_result"] == "pass").sum()
        all3 = ((t["spf_result"] == "pass") & (t["dkim_result"] == "pass") & (t["dmarc_result"] == "pass")).sum()
        print(
            f"  {cat:<20} {tt:>5} {pct(spf,tt):>10} {pct(dkim,tt):>10} "
            f"{pct(dmarc,tt):>10} {pct(all3,tt):>10}"
        )


# ─────────────────────────────────────────────────────────────────────────
#  F3. DMARC policy breakdown
# ─────────────────────────────────────────────────────────────────────────
def dmarc_policy_breakdown(df):
    section("F3a. DMARC POLICY BREAKDOWN – OVERALL")
    total = len(df)
    for val, cnt in df["dmarc_policy"].value_counts().items():
        label = val if val else "(empty/none)"
        print(f"  {label:<20} {cnt:>6}  ({pct(cnt, total)})")

    section("F3b. DMARC POLICY BY CATEGORY")
    categories = sorted(df["category"].unique())
    policies = ["REJECT", "QUARANTINE", "NONE", ""]

    print(f"\n  {'Category':<20}", end="")
    for p in policies:
        label = p if p else "(empty)"
        print(f"  {label:>12}", end="")
    print()
    print(f"  {'-'*20}", end="")
    for _ in policies:
        print(f"  {'-'*12}", end="")
    print()

    for cat in categories:
        t = df[df["category"] == cat]
        tt = len(t)
        print(f"  {cat:<20}", end="")
        for p in policies:
            cnt = (t["dmarc_policy"] == p).sum()
            print(f"  {pct(cnt, tt):>12}", end="")
        print()


# ─────────────────────────────────────────────────────────────────────────
#  F4. Failure investigation
# ─────────────────────────────────────────────────────────────────────────
def failure_investigation(df):
    section("F4. EMAILS WITH AT LEAST ONE FAILURE")

    failures = df[
        (df["spf_result"] != "pass") |
        (df["dkim_result"] != "pass") |
        (df["dmarc_result"] != "pass")
    ]

    if len(failures) == 0:
        print("  No failures found — all emails passed SPF, DKIM, and DMARC.")
        return

    print(f"  Total emails with failures: {len(failures)}\n")
    print(
        f"  {'Domain':<40} {'Cat':<12} {'SPF':<8} {'DKIM':<8} "
        f"{'DMARC':<8} {'Policy':<12} {'Member':<10}"
    )
    print(
        f"  {'-'*40} {'-'*12} {'-'*8} {'-'*8} "
        f"{'-'*8} {'-'*12} {'-'*10}"
    )
    for _, row in failures.iterrows():
        spf_flag = "FAIL" if row["spf_result"] != "pass" else "pass"
        dkim_flag = "FAIL" if row["dkim_result"] != "pass" else "pass"
        dmarc_flag = "FAIL" if row["dmarc_result"] != "pass" else "pass"
        print(
            f"  {row['domain']:<40} {row['category']:<12} {spf_flag:<8} {dkim_flag:<8} "
            f"{dmarc_flag:<8} {row['dmarc_policy']:<12} {row['member']:<10}"
        )

    section("F4b. FAILURE TYPE COUNTS")
    spf_fails = (df["spf_result"] != "pass").sum()
    dkim_fails = (df["dkim_result"] != "pass").sum()
    dmarc_fails = (df["dmarc_result"] != "pass").sum()
    print(f"  SPF failures:    {spf_fails:>4}")
    print(f"  DKIM failures:   {dkim_fails:>4}")
    print(f"  DMARC failures:  {dmarc_fails:>4}")


# ─────────────────────────────────────────────────────────────────────────
#  F5. Per-member comparison
# ─────────────────────────────────────────────────────────────────────────
def per_member_comparison(df):
    section("F5. PER-MEMBER COMPARISON")

    members = sorted(df["member"].unique())

    print(f"\n  {'Member':<15} {'n':>5} {'SPF':>10} {'DKIM':>10} {'DMARC':>10} {'All 3':>10}")
    print(f"  {'-'*15} {'-'*5} {'-'*10} {'-'*10} {'-'*10} {'-'*10}")

    for member in members:
        t = df[df["member"] == member]
        tt = len(t)
        spf = (t["spf_result"] == "pass").sum()
        dkim = (t["dkim_result"] == "pass").sum()
        dmarc = (t["dmarc_result"] == "pass").sum()
        all3 = ((t["spf_result"] == "pass") & (t["dkim_result"] == "pass") & (t["dmarc_result"] == "pass")).sum()
        print(
            f"  {member:<15} {tt:>5} {pct(spf,tt):>10} {pct(dkim,tt):>10} "
            f"{pct(dmarc,tt):>10} {pct(all3,tt):>10}"
        )

    section("F5b. DMARC POLICY BY MEMBER")
    print(f"\n  {'Member':<15} {'REJECT':>10} {'QUARANTINE':>12} {'NONE':>10} {'(empty)':>10}")
    print(f"  {'-'*15} {'-'*10} {'-'*12} {'-'*10} {'-'*10}")
    for member in members:
        t = df[df["member"] == member]
        tt = len(t)
        rej = (t["dmarc_policy"] == "REJECT").sum()
        quar = (t["dmarc_policy"] == "QUARANTINE").sum()
        none_ = (t["dmarc_policy"] == "NONE").sum()
        empty = (t["dmarc_policy"] == "").sum()
        print(
            f"  {member:<15} {pct(rej,tt):>10} {pct(quar,tt):>12} "
            f"{pct(none_,tt):>10} {pct(empty,tt):>10}"
        )

    section("F5c. CATEGORY DISTRIBUTION BY MEMBER")
    for member in members:
        t = df[df["member"] == member]
        tt = len(t)
        print(f"\n  {member}  (n={tt})")
        for cat, cnt in t["category"].value_counts().items():
            print(f"    {cat:<20} {cnt:>4}  ({pct(cnt, tt)})")


# ─────────────────────────────────────────────────────────────────────────
#  F6. Domain overlap
# ─────────────────────────────────────────────────────────────────────────
def domain_overlap(df):
    section("F6. DOMAIN OVERLAP ACROSS MEMBERS")

    members = sorted(df["member"].unique())
    member_domains = {m: set(df[df["member"] == m]["domain"].unique()) for m in members}

    print(f"\n  Unique domains per member:")
    for m in members:
        print(f"    {m:<15} {len(member_domains[m]):>4} unique domains")

    all_domains = set()
    for s in member_domains.values():
        all_domains |= s
    print(f"\n  Total unique domains across all members: {len(all_domains)}")

    shared_all = set.intersection(*member_domains.values()) if len(members) > 1 else set()
    print(f"  Domains shared by ALL members:           {len(shared_all)}")
    if shared_all:
        for d in sorted(shared_all):
            print(f"    - {d}")

    if len(members) >= 2:
        print(f"\n  Pair-wise overlap:")
        for i, m1 in enumerate(members):
            for m2 in members[i+1:]:
                overlap = member_domains[m1] & member_domains[m2]
                print(f"    {m1} ∩ {m2}: {len(overlap)} domains")
                for d in sorted(overlap):
                    print(f"      - {d}")


# ─────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────
def main():
    print("Loading email authentication results …")
    df = load_all()
    print(f"Loaded {len(df)} emails from {df['member'].nunique()} members.\n")

    overall_pass_rates(df)
    pass_rates_by_category(df)
    dmarc_policy_breakdown(df)
    failure_investigation(df)
    per_member_comparison(df)
    domain_overlap(df)

    print(f"\n{SEP}")
    print("  EMAIL ANALYSIS COMPLETE")
    print(SEP)


if __name__ == "__main__":
    main()
