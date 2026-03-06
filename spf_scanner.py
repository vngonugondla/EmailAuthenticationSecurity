#!/usr/bin/env python3

import argparse
import csv
import json
import random
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from spf_utils import (
    classify_strictness,
    get_ranking_tier,
    query_spf_records,
    resolve_include_chain,
)

FIELDNAMES = [
    "domain",
    "tranco_rank",
    "ranking_tier",
    "query_timestamp",
    "spf_present",
    "spf_record_count",
    "spf_raw_record",
    "policy_strictness",
    "include_chain",
    "dns_lookup_count",
    "dns_lookup_limit_exceeded",
    "multiple_spf_records",
    "has_ptr_mechanism",
    "error",
]


# scan a single domain for spf and collect all the fields we need
def scan_domain(domain, rank, timeout=5.0):
    tier = get_ranking_tier(rank)
    timestamp = datetime.now(timezone.utc).isoformat()

    result = {
        "domain": domain,
        "tranco_rank": rank,
        "ranking_tier": tier,
        "query_timestamp": timestamp,
        "spf_present": False,
        "spf_record_count": 0,
        "spf_raw_record": "",
        "policy_strictness": "missing",
        "include_chain": "",
        "dns_lookup_count": 0,
        "dns_lookup_limit_exceeded": False,
        "multiple_spf_records": False,
        "has_ptr_mechanism": False,
        "error": "",
    }

    spf_data = query_spf_records(domain, timeout)

    if spf_data["error"]:
        result["error"] = spf_data["error"]
        return result

    result["spf_present"] = spf_data["spf_present"]
    result["spf_record_count"] = spf_data["spf_record_count"]
    result["multiple_spf_records"] = spf_data["spf_record_count"] > 1

    if not spf_data["spf_present"]:
        return result

    spf_record = spf_data["spf_raw_records"][0]
    if spf_data["spf_record_count"] > 1:
        result["spf_raw_record"] = " ||| ".join(spf_data["spf_raw_records"])
    else:
        result["spf_raw_record"] = spf_record

    result["policy_strictness"] = classify_strictness(spf_record)

    chain = resolve_include_chain(domain, spf_record, timeout)
    result["include_chain"] = "; ".join(chain["all_included_domains"])
    result["dns_lookup_count"] = chain["dns_lookup_count"]
    result["dns_lookup_limit_exceeded"] = chain["dns_lookup_count"] > 10
    result["has_ptr_mechanism"] = chain["has_ptr"]

    if chain["errors"]:
        result["error"] = "; ".join(chain["errors"])

    return result


# load domains from the tranco csv, with optional stratified sampling across tiers
def load_tranco(path, sample=None):
    domains = []

    with open(path, "r") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) >= 2:
                try:
                    domains.append((int(row[0]), row[1].strip()))
                except ValueError:
                    continue

    if sample is None or sample >= len(domains):
        return domains

    tier_buckets = {"T1": [], "T2": [], "T3": [], "T4": []}
    for rank, domain in domains:
        if rank <= 1_000:
            tier_buckets["T1"].append((rank, domain))
        elif rank <= 10_000:
            tier_buckets["T2"].append((rank, domain))
        elif rank <= 100_000:
            tier_buckets["T3"].append((rank, domain))
        else:
            tier_buckets["T4"].append((rank, domain))

    per_tier = sample // 4
    sampled = []
    for bucket in tier_buckets.values():
        n = min(per_tier, len(bucket))
        sampled.extend(random.sample(bucket, n))

    remaining_pool = [d for d in domains if d not in set(sampled)]
    shortfall = sample - len(sampled)
    if shortfall > 0 and remaining_pool:
        sampled.extend(random.sample(remaining_pool, min(shortfall, len(remaining_pool))))

    return sorted(sampled, key=lambda x: x[0])


# print a summary of the scan results to the terminal
def print_summary(results):
    total = len(results)
    if total == 0:
        return

    present = sum(1 for r in results if r["spf_present"])
    missing = sum(1 for r in results if not r["spf_present"] and not r["error"])
    errors = sum(1 for r in results if r["error"])
    multiple = sum(1 for r in results if r["multiple_spf_records"])
    exceeded = sum(1 for r in results if r["dns_lookup_limit_exceeded"])
    has_ptr = sum(1 for r in results if r["has_ptr_mechanism"])

    pct = lambda n: f"{100 * n / total:.1f}%"

    print(f"\n{'=' * 55}")
    print("  SPF SCAN SUMMARY")
    print(f"{'=' * 55}")
    print(f"  Total domains scanned:   {total}")
    print(f"  SPF present:             {present:>6}  ({pct(present)})")
    print(f"  SPF missing:             {missing:>6}  ({pct(missing)})")
    print(f"  DNS errors:              {errors:>6}  ({pct(errors)})")
    print(f"  Multiple SPF records:    {multiple:>6}  ({pct(multiple)})")
    print(f"  Exceeded 10 lookups:     {exceeded:>6}  ({pct(exceeded)})")
    print(f"  Deprecated ptr usage:    {has_ptr:>6}  ({pct(has_ptr)})")

    print(f"\n  Policy Strictness Breakdown:")
    strictness_counts = {}
    for r in results:
        s = r["policy_strictness"]
        strictness_counts[s] = strictness_counts.get(s, 0) + 1
    for s, count in sorted(strictness_counts.items(), key=lambda x: -x[1]):
        print(f"    {s:<25} {count:>6}  ({pct(count)})")

    print(f"\n  SPF Adoption by Ranking Tier:")
    tier_stats = {}
    for r in results:
        tier = r["ranking_tier"]
        tier_stats.setdefault(tier, {"total": 0, "present": 0})
        tier_stats[tier]["total"] += 1
        if r["spf_present"]:
            tier_stats[tier]["present"] += 1
    for tier in sorted(tier_stats):
        ts = tier_stats[tier]
        tp = 100 * ts["present"] / ts["total"] if ts["total"] else 0
        print(f"    {tier:<25} {ts['present']:>6}/{ts['total']:<6}  ({tp:.1f}%)")

    print(f"{'=' * 55}\n")


# parse args, run the scan with threading, and write results to csv
def main():
    parser = argparse.ArgumentParser(description="SPF Scanner for Tranco domains")
    parser.add_argument("--input", "-i", default="tranco_VQPQN.csv",
                        help="Path to Tranco CSV")
    parser.add_argument("--output", "-o", default="spf_results.csv",
                        help="Output CSV path")
    parser.add_argument("--output-json", default=None,
                        help="Also save results as JSON")
    parser.add_argument("--sample", "-s", type=int, default=None,
                        help="Stratified sample size (equal across 4 tiers)")
    parser.add_argument("--workers", "-w", type=int, default=50,
                        help="Concurrent worker threads")
    parser.add_argument("--timeout", "-t", type=float, default=5.0,
                        help="DNS query timeout in seconds")
    args = parser.parse_args()

    print(f"Loading Tranco list from {args.input} ...")
    domains = load_tranco(args.input, args.sample)
    print(f"  {len(domains)} domains to scan\n")

    results = []
    completed = 0
    start_time = time.time()

    with open(args.output, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(scan_domain, domain, rank, args.timeout): (rank, domain)
                for rank, domain in domains
            }

            for future in as_completed(futures):
                rank, domain = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "domain": domain,
                        "tranco_rank": rank,
                        "ranking_tier": get_ranking_tier(rank),
                        "query_timestamp": datetime.now(timezone.utc).isoformat(),
                        "spf_present": False,
                        "spf_record_count": 0,
                        "spf_raw_record": "",
                        "policy_strictness": "error",
                        "include_chain": "",
                        "dns_lookup_count": 0,
                        "dns_lookup_limit_exceeded": False,
                        "multiple_spf_records": False,
                        "has_ptr_mechanism": False,
                        "error": str(e),
                    }

                results.append(result)
                writer.writerow(result)
                csvfile.flush()

                completed += 1
                if completed % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = completed / elapsed if elapsed else 0
                    eta = (len(domains) - completed) / rate if rate else 0
                    print(
                        f"  [{completed:>7}/{len(domains)}]  "
                        f"{rate:.1f} domains/sec  ETA: {eta:.0f}s",
                        end="\r",
                    )

    elapsed = time.time() - start_time
    print(f"\n\nScan complete — {len(domains)} domains in {elapsed:.1f}s")
    print(f"Results saved to {args.output}")

    if args.output_json:
        with open(args.output_json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"JSON results saved to {args.output_json}")

    print_summary(results)


if __name__ == "__main__":
    main()
