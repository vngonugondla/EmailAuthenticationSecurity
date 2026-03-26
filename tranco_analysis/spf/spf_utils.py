import random
import time

import dns.resolver
import dns.exception

LOOKUP_MECHANISMS = {"include", "a", "mx", "redirect", "exists", "ptr"}

PUBLIC_RESOLVERS = [
    ["8.8.8.8", "8.8.4.4"],
    ["1.1.1.1", "1.0.0.1"],
    ["9.9.9.9", "149.112.112.112"],
    ["208.67.222.222", "208.67.220.220"],
]

RETRYABLE_ERRORS = (dns.resolver.NoNameservers, dns.exception.Timeout)

DEFAULT_RETRIES = 3


# assign a tier label based on the domain's tranco rank
def get_ranking_tier(rank):
    if rank <= 1_000:
        return "Tier 1 (1-1K)"
    elif rank <= 10_000:
        return "Tier 2 (1K-10K)"
    elif rank <= 100_000:
        return "Tier 3 (10K-100K)"
    else:
        return "Tier 4 (100K-1M)"


def _make_resolver(timeout=5.0, nameservers=None):
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameservers:
        resolver.nameservers = nameservers
    return resolver


# query dns txt records for a domain and pull out any spf records
def query_spf_records(domain, timeout=5.0, retries=DEFAULT_RETRIES):
    result = {
        "spf_present": False,
        "spf_record_count": 0,
        "spf_raw_records": [],
        "error": None,
    }

    last_error = None
    for attempt in range(retries + 1):
        try:
            ns = random.choice(PUBLIC_RESOLVERS)
            resolver = _make_resolver(timeout, nameservers=ns)

            answers = resolver.resolve(domain, "TXT")

            for rdata in answers:
                txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
                if txt.strip().lower().startswith("v=spf1"):
                    result["spf_raw_records"].append(txt.strip())

            result["spf_record_count"] = len(result["spf_raw_records"])
            result["spf_present"] = result["spf_record_count"] > 0
            result["error"] = None
            return result

        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"
            return result
        except dns.resolver.NoAnswer:
            result["error"] = "NoAnswer"
            return result
        except RETRYABLE_ERRORS as e:
            last_error = type(e).__name__
            if attempt < retries:
                time.sleep(1.5 * (2 ** attempt) + random.random())
                continue
        except Exception as e:
            last_error = str(e)
            if "no nameservers" in last_error.lower() and attempt < retries:
                time.sleep(1.5 * (2 ** attempt) + random.random())
                continue

    result["error"] = last_error or "UnknownError"
    return result


# figure out the policy strictness based on the all mechanism
def classify_strictness(record):
    if not record:
        return "missing"

    parts = record.lower().split()

    for part in reversed(parts):
        bare = part.lstrip("+-~?")
        if bare == "all":
            if part.startswith("-"):
                return "strict (-all)"
            elif part.startswith("~"):
                return "softfail (~all)"
            elif part.startswith("?"):
                return "neutral (?all)"
            else:
                return "permissive (+all)"

    return "no_all_mechanism"


# recursively walk the spf include/redirect chain and count dns lookups
def resolve_include_chain(domain, record, timeout=5.0, max_depth=10, _visited=None):
    if _visited is None:
        _visited = set()

    result = {
        "includes": [],
        "dns_lookup_count": 0,
        "all_included_domains": [],
        "has_ptr": False,
        "errors": [],
    }

    if domain in _visited or not record:
        return result
    _visited.add(domain)

    parts = record.split()

    for part in parts[1:]:
        mechanism = part.lstrip("+-~?")

        if mechanism.startswith("include:"):
            included_domain = mechanism.split(":", 1)[1]
            result["dns_lookup_count"] += 1
            result["all_included_domains"].append(included_domain)

            if len(_visited) < max_depth:
                _recurse_into(included_domain, result, timeout, max_depth, _visited)

        elif mechanism.startswith("redirect="):
            redirected_domain = mechanism.split("=", 1)[1]
            result["dns_lookup_count"] += 1
            result["all_included_domains"].append(redirected_domain)

            if len(_visited) < max_depth:
                _recurse_into(redirected_domain, result, timeout, max_depth, _visited)

        elif mechanism == "a" or mechanism.startswith("a:") or mechanism.startswith("a/"):
            result["dns_lookup_count"] += 1

        elif mechanism == "mx" or mechanism.startswith("mx:") or mechanism.startswith("mx/"):
            result["dns_lookup_count"] += 1

        elif mechanism.startswith("exists:"):
            result["dns_lookup_count"] += 1

        elif mechanism == "ptr" or mechanism.startswith("ptr:"):
            result["dns_lookup_count"] += 1
            result["has_ptr"] = True

    return result


# helper to resolve a sub-domain's spf and merge it into the parent result
def _recurse_into(target_domain, result, timeout, max_depth, _visited):
    try:
        sub_spf = query_spf_records(target_domain, timeout)
        if sub_spf["spf_present"] and sub_spf["spf_raw_records"]:
            sub_chain = resolve_include_chain(
                target_domain,
                sub_spf["spf_raw_records"][0],
                timeout,
                max_depth,
                _visited,
            )
            result["includes"].append(
                {
                    "domain": target_domain,
                    "record": sub_spf["spf_raw_records"][0],
                    "sub_includes": sub_chain["includes"],
                }
            )
            result["dns_lookup_count"] += sub_chain["dns_lookup_count"]
            result["all_included_domains"].extend(sub_chain["all_included_domains"])
            if sub_chain["has_ptr"]:
                result["has_ptr"] = True
        elif sub_spf["error"]:
            result["errors"].append(f"{target_domain}: {sub_spf['error']}")
    except Exception as e:
        result["errors"].append(f"{target_domain}: {e}")


