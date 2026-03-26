import asyncio
import base64
import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional, Tuple

import dns.asyncresolver
import dns.exception
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


RankingTier = str


def get_ranking_tier(rank: int) -> RankingTier:
    if 1 <= rank <= 1000:
        return "Tier 1 (1-1K)"
    if 1001 <= rank <= 10_000:
        return "Tier 2 (1K-10K)"
    if 10_001 <= rank <= 100_000:
        return "Tier 3 (10K-100K)"
    if 100_001 <= rank <= 1_000_000:
        return "Tier 4 (100K-1M)"
    return "Unranked"


def iter_tranco_csv(path: str):
    with open(path, newline="") as f:
        reader = csv.reader(f)
        for row_idx, row in enumerate(reader):
            if len(row) < 2:
                continue
            try:
                rank = int(row[0])
            except ValueError:
                continue
            domain = row[1].strip()
            yield row_idx, rank, domain


def _join_txt_rdata(rdata) -> str:
    try:
        strings = getattr(rdata, "strings", None)
        if strings is None:
            return rdata.to_text().strip('"')
        return "".join(s.decode("utf-8", errors="ignore") for s in strings)
    except Exception:
        return rdata.to_text()


def _pick_dkim_txt(candidates):
    for txt in candidates:
        t = txt.replace(" ", "")
        if "v=DKIM1" in t and "p=" in t:
            return txt
    return None


@dataclass
class DkimAnalysisResult:
    domain: str
    tranco_rank: int
    ranking_tier: RankingTier
    query_timestamp_utc: str
    dkim_present: bool
    matched_selector: Optional[str]
    key_algorithm: Optional[str]
    key_length_bits: Optional[int]
    revoked: bool
    error: bool = False


class DkimResolver:
    def __init__(
        self,
        selectors: Optional[List[str]] = None,
        max_concurrency: int = 300,
        timeout: float = 2.0,
    ):

        self._selectors = selectors or [
            "default",
            "selector1",
            "selector2",
            "google",
            "k1",
            "s1",
            "s1024",
            "s2048",
            "smtp",
            "mail",
            "dkim",
            "mta",
            "mandrill",
            "sendgrid",
            "amazonses"
            ]

        self._resolver = dns.asyncresolver.Resolver()
        self._resolver.lifetime = timeout
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._cache: Dict[Tuple[str, str], Optional[str]] = {}

    async def _lookup_selector(self, domain, selector):

        key = (domain, selector)
        if key in self._cache:
            return self._cache[key]

        name = f"{selector}._domainkey.{domain}."

        try:
            async with self._semaphore:
                answer = await self._resolver.resolve(name, "TXT")
        except (dns.exception.DNSException, OSError):
            self._cache[key] = None
            return None

        texts = [_join_txt_rdata(rdata) for rdata in answer]
        txt = _pick_dkim_txt(texts)

        self._cache[key] = txt
        return txt

    @staticmethod
    def _parse_dkim_txt(txt):

        tags = {}

        for part in txt.split(";"):
            part = part.strip()
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

        k_tag = tags.get("k", "rsa").lower()
        p_tag = tags.get("p", "").strip()

        revoked = p_tag == ""

        key_bits = None
        algorithm = None

        if revoked:
            algorithm = "RSA" if k_tag == "rsa" else "Ed25519"
            return tags, revoked, key_bits, algorithm

        try:
            key_bytes = base64.b64decode(p_tag.encode("ascii"), validate=False)
        except Exception:
            return tags, revoked, key_bits, algorithm

        try:
            pub_key = serialization.load_der_public_key(key_bytes)
        except Exception:
            return tags, revoked, key_bits, algorithm

        if isinstance(pub_key, rsa.RSAPublicKey):
            algorithm = "RSA"
            key_bits = pub_key.key_size

        elif isinstance(pub_key, ed25519.Ed25519PublicKey):
            algorithm = "Ed25519"
            key_bits = 256

        return tags, revoked, key_bits, algorithm

    async def resolve_domain(self, domain, tranco_rank):

        timestamp = datetime.now(timezone.utc).isoformat()
        tier = get_ranking_tier(tranco_rank)

        try:
            for selector in self._selectors:

                txt = await self._lookup_selector(domain, selector)

                if txt is None:
                    continue

                tags, revoked, key_bits, algorithm = self._parse_dkim_txt(
                    txt
                )

                return DkimAnalysisResult(
                    domain=domain,
                    tranco_rank=tranco_rank,
                    ranking_tier=tier,
                    query_timestamp_utc=timestamp,
                    dkim_present=True,
                    matched_selector=selector,
                    key_algorithm=algorithm,
                    key_length_bits=key_bits,
                    revoked=revoked,
                )

            return DkimAnalysisResult(
                domain=domain,
                tranco_rank=tranco_rank,
                ranking_tier=tier,
                query_timestamp_utc=timestamp,
                dkim_present=False,
                matched_selector=None,
                key_algorithm=None,
                key_length_bits=None,
                revoked=False,
            )
        except Exception:
            return DkimAnalysisResult(
                domain=domain,
                tranco_rank=tranco_rank,
                ranking_tier=tier,
                query_timestamp_utc=timestamp,
                dkim_present=False,
                matched_selector=None,
                key_algorithm=None,
                key_length_bits=None,
                revoked=False,
                error=True,
            )