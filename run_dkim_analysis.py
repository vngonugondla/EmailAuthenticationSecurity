import argparse
import asyncio
import csv
import logging
from typing import List, Optional

from dkim_analysis import (
    DkimResolver,
    iter_tranco_csv,
)


async def process_batch(resolver, batch_rows):

    tasks = [
        resolver.resolve_domain(domain=row[2], tranco_rank=row[1])
        for row in batch_rows
    ]

    return await asyncio.gather(*tasks)


async def run_analysis(
    input_csv,
    output_csv,
    selectors,
    max_concurrency,
    batch_size,
    limit,
):

    resolver = DkimResolver(
        selectors=selectors,
        max_concurrency=max_concurrency,
    )

    with open(output_csv, "w", newline="") as f_out:

        writer = csv.writer(f_out)

        writer.writerow(
            [
                "row_index",
                "domain",
                "tranco_rank",
                "ranking_tier",
                "query_timestamp_utc",
                "dkim_present",
                "matched_selector",
                "key_algorithm",
                "key_length_bits",
                "revoked",
            ]
        )

        batch = []
        processed_count = 0
        next_log_at = 1000

        for row_index, rank, domain in iter_tranco_csv(input_csv):

            batch.append((row_index, rank, domain))

            if limit and row_index >= limit:
                break

            if len(batch) >= batch_size:

                results = await process_batch(resolver, batch)

                for (row_idx, _, _), res in zip(batch, results):

                    dkim_value = "error" if res.error else res.dkim_present

                    writer.writerow(
                        [
                            row_idx,
                            res.domain,
                            res.tranco_rank,
                            res.ranking_tier,
                            res.query_timestamp_utc,
                            dkim_value,
                            res.matched_selector or "",
                            res.key_algorithm or "",
                            res.key_length_bits or "",
                            res.revoked,
                        ]
                    )

                processed_count += len(batch)
                while processed_count >= next_log_at:
                    logging.info("Processed %d entries ...", next_log_at)
                    next_log_at += 1000

                batch = []


        if batch:

            results = await process_batch(resolver, batch)

            for (row_idx, _, _), res in zip(batch, results):

                dkim_value = "error" if res.error else res.dkim_present

                writer.writerow(
                    [
                        row_idx,
                        res.domain,
                        res.tranco_rank,
                        res.ranking_tier,
                        res.query_timestamp_utc,
                        dkim_value,
                        res.matched_selector or "",
                        res.key_algorithm or "",
                        res.key_length_bits or "",
                        res.revoked,
                    ]
                )

            processed_count += len(batch)
            while processed_count >= next_log_at:
                logging.info("Processed %d entries ...", next_log_at)
                next_log_at += 1000

        logging.info("Done. Total entries processed: %d", processed_count)


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--output-csv", required=True)

    parser.add_argument(
        "--selectors",
        default=None,
        help="Optional comma-separated selectors",
    )

    parser.add_argument("--max-concurrency", type=int, default=300)
    parser.add_argument("--batch-size", type=int, default=512)
    parser.add_argument("--limit", type=int)

    return parser.parse_args()


def main():

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    args = parse_args()

    selectors = (
        [s.strip() for s in args.selectors.split(",")]
        if args.selectors
        else None
    )

    asyncio.run(
        run_analysis(
            args.input_csv,
            args.output_csv,
            selectors,
            args.max_concurrency,
            args.batch_size,
            args.limit,
        )
    )


if __name__ == "__main__":
    main()