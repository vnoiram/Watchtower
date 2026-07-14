import argparse

from api.app.database import SessionLocal
from api.app.services.scheduler import enqueue_stale_repository_scans


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enqueue scans for stale repositories.")
    parser.add_argument("--stale-after-hours", type=int, default=24)
    parser.add_argument("--limit", type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    with SessionLocal() as db:
        result = enqueue_stale_repository_scans(
            db,
            stale_after_hours=args.stale_after_hours,
            limit=args.limit,
        )
        db.commit()

    print(f"enqueued={result.enqueued_count}")
    print(f"considered={result.considered_count}")
    print(f"skipped_archived={result.archived_count}")
    print(f"skipped_missing_source={result.missing_source_count}")
    print(f"skipped_fresh={result.fresh_count}")
    print(f"skipped_already_queued={result.already_queued_count}")


if __name__ == "__main__":
    main()
