from __future__ import annotations

import logging
import time
from collections.abc import Callable

from api.app.config import Settings, get_settings
from api.app.database import SessionLocal
from api.app.services.scheduler import enqueue_stale_repository_scans

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("watchtower.scheduler")


def run_once(settings: Settings) -> None:
    with SessionLocal() as db:
        try:
            result = enqueue_stale_repository_scans(
                db,
                stale_after_hours=settings.scan_scheduler_stale_after_hours,
                limit=settings.scan_scheduler_limit,
            )
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("stale repository scan enqueue failed")
            raise

    logger.info(
        "stale repository scan enqueue completed enqueued=%s considered=%s skipped_archived=%s "
        "skipped_missing_source=%s skipped_fresh=%s skipped_already_queued=%s",
        result.enqueued_count,
        result.considered_count,
        result.archived_count,
        result.missing_source_count,
        result.fresh_count,
        result.already_queued_count,
    )


def run_forever(
    settings: Settings,
    *,
    run_once_func: Callable[[Settings], None] = run_once,
    sleep_func: Callable[[int], None] = time.sleep,
) -> None:
    while True:
        try:
            run_once_func(settings)
        except Exception:
            pass
        sleep_func(settings.scan_scheduler_interval_seconds)


def main() -> None:
    run_forever(get_settings())


if __name__ == "__main__":
    main()
