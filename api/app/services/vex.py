from datetime import datetime, timezone


def is_vex_expired(review_date: datetime, now: datetime | None = None) -> bool:
    current = now or datetime.now(timezone.utc)
    if review_date.tzinfo is None:
        review_date = review_date.replace(tzinfo=timezone.utc)
    return review_date < current

