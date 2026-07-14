from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import datetime
from uuid import UUID

from sqlalchemy import Select, tuple_


def encode_cursor(created_at: datetime, item_id: UUID) -> str:
    raw = f"{created_at.isoformat()}|{item_id}"
    return urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if not cursor:
        return None
    raw = urlsafe_b64decode(cursor.encode()).decode()
    created_at, item_id = raw.split("|", 1)
    return datetime.fromisoformat(created_at), UUID(item_id)


def apply_cursor(stmt: Select, model, cursor: str | None, limit: int) -> Select:
    decoded = decode_cursor(cursor)
    if decoded:
        created_at, item_id = decoded
        stmt = stmt.where(tuple_(model.created_at, model.id) > (created_at, item_id))
    return stmt.order_by(model.created_at.asc(), model.id.asc()).limit(min(limit, 100) + 1)

