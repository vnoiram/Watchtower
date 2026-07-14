import pytest

from api.app.config import Settings
from worker import scheduler


class FakeResult:
    enqueued_count = 3
    considered_count = 5
    archived_count = 1
    missing_source_count = 0
    fresh_count = 1
    already_queued_count = 0


class FakeSession:
    def __init__(self) -> None:
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def __enter__(self) -> "FakeSession":
        return self

    def __exit__(self, *args: object) -> None:
        self.closed = True

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


def test_run_once_uses_settings_and_commits(monkeypatch: pytest.MonkeyPatch) -> None:
    db = FakeSession()
    calls = []

    def fake_enqueue(db_arg: FakeSession, *, stale_after_hours: int, limit: int | None) -> FakeResult:
        calls.append((db_arg, stale_after_hours, limit))
        return FakeResult()

    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    monkeypatch.setattr(scheduler, "enqueue_stale_repository_scans", fake_enqueue)

    scheduler.run_once(Settings(scan_scheduler_stale_after_hours=48, scan_scheduler_limit=25))

    assert calls == [(db, 48, 25)]
    assert db.committed is True
    assert db.rolled_back is False
    assert db.closed is True


def test_run_once_rolls_back_and_reraises_on_enqueue_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = FakeSession()

    def fake_enqueue(*args: object, **kwargs: object) -> FakeResult:
        raise RuntimeError("enqueue failed")

    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    monkeypatch.setattr(scheduler, "enqueue_stale_repository_scans", fake_enqueue)

    with pytest.raises(RuntimeError, match="enqueue failed"):
        scheduler.run_once(Settings())

    assert db.committed is False
    assert db.rolled_back is True
    assert db.closed is True


def test_run_forever_runs_before_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    events = []
    settings = Settings(scan_scheduler_interval_seconds=17)

    def fake_run_once(settings_arg: Settings) -> None:
        assert settings_arg is settings
        events.append("run")

    def fake_sleep(seconds: int) -> None:
        events.append(f"sleep:{seconds}")
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        scheduler.run_forever(settings, run_once_func=fake_run_once, sleep_func=fake_sleep)

    assert events == ["run", "sleep:17"]


def test_settings_treats_empty_scan_scheduler_limit_as_unset() -> None:
    settings = Settings(scan_scheduler_limit="")

    assert settings.scan_scheduler_limit is None
