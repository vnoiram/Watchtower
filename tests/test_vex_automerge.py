from datetime import datetime, timedelta, timezone

from api.app.services.automerge import evaluate_auto_merge
from api.app.services.vex import is_vex_expired


def test_vex_expiration_requires_future_review() -> None:
    assert is_vex_expired(datetime.now(timezone.utc) - timedelta(days=1))
    assert not is_vex_expired(datetime.now(timezone.utc) + timedelta(days=1))


def test_auto_merge_policy_defaults_to_dry_run_but_allows_eligible_change() -> None:
    decision = evaluate_auto_merge(
        enabled=True,
        dry_run=True,
        update_kind="patch",
        ci_passed=True,
        validation_scan_resolved=True,
        tier_allows=True,
        touches_forbidden_path=False,
    )
    assert decision.allowed
    assert decision.dry_run


def test_auto_merge_policy_rejects_major_update() -> None:
    decision = evaluate_auto_merge(
        enabled=True,
        dry_run=True,
        update_kind="major",
        ci_passed=True,
        validation_scan_resolved=True,
        tier_allows=True,
        touches_forbidden_path=False,
    )
    assert not decision.allowed

