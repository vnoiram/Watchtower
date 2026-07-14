from dataclasses import dataclass


@dataclass(frozen=True)
class AutoMergeDecision:
    allowed: bool
    reason: str
    dry_run: bool = True


def evaluate_auto_merge(
    *,
    enabled: bool,
    dry_run: bool,
    update_kind: str,
    ci_passed: bool,
    validation_scan_resolved: bool,
    tier_allows: bool,
    touches_forbidden_path: bool,
) -> AutoMergeDecision:
    if not enabled:
        return AutoMergeDecision(False, "auto merge disabled", dry_run)
    if update_kind not in {"patch", "minor"}:
        return AutoMergeDecision(False, "only patch and minor updates are eligible", dry_run)
    if not ci_passed:
        return AutoMergeDecision(False, "ci has not passed", dry_run)
    if not validation_scan_resolved:
        return AutoMergeDecision(False, "validation scan did not resolve finding", dry_run)
    if not tier_allows:
        return AutoMergeDecision(False, "application tier does not allow auto merge", dry_run)
    if touches_forbidden_path:
        return AutoMergeDecision(False, "change touches a forbidden path", dry_run)
    return AutoMergeDecision(True, "eligible", dry_run)

