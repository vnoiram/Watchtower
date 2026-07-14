from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.config import Settings
from api.app.models import Repository, RepositoryProvider, SourceClassification, now_utc
from api.app.services.github import GitHubRepositoryInfo, list_github_owner_repositories


def _source_classification_for_visibility(visibility: str) -> SourceClassification:
    if visibility == "public":
        return SourceClassification.public
    return SourceClassification.private


def _find_github_repository(db: Session, repo_info: GitHubRepositoryInfo) -> Repository | None:
    repository = db.scalar(
        select(Repository).where(
            Repository.provider == RepositoryProvider.github,
            Repository.provider_repository_id == repo_info.provider_repository_id,
        )
    )
    if repository:
        return repository
    return db.scalar(
        select(Repository).where(
            Repository.provider == RepositoryProvider.github,
            Repository.owner == repo_info.owner,
            Repository.name == repo_info.name,
        )
    )


def _apply_github_repository_info(repository: Repository, repo_info: GitHubRepositoryInfo) -> None:
    repository.provider = RepositoryProvider.github
    repository.provider_repository_id = repo_info.provider_repository_id
    repository.owner = repo_info.owner
    repository.name = repo_info.name
    repository.url = repo_info.url
    repository.visibility = repo_info.visibility
    repository.default_branch = repo_info.default_branch
    repository.archived = repo_info.archived
    repository.fork = repo_info.fork
    repository.topics = repo_info.topics
    repository.primary_language = repo_info.primary_language
    repository.pushed_at = repo_info.pushed_at
    repository.last_synced_at = now_utc()
    repository.source_classification = _source_classification_for_visibility(repo_info.visibility)


def sync_github_repositories(db: Session, owner: str, settings: Settings) -> list[Repository]:
    repositories: list[Repository] = []
    for repo_info in list_github_owner_repositories(owner, settings):
        repository = _find_github_repository(db, repo_info)
        if not repository:
            repository = Repository(
                provider=RepositoryProvider.github,
                provider_repository_id=repo_info.provider_repository_id,
                owner=repo_info.owner,
                name=repo_info.name,
                source_classification=_source_classification_for_visibility(repo_info.visibility),
                archived=repo_info.archived,
                fork=repo_info.fork,
                topics=[],
            )
            db.add(repository)
        _apply_github_repository_info(repository, repo_info)
        repositories.append(repository)
    db.flush()
    return repositories
