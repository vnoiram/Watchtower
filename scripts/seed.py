from api.app.database import SessionLocal
from api.app.models import Repository, RepositoryProvider, SourceClassification


def main() -> None:
    with SessionLocal() as db:
        repo = Repository(
            provider=RepositoryProvider.manual,
            provider_repository_id="seed-watchtower",
            owner="local",
            name="seed-repository",
            url="https://github.com/example/example",
            visibility="private",
            default_branch="main",
            source_classification=SourceClassification.private,
            archived=False,
            fork=False,
            topics=[],
        )
        db.add(repo)
        db.commit()
        print(repo.id)


if __name__ == "__main__":
    main()

