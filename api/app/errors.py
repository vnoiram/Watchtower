from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from api.app.schemas import ProblemDetails


def problem(status: int, title: str, detail: str | None = None) -> HTTPException:
    return HTTPException(status_code=status, detail={"title": title, "detail": detail})


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(HTTPException)
    async def http_problem(_: Request, exc: HTTPException) -> JSONResponse:
        if isinstance(exc.detail, dict) and "title" in exc.detail:
            payload = ProblemDetails(
                title=exc.detail["title"],
                status=exc.status_code,
                detail=exc.detail.get("detail"),
            )
        else:
            payload = ProblemDetails(title="HTTP error", status=exc.status_code, detail=str(exc.detail))
        return JSONResponse(status_code=exc.status_code, content=payload.model_dump())

