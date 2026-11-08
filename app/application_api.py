"""Authenticated application catalog and bounded monitoring; policy uses common Apply."""

from collections.abc import Callable
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.application_runtime import ApplicationRuntime
from app.auth import PublicUser
from app.firewall import FirewallService


def application_router(
    service: FirewallService,
    runtime: ApplicationRuntime,
    authenticated: Callable[[Request], PublicUser | None],
    full_access: Callable[[Request], PublicUser | None],
) -> APIRouter:
    router = APIRouter(prefix="/api/applications", dependencies=[Depends(authenticated)])

    @router.get("/status")
    def status() -> dict[str, Any]:
        return runtime.status()

    @router.get("/catalog")
    def catalog(
        request: Request,
        expression: Annotated[str, Query(max_length=4096)] = "",
        offset: Annotated[int, Query(ge=0, le=10000)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> dict[str, Any]:
        user = request.state.current_user
        try:
            return runtime.catalog.page(
                service.config().applications.catalog_version,
                runtime.capabilities(),
                expression,
                offset,
                limit,
                user.language if user else "ru",
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/catalog/{identifier}")
    def entry(identifier: str, request: Request) -> dict[str, Any]:
        user = request.state.current_user
        items = runtime.catalog.entries(
            service.config().applications.catalog_version,
            runtime.capabilities(),
            language=user.language if user else "ru",
        )
        selected = next((item for item in items if item["id"] == identifier), None)
        if selected is None:
            raise HTTPException(404, "Unknown application catalog ID")
        return selected

    @router.get("/connections")
    def connections(
        expression: Annotated[str, Query(max_length=4096)] = "",
        offset: Annotated[int, Query(ge=0, le=10000)] = 0,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        try:
            return runtime.connections(expression, offset, limit)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/events")
    def events(
        offset: Annotated[int, Query(ge=0, le=10000)] = 0,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
    ) -> dict[str, Any]:
        return runtime.events(offset, limit)

    @router.get("/counters")
    def counters() -> dict[str, Any]:
        current = runtime.status()
        return {
            "packets": current["packets"],
            "flows": current["flows"],
            "counters_scope": "analyzed",
            "healthy": current["healthy"],
        }

    @router.post("/catalog/{operation}", dependencies=[Depends(full_access)])
    def synchronize(operation: str) -> dict[str, Any]:
        if operation not in ("check", "download"):
            raise HTTPException(404, "Unknown catalog operation")
        try:
            return runtime.catalog.sync(operation == "download")
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    return router
