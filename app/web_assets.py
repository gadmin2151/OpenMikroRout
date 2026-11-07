"""Revalidate UI assets, including modules imported below the entry point."""

import os
from pathlib import Path

from starlette.middleware.gzip import GZipMiddleware
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Receive, Scope, Send


class StaticTextCompression(GZipMiddleware):
    """Compress text, while already compressed images keep their native bytes."""

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] == "http" and (
            path.endswith("/")
            or Path(path).suffix.lower() in {".html", ".js", ".mjs", ".css", ".svg"}
        ):
            await super().__call__(scope, receive, send)
        else:
            await self.app(scope, receive, send)


class WebAssets(StaticFiles):
    def file_response(
        self,
        full_path: str | os.PathLike[str],
        stat_result: os.stat_result,
        scope: Scope,
        status_code: int = 200,
    ) -> Response:
        response = super().file_response(full_path, stat_result, scope, status_code)
        if Path(full_path).suffix.lower() in {".html", ".js", ".mjs", ".css"}:
            # Keep ETag/Last-Modified and inexpensive 304s, but never reuse stale
            # application code after a release. Also applies to directory indexes.
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response
