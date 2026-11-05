"""Accept the configured panel hostname without replacing existing access addresses."""

from collections.abc import Callable

from starlette.concurrency import run_in_threadpool
from starlette.datastructures import Headers
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.types import ASGIApp, Receive, Scope, Send


class PanelHostMiddleware(TrustedHostMiddleware):
    def __init__(
        self, app: ASGIApp, allowed_hosts: list[str], domains: Callable[[], set[str]]
    ) -> None:
        super().__init__(app, allowed_hosts=allowed_hosts)
        self.domains = domains

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] in ("http", "websocket") and not self.allow_any:
            host, separator, port = Headers(scope=scope).get("host", "").partition(":")
            valid_port = not separator or (
                1 <= len(port) <= 5
                and port.isascii()
                and port.isdecimal()
                and 1 <= int(port) <= 65535
            )
            if (
                valid_port
                and host.lower() not in self.allowed_hosts
                and host.lower() in await run_in_threadpool(self.domains)
            ):
                await self.app(scope, receive, send)
                return
        await super().__call__(scope, receive, send)
