import fcntl
import json
import logging
import os
import platform
import shutil
import socket
import threading
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.auth import (
    AuthError,
    AuthService,
    AuthStore,
    LoginResponse,
    ManagedUser,
    PublicUser,
    SessionResponse,
    UserCreate,
    UserList,
    UserUpdate,
    normalize_username,
)
from app.compiler import FirewallError
from app.demo import demo_config
from app.firewall import Conflict, DemoDriver, Driver, FirewallService, LinuxDriver
from app.models import Configuration, ConfirmRequest, LoginRequest, RevisionRequest, SaveRequest
from app.runtime import RouterRuntime, create_runtime
from app.storage import Store
from app.telemetry import TelemetryCollector, TelemetrySnapshot

log = logging.getLogger(__name__)
STATIC = Path(__file__).parent / "static"


def environment(name: str, legacy: str, default: str = "") -> str:
    return os.environ.get(name, os.environ.get(legacy, default))


@dataclass
class Settings:
    mode: str = field(default_factory=lambda: environment("OMR_MODE", "NAT_MODE", "demo"))
    data_dir: Path = field(
        default_factory=lambda: Path(environment("OMR_DATA_DIR", "NAT_DATA_DIR", "data"))
    )
    password: str = field(
        default_factory=lambda: environment("OMR_ADMIN_PASSWORD", "NAT_ADMIN_PASSWORD"), repr=False
    )
    auth_enabled: bool = field(
        default_factory=lambda: environment("OMR_AUTH_ENABLED", "NAT_AUTH_ENABLED") == "1"
    )
    admin_username: str = field(
        default_factory=lambda: environment("OMR_ADMIN_USERNAME", "NAT_ADMIN_USERNAME", "admin")
    )
    read_username: str = field(
        default_factory=lambda: environment("OMR_READ_USERNAME", "NAT_READ_USERNAME", "viewer")
    )
    read_password: str = field(
        default_factory=lambda: environment("OMR_READ_PASSWORD", "NAT_READ_PASSWORD"), repr=False
    )
    allowed_hosts: list[str] = field(
        default_factory=lambda: environment(
            "OMR_ALLOWED_HOSTS", "NAT_ALLOWED_HOSTS", "localhost,127.0.0.1,[::1],testserver"
        ).split(",")
    )
    secure_cookie: bool = field(
        default_factory=lambda: environment("OMR_SECURE_COOKIE", "NAT_SECURE_COOKIE") == "1"
    )

    def __post_init__(self) -> None:
        if self.mode not in ("demo", "linux"):
            raise RuntimeError("OMR_MODE must be demo or linux")
        existing_accounts = AuthStore.has_users(self.data_dir / "auth.sqlite3")
        self.auth_enabled = self.mode == "linux" or self.auth_enabled or existing_accounts
        if (self.password and not 12 <= len(self.password) <= 512) or (
            self.auth_enabled and not existing_accounts and not self.password
        ):
            raise RuntimeError(
                "Set OMR_ADMIN_PASSWORD to at least 12 characters "
                "(maximum 512) for initial authentication"
            )
        if self.read_password and not 12 <= len(self.read_password) <= 512:
            raise RuntimeError("Set OMR_READ_PASSWORD to 12–512 characters")
        self.admin_username = normalize_username(self.admin_username)
        self.read_username = normalize_username(self.read_username)


def create_app(
    settings: Settings | None = None,
    driver: Driver | None = None,
    runtime: RouterRuntime | None = None,
) -> FastAPI:
    settings = settings or Settings()
    initial = demo_config() if settings.mode == "demo" else Configuration()
    store = Store(settings.data_dir / f"{settings.mode}.sqlite3", initial)
    injected_driver = driver is not None
    applied = Configuration.model_validate(store.read("applied"))
    driver = driver or (DemoDriver(applied) if settings.mode == "demo" else LinuxDriver())
    runtime = runtime or create_runtime(
        settings.data_dir, applied, settings.mode == "demo" or injected_driver
    )
    service = FirewallService(store, driver, runtime=runtime)
    telemetry = TelemetryCollector(settings.mode, settings.data_dir)
    stop = threading.Event()
    auth = AuthService(
        settings.data_dir,
        settings.auth_enabled,
        settings.admin_username,
        settings.password,
        settings.read_username,
        settings.read_password,
    )

    def watchdog() -> None:
        while not stop.wait(1):
            try:
                service.recover()
            except Exception:
                log.exception("Automatic router rollback failed; recovery remains pending")

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        # One process owns this database and the managed chains. Do not use multiple workers.
        with (settings.data_dir / f"{settings.mode}.lock").open("w") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError(
                    "Another OpenMikroRout process already owns this data directory"
                ) from exc
            try:
                service.recover(startup=True)
                if settings.mode == "linux" and not injected_driver:
                    service.restore_confirmed()
            except (FirewallError, OSError) as exc:
                store.write({"runtime_error": str(exc)}, "startup_failed", str(exc))
                log.exception(
                    "Startup router recovery failed; administrator intervention may be needed"
                )
            thread = threading.Thread(target=watchdog, daemon=True, name="router-rollback")
            thread.start()
            try:
                yield
            finally:
                stop.set()
                thread.join(timeout=20)
                if store.read("pending"):
                    service.rollback("Service stopped before confirmation")

    app = FastAPI(
        title="OpenMikroRout",
        version="0.2.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.service = service
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)

    @app.middleware("http")
    async def security(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        api_request = request.url.path.startswith("/api/")
        denied: Response | None = None
        request.state.current_user = None
        if api_request and request.method not in ("GET", "HEAD"):
            origin = request.headers.get("origin")
            expected_origin = f"{request.url.scheme}://{request.headers.get('host', '')}"
            if (
                request.headers.get("x-nat-request") != "1"
                or (origin and origin != expected_origin)
                or request.headers.get("sec-fetch-site") == "cross-site"
            ):
                denied = JSONResponse({"detail": "Same-origin request required"}, status_code=403)
            else:
                total = 0
                chunks = []
                async for chunk in request.stream():
                    total += len(chunk)
                    if total > 1_048_576:
                        denied = JSONResponse({"detail": "Request exceeds 1 MiB"}, status_code=413)
                        break
                    chunks.append(chunk)
                request._body = b"".join(chunks)
        if (
            api_request
            and not denied
            and request.url.path not in ("/api/health", "/api/login", "/api/logout")
        ):
            try:
                request.state.current_user = await run_in_threadpool(
                    auth.resolve, request.cookies.get("nat_session", "")
                )
            except AuthError as exc:
                denied = JSONResponse({"detail": str(exc)}, status_code=exc.status)
        if (
            api_request
            and not denied
            and auth.enabled
            and request.method not in ("GET", "HEAD")
            and request.url.path not in ("/api/login", "/api/logout", "/api/preview")
        ):
            user = request.state.current_user
            if user is None:
                denied = JSONResponse({"detail": "Sign in to manage the router"}, status_code=401)
            elif user.role != "full":
                denied = JSONResponse(
                    {"detail": "This account has read-only access"}, status_code=403
                )
        response = denied if denied is not None else await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        if api_request:
            response.headers["Cache-Control"] = "no-store"
        return response

    def authenticated(request: Request) -> PublicUser | None:
        user: PublicUser | None = request.state.current_user
        if auth.enabled and user is None:
            raise HTTPException(401, "Sign in to manage the router")
        return user

    def full_access(request: Request) -> PublicUser | None:
        user = authenticated(request)
        if auth.enabled and user is not None and user.role != "full":
            raise HTTPException(403, "Full access is required")
        return user

    @app.exception_handler(AuthError)
    async def auth_handler(_: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=exc.status)

    @app.exception_handler(Conflict)
    async def conflict_handler(_: Request, exc: Conflict) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(FirewallError)
    async def firewall_handler(_: Request, exc: FirewallError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=503)

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Do not echo inputs (notably passwords) in errors.
        errors = [
            {"field": ".".join(str(v) for v in item["loc"][1:]), "message": item["msg"]}
            for item in exc.errors()
        ]
        return JSONResponse({"detail": errors}, status_code=422)

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode}

    @app.get("/api/session")
    def session(request: Request) -> SessionResponse:
        return SessionResponse(auth_enabled=auth.enabled, user=request.state.current_user)

    @app.post("/api/login")
    def login(body: LoginRequest, request: Request, response: Response) -> LoginResponse:
        client = request.client.host if request.client else "unknown"
        token, user = auth.login(body.username, body.password, client)
        if token is not None:
            response.set_cookie(
                "nat_session",
                token,
                httponly=True,
                samesite="strict",
                secure=settings.secure_cookie,
                max_age=28_800,
                path="/api",
            )
        return LoginResponse(auth_enabled=auth.enabled, user=user)

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict[str, bool]:
        auth.logout(request.cookies.get("nat_session", ""))
        response.delete_cookie("nat_session", path="/api")
        return {"ok": True}

    @app.get("/api/users", dependencies=[Depends(full_access)])
    def users() -> UserList:
        return UserList(users=auth.require_store().list_users())

    @app.post("/api/users", status_code=201, dependencies=[Depends(full_access)])
    def create_user(body: UserCreate) -> ManagedUser:
        return auth.create(body)

    @app.put("/api/users/{user_id}", dependencies=[Depends(full_access)])
    def update_user(user_id: UUID, body: UserUpdate) -> ManagedUser:
        return auth.update(str(user_id), body)

    @app.delete("/api/users/{user_id}", dependencies=[Depends(full_access)])
    def delete_user(user_id: UUID, request: Request) -> dict[str, bool]:
        actor: PublicUser | None = request.state.current_user
        auth.delete(str(user_id), actor.id if actor else None)
        return {"ok": True}

    @app.get("/api/state", dependencies=[Depends(authenticated)])
    def state(request: Request) -> dict[str, Any]:
        return {
            **service.state(),
            "mode": settings.mode,
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "confirm_seconds": service.confirm_seconds,
            "application": "OpenMikroRout",
            "version": "0.2.0",
            "auth_enabled": auth.enabled,
            "current_user": request.state.current_user,
        }

    @app.put("/api/config", dependencies=[Depends(authenticated)])
    def save(body: SaveRequest) -> dict[str, Any]:
        return service.save(body.config, body.revision)

    @app.post("/api/discard", dependencies=[Depends(authenticated)])
    def discard(body: RevisionRequest) -> dict[str, Any]:
        return service.discard(body.revision)

    @app.post("/api/preview", dependencies=[Depends(authenticated)])
    def preview() -> dict[str, Any]:
        return service.preview()

    @app.post("/api/apply", dependencies=[Depends(authenticated)])
    def apply(body: RevisionRequest) -> dict[str, Any]:
        return service.apply(body.revision)

    @app.post("/api/confirm", dependencies=[Depends(authenticated)])
    def confirm(body: ConfirmRequest) -> dict[str, Any]:
        return service.confirm(body.token)

    @app.post("/api/rollback", dependencies=[Depends(authenticated)])
    def rollback() -> dict[str, Any]:
        return service.rollback()

    @app.get("/api/statistics", dependencies=[Depends(authenticated)])
    def statistics() -> dict[str, Any]:
        return {"counters": service.statistics(), "demo": settings.mode == "demo"}

    @app.get("/api/telemetry", dependencies=[Depends(authenticated)])
    def router_telemetry() -> TelemetrySnapshot:
        return telemetry.snapshot()

    @app.get("/api/audit", dependencies=[Depends(authenticated)])
    def audit() -> list[dict[str, Any]]:
        return store.audit()

    @app.get("/api/network/status", dependencies=[Depends(authenticated)])
    def network_status() -> dict[str, Any]:
        return service.network_status()

    @app.get("/api/interfaces", dependencies=[Depends(authenticated)])
    def interfaces() -> dict[str, Any]:
        if settings.mode == "demo":
            status = service.network_status()
            active = Configuration.model_validate(store.read("applied")).network
            rows: list[dict[str, Any]] = [
                {"name": "eth0", "address": "203.0.113.10/24", "state": "UP", "role": "WAN"},
                {"name": "eth1", "address": "", "state": "UP", "role": "LAN"},
                {"name": "eth2", "address": "", "state": "UP", "role": "LAN"},
                {"name": "wg0", "address": "10.8.0.1/24", "state": "UP", "role": "VPN"},
            ]
            known = {item["name"] for item in rows}
            for item in status.get("links", []):
                if item["name"] not in known:
                    rows.append(
                        {
                            "name": item["name"],
                            "address": "",
                            "state": "UP" if item["up"] else "DOWN",
                            "role": item["kind"],
                        }
                    )
            for item in rows:
                item.setdefault(
                    "kind", item["role"] if item["role"] in ("bridge", "vlan", "dummy") else "ether"
                )
                item.setdefault("mtu", 1500)
                addresses = [
                    address["address"]
                    for address in status.get("addresses", [])
                    if address["interface"] == item["name"]
                ]
                if addresses:
                    item["address"] = ", ".join(addresses)
                item["master"] = next(
                    (bridge.name for bridge in active.bridges if item["name"] in bridge.members),
                    None,
                )
            return {
                "interfaces": rows,
                "forwarding": status.get("forwarding"),
                "demo": True,
            }
        ip = shutil.which("ip")
        if not ip:
            raise FirewallError("Install iproute2 to list host interfaces")
        rows = json.loads(LinuxDriver.run([ip, "-d", "-j", "address", "show"]))
        items = [
            {
                "name": row["ifname"],
                "state": row.get("operstate", "UNKNOWN"),
                "role": "",
                "master": row.get("master"),
                "kind": row.get("linkinfo", {}).get("info_kind", row.get("link_type", "ether")),
                "mtu": row.get("mtu", 1500),
                "address": ", ".join(
                    f"{addr['local']}/{addr['prefixlen']}"
                    for addr in row.get("addr_info", [])
                    if addr["family"] == "inet"
                ),
            }
            for row in rows
        ]
        forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
        return {"interfaces": items, "forwarding": forwarding, "demo": False}

    app.mount("/", StaticFiles(directory=STATIC, html=True), name="web")
    return app
