"""Authenticated security status, operational actions and bounded discovery APIs."""

from collections.abc import Callable
from ipaddress import IPv4Address
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import Field, field_validator

from app.auth import AuthService, PublicUser
from app.discovery_models import ScanRequest
from app.discovery_protocols import MAX_NEIGHBORS
from app.display_filters import validate_display_negation
from app.firewall import Conflict, FirewallService
from app.link_models import LinkModel
from app.list_filter_sql import ListFilterError
from app.models import RevisionRequest
from app.rule_protection import effective_fail2ban
from app.security_services import SecurityServices
from app.system_lists import resolved_system_lists
from app.totp import CredentialProof


class ProtectedAction(LinkModel):
    proof: CredentialProof | None = None


class ProtectedApply(RevisionRequest):
    proof: CredentialProof | None = None


class UnbanRequest(ProtectedAction):
    profile: str = Field(pattern=r"^[a-z][a-z0-9_]{0,19}$")
    address: str = Field(max_length=15)

    @field_validator("address")
    @classmethod
    def address_value(cls, value: str) -> str:
        return str(IPv4Address(value))


def reauthenticate(auth: AuthService, request: Request, proof: CredentialProof | None) -> None:
    if auth.enabled:
        if proof is None:
            raise Conflict("Подтвердите пароль и код 2FA для изменения защиты")
        actor = request.state.current_user
        if actor is None or actor.role != "full":
            raise Conflict("Full access is required")
        auth.reauthenticate(
            actor,
            proof,
            request.client.host if request.client else "unknown",
            token=request.cookies.get("nat_session", ""),
            required_role="full",
        )


PageOffset = Annotated[int, Query(ge=0, le=1_000_000)]
PageLimit = Annotated[int, Query(ge=1, le=200)]
HostOffset = Annotated[int, Query(ge=0, le=MAX_NEIGHBORS)]
SmallPageLimit = Annotated[int, Query(ge=1, le=100)]
NegatedFilters = Annotated[list[str] | None, Query(max_length=7)]
ListExpression = Annotated[str, Query(max_length=4096)]
ScanOffset = Annotated[int, Query(ge=0, le=100)]


def security_router(
    firewall: FirewallService,
    services: SecurityServices,
    auth: AuthService,
    full_access: Callable[[Request], PublicUser | None],
    authenticated: Callable[[Request], PublicUser | None],
) -> APIRouter:
    router = APIRouter(prefix="/api", dependencies=[Depends(authenticated)])

    def audit(request: Request, event: str, detail: str) -> None:
        user = request.state.current_user
        firewall.store.write({}, event, f"{user.username if user else 'demo'}: {detail}")

    @router.get("/security/fail2ban")
    def fail2ban_status() -> dict[str, Any]:
        config = firewall.config()
        effective = effective_fail2ban(config)
        status = services.fail2ban.status()
        collector = services.attempts.status()
        if collector["enabled"] and not collector["healthy"]:
            status["effective"] = False
            status["error"] = (
                status["error"]
                or collector["last_error"]
                or ("Сбор событий TCP не работает; автоматические баны не подтверждены")
            )
            status["warnings"].append(
                "Сбор событий TCP не подтверждён: проверьте состояние защиты."
            )
        return {
            **status,
            "connection_collector": collector,
            "draft_profiles": [profile.model_dump(mode="json") for profile in effective.profiles],
            "manual_enabled": config.fail2ban.enabled,
            "inline_enabled_count": sum(
                profile.rule_id is not None and profile.enabled for profile in effective.profiles
            ),
        }

    @router.get("/security/fail2ban/bans")
    def bans(
        profile: Annotated[str, Query(max_length=20, pattern=r"^[a-z0-9_]*$")] = "",
        query: Annotated[str, Query(max_length=64)] = "",
        offset: PageOffset = 0,
        limit: PageLimit = 50,
        negate: NegatedFilters = None,
        expression: ListExpression = "",
    ) -> dict[str, Any]:
        try:
            return services.fail2ban.bans.page(
                profile, query, limit, offset, negate=negate or [], expression=expression
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.post("/security/fail2ban/unban", dependencies=[Depends(full_access)])
    def unban(body: UnbanRequest, request: Request) -> dict[str, bool]:
        reauthenticate(auth, request, body.proof)
        with firewall.lock:
            if firewall.store.read("pending"):
                raise Conflict("Finish the pending application before unbanning")
            try:
                services.fail2ban.unban(body.profile, body.address)
            except ValueError as exc:
                raise Conflict(str(exc)) from exc
            audit(request, "fail2ban_unban", f"{body.profile} {body.address}")
        return {"ok": True}

    @router.get("/security/geoip")
    def geoip_status() -> dict[str, Any]:
        return services.geoip_status()

    @router.get("/security/geoip/countries")
    def countries(
        query: Annotated[str, Query(max_length=32)] = "",
        offset: PageOffset = 0,
        limit: PageLimit = 50,
        negate: NegatedFilters = None,
        expression: ListExpression = "",
    ) -> dict[str, Any]:
        try:
            return services.geoip.countries(
                query, offset, limit, negate=negate or [], expression=expression
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/security/geoip/lookup")
    def country(address: Annotated[str, Query(max_length=15)]) -> dict[str, Any]:
        try:
            return services.geoip.lookup(str(IPv4Address(address)))
        except ValueError as exc:
            raise Conflict("Enter a valid IPv4 address") from exc

    @router.post("/security/geoip/update", status_code=202, dependencies=[Depends(full_access)])
    def geoip_update(body: ProtectedAction, request: Request) -> dict[str, Any]:
        reauthenticate(auth, request, body.proof)
        result = services.queue_geoip()
        audit(request, "geoip_update_requested", "DB-IP Country Lite")
        return result

    @router.get("/security/lists")
    def lists() -> dict[str, Any]:
        with firewall.lock:
            config = firewall.config()
            rows = []
            counts = {
                row["country"]: row["networks"]
                for row in services.geoip.countries(limit=200)["items"]
            }
            # At most 250 ISO codes; read the final bounded page as well.
            counts.update(
                {
                    row["country"]: row["networks"]
                    for row in services.geoip.countries(offset=200, limit=200)["items"]
                }
            )
            for item in resolved_system_lists(config).values():
                count = (
                    counts.get(item.country, 0)
                    if item.kind == "country"
                    else services.fail2ban.bans.page(profile=item.profile, limit=1)["total"]
                )
                rows.append(
                    {
                        **item.model_dump(),
                        "count": count,
                        "version": services.geoip.active_version if item.kind == "country" else "",
                        "source": "DB-IP Country Lite" if item.kind == "country" else "Fail2ban",
                    }
                )
            return {"items": rows, "total": len(rows), "demo": services.demo}

    @router.get("/security/lists/{name}")
    def entries(
        name: str,
        offset: PageOffset = 0,
        limit: PageLimit = 50,
        query: Annotated[str, Query(max_length=64)] = "",
        negate: NegatedFilters = None,
        expression: ListExpression = "",
    ) -> dict[str, Any]:
        try:
            validate_display_negation(negate or [], {"query": query})
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        with firewall.lock:
            item = resolved_system_lists(firewall.config()).get(name)
            if item is None:
                raise Conflict("Unknown system address list")
        try:
            if item.kind == "country":
                return services.geoip.entries(
                    item.country, offset, limit, query, negate=negate or [], expression=expression
                )
            return services.fail2ban.bans.page(
                profile=item.profile,
                query=query,
                offset=offset,
                limit=limit,
                negate=negate or [],
                expression=expression,
            )
        except ListFilterError as exc:
            raise HTTPException(422, str(exc)) from exc
        except ValueError as exc:
            raise Conflict(str(exc)) from exc

    @router.get("/discovery/status")
    def discovery_status() -> dict[str, Any]:
        return services.discovery.status()

    @router.get("/discovery/hosts")
    def hosts(
        query: Annotated[str, Query(max_length=100)] = "",
        interface: Annotated[
            str,
            Query(max_length=15, pattern=r"^(?:[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14})?$"),
        ] = "",
        offset: HostOffset = 0,
        limit: SmallPageLimit = 50,
        negate: NegatedFilters = None,
        expression: ListExpression = "",
    ) -> dict[str, Any]:
        try:
            return services.discovery.hosts(
                query, interface, offset, limit, negate=negate or [], expression=expression
            )
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    @router.get("/discovery/hosts/{identifier}")
    def host(identifier: str) -> dict[str, Any]:
        try:
            return services.discovery.host(identifier)
        except KeyError as exc:
            raise HTTPException(404, "Host not found") from exc

    @router.get("/scans/status")
    def scan_status() -> dict[str, Any]:
        return services.scans.status()

    @router.get("/scans/jobs")
    def jobs(offset: ScanOffset = 0, limit: SmallPageLimit = 50) -> dict[str, Any]:
        return services.scans.jobs(offset, limit)

    @router.post("/scans/jobs", status_code=202, dependencies=[Depends(full_access)])
    def start_scan(body: ScanRequest, request: Request) -> dict[str, Any]:
        with firewall.lock:
            if firewall.store.read("pending"):
                raise Conflict("Finish the pending application before scanning")
            result = services.scans.start(body)
            audit(request, "scan_started", f"{body.kind} {body.interface} {body.target}")
        return result

    @router.get("/scans/jobs/{identifier}")
    def job(identifier: UUID) -> dict[str, Any]:
        try:
            return services.scans.job(identifier.hex)
        except KeyError as exc:
            raise HTTPException(404, "Scan job not found") from exc

    @router.post("/scans/jobs/{identifier}/cancel", dependencies=[Depends(full_access)])
    def cancel_scan(identifier: UUID, request: Request) -> dict[str, Any]:
        try:
            result = services.scans.cancel(identifier.hex)
        except KeyError as exc:
            raise HTTPException(404, "Scan job not found") from exc
        audit(request, "scan_cancelled", str(identifier))
        return result

    return router
