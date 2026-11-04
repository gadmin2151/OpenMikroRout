"""Authenticated transport for WireGuard drafts and reauthenticated secret export."""

from collections.abc import Callable
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from pydantic import Field, field_validator

from app.auth import AuthService, PublicUser
from app.firewall import Conflict, FirewallService
from app.ipv4 import endpoint_host
from app.link_models import LinkModel
from app.totp import CredentialProof
from app.wireguard_service import ClientImport, KeyCreate, PeerCreate, ServerSetup, WireGuardService
from app.wireguard_vault import WireGuardKey, WireGuardVault


class ExportRequest(LinkModel):
    object_id: UUID
    client: bool = True
    endpoint: str = Field(default="", max_length=253)
    proof: CredentialProof | None = None

    _endpoint = field_validator("endpoint")(endpoint_host)


def wireguard_router(
    firewall: FirewallService,
    vault: WireGuardVault,
    auth: AuthService,
    full_access: Callable[[Request], PublicUser | None],
    authenticated: Callable[[Request], PublicUser | None],
) -> APIRouter:
    router = APIRouter(prefix="/api/wireguard")
    service = WireGuardService(firewall, vault)

    @router.get("/status", dependencies=[Depends(authenticated)])
    def status() -> dict[str, Any]:
        with firewall.lock:
            if firewall.runtime is None or firewall.runtime.wireguard is None:
                return {"available": False, "interfaces": [], "error": "WireGuard is unavailable"}
            return firewall.runtime.wireguard.status()

    @router.post("/keys", dependencies=[Depends(full_access)])
    def key_create(body: KeyCreate) -> WireGuardKey:
        with firewall.lock:
            try:
                result = vault.create(body.kind, body.value)
            except (ValueError, RuntimeError) as exc:
                raise Conflict(
                    "Cannot store this WireGuard key; check format and private backup"
                ) from exc
            firewall.store.write({}, "wireguard_key_created", f"{result.kind}: {result.id}")
            return result

    @router.post("/server", dependencies=[Depends(full_access)])
    def server(body: ServerSetup) -> dict[str, Any]:
        try:
            return service.server(body)
        except ValueError as exc:
            raise Conflict(str(exc)) from exc

    @router.post("/import", dependencies=[Depends(full_access)])
    def import_client(body: ClientImport) -> dict[str, Any]:
        try:
            return service.import_client(body)
        except ValueError as exc:
            # The strict parser reports only option/line names, never secret input.
            raise Conflict(str(exc)) from exc

    @router.post("/peers", dependencies=[Depends(full_access)])
    def peer(body: PeerCreate) -> dict[str, Any]:
        try:
            return service.peer(body)
        except ValueError as exc:
            raise Conflict(str(exc)) from exc

    @router.post("/export", dependencies=[Depends(full_access)])
    def export(body: ExportRequest, request: Request) -> dict[str, str]:
        if auth.enabled:
            actor: PublicUser | None = request.state.current_user
            if actor is None or body.proof is None:
                raise Conflict("Confirm your password and enabled second factor to export keys")
            auth.reauthenticate(
                actor, body.proof, request.client.host if request.client else "unknown"
            )
        try:
            result = service.export(body.object_id, body.client, body.endpoint)
        except (ValueError, RuntimeError) as exc:
            raise Conflict(
                "Cannot export this profile; check endpoint, client address and keys"
            ) from exc
        firewall.store.write({}, "wireguard_private_export", str(body.object_id))
        return result

    return router
