"""Authenticated downloads and preview-bound configuration restoration."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Request, Response
from pydantic import Field, SecretStr

from app.auth import AuthService, PublicUser
from app.backup_archive import BackupError
from app.backups import BackupService
from app.firewall import Conflict, FirewallService
from app.link_models import LinkModel
from app.rsc import MAX_SCRIPT, ScriptError, export_rsc
from app.totp import CredentialProof


class BackupCreate(LinkModel):
    archive_password: SecretStr = Field(min_length=12, max_length=512)
    proof: CredentialProof | None = None


class ImportInspect(LinkModel):
    kind: Literal["rsc", "json", "backup"]
    data: str = Field(max_length=12 * 1024 * 1024, repr=False)
    archive_password: SecretStr = Field(default_factory=lambda: SecretStr(""), max_length=512)
    revision: int = Field(ge=0)


class ImportStage(LinkModel):
    preview_id: str = Field(min_length=20, max_length=100)
    revision: int = Field(ge=0)
    restore_accounts: bool = False
    proof: CredentialProof | None = None


def backup_router(
    firewall: FirewallService,
    service: BackupService,
    auth: AuthService,
    full_access: Callable[[Request], PublicUser | None],
    authenticated: Callable[[Request], PublicUser | None],
) -> APIRouter:
    router = APIRouter(prefix="/api/configuration")

    def actor(request: Request) -> str:
        user = request.state.current_user
        return str(user.id) if user else "demo"

    def proof(request: Request, value: CredentialProof | None) -> None:
        if auth.enabled:
            if value is None:
                raise Conflict("Подтвердите пароль и включённый второй фактор")
            auth.reauthenticate(
                request.state.current_user,
                value,
                request.client.host if request.client else "unknown",
            )

    @router.get("/export", dependencies=[Depends(authenticated)])
    def export(
        kind: Literal["rsc", "json"] = "rsc", source: Literal["applied", "draft"] = "applied"
    ) -> Response:
        import json

        from app.models import Configuration

        with firewall.lock:
            config = (
                Configuration.model_validate(firewall.store.read("applied"))
                if source == "applied"
                else firewall.config()
            )
            try:
                data = (
                    export_rsc(config)
                    if kind == "rsc"
                    else json.dumps(
                        {"version": 1, "config": config.model_dump(mode="json")},
                        ensure_ascii=False,
                        indent=2,
                    )
                )
            except ScriptError as exc:
                raise Conflict("Текстовый экспорт превышает 1 MiB; используйте backup") from exc
            if len(data.encode()) > MAX_SCRIPT:
                raise Conflict("Текстовый экспорт превышает 1 MiB; используйте backup")
            firewall.store.write(
                {}, "configuration_exported", f"{source}: {kind}; secret values omitted"
            )
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return Response(
            data,
            media_type="text/plain" if kind == "rsc" else "application/json",
            headers={
                "Content-Disposition": f'attachment; filename="openmikrorout-{stamp}.{kind}"',
                "Cache-Control": "no-store",
            },
        )

    @router.post("/backup", dependencies=[Depends(full_access)])
    def backup(body: BackupCreate, request: Request) -> Response:
        proof(request, body.proof)
        try:
            data = service.create(body.archive_password.get_secret_value())
        except BackupError as exc:
            raise Conflict(str(exc)) from exc
        except (ValueError, RuntimeError) as exc:
            raise Conflict(
                "Не удалось создать backup; проверьте состояние конфигурации и ключей"
            ) from exc
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return Response(
            data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="openmikrorout-{stamp}.backup"',
                "Cache-Control": "no-store",
            },
        )

    @router.post("/inspect", dependencies=[Depends(full_access)])
    def inspect(body: ImportInspect, request: Request) -> dict[str, Any]:
        try:
            return service.preview(
                body.kind,
                body.data,
                body.archive_password.get_secret_value(),
                actor(request),
                body.revision,
            )
        except ScriptError as exc:
            raise Conflict(str(exc)) from exc
        except BackupError as exc:
            raise Conflict(str(exc)) from exc
        except (ValueError, RuntimeError) as exc:
            raise Conflict(
                "Не удалось проверить файл: пароль неверен, файл повреждён или несовместим"
            ) from exc

    @router.post("/stage", dependencies=[Depends(full_access)])
    def stage(body: ImportStage, request: Request) -> dict[str, Any]:
        proof(request, body.proof)
        try:
            return service.stage(
                body.preview_id, actor(request), body.revision, body.restore_accounts
            )
        except (ValueError, RuntimeError) as exc:
            raise Conflict(
                "Не удалось подготовить восстановление. "
                "Проверьте файл, ключи и настройки авторизации"
            ) from exc

    return router
