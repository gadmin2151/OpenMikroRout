"""Configuration previews and rollback-aware application backups."""

import base64
import hashlib
import json
import secrets
import socket
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import SecretStr

from app.account_backup import AccountSnapshots
from app.auth import AuthError, AuthService
from app.backup_archive import (
    MAX_PLAINTEXT,
    BackupError,
    BackupKey,
    BackupPayload,
    decrypt_backup,
    encrypt_backup,
    referenced_keys,
)
from app.compiler import FirewallError
from app.firewall import Conflict, FirewallService
from app.models import Configuration
from app.rsc import MAX_SCRIPT, export_rsc, import_rsc
from app.version import VERSION
from app.wireguard_vault import WireGuardVault

PREVIEW_SECONDS = 300


def config_hash(config: Configuration) -> str:
    return hashlib.sha256(config.model_dump_json().encode()).hexdigest()


def configuration_summary(config: Configuration) -> dict[str, int]:
    result = {
        key: len(getattr(config, key))
        for key in ("rules", "filter_rules", "address_lists", "system_lists")
    }
    result["application_rules"] = len(config.applications.rules)
    for key, value in config.network.model_dump(mode="json").items():
        if isinstance(value, list):
            result[key] = len(value)
    return result


@dataclass(repr=False)
class ImportPreview:
    actor: str
    revision: int
    expires: float
    config: Configuration
    backup: BackupPayload | None


class BackupService:
    def __init__(self, firewall: FirewallService, auth: AuthService, vault: WireGuardVault) -> None:
        self.firewall, self.auth, self.vault = firewall, auth, vault
        self.accounts = AccountSnapshots(auth)
        self.previews: OrderedDict[str, ImportPreview] = OrderedDict()
        self.lock = threading.RLock()
        self.decrypt_slots = threading.BoundedSemaphore(1)
        self.attempts: dict[str, list[float]] = {}

    def prune(self) -> None:
        with self.lock:
            now = time.time()
            self.previews = OrderedDict((k, v) for k, v in self.previews.items() if v.expires > now)
            self.attempts = {
                actor: recent
                for actor, attempts in self.attempts.items()
                if (recent := [stamp for stamp in attempts if now - stamp < 60])
            }

    def snapshot(self, config: Configuration, revision: int) -> dict[str, Any]:
        plan = self.firewall.store.read("restore_plan")
        if not plan:
            return {}
        if plan["revision"] != revision or plan["config_hash"] != config_hash(config):
            raise Conflict("План восстановления устарел; отмените его и проверьте копию заново")
        return {"accounts": plan.get("accounts", [])}

    def confirm(self, snapshot: dict[str, Any], checkpoint: Callable[[], None]) -> bool:
        if not snapshot.get("accounts"):
            return False

        def journal(undo: list[dict[str, Any]]) -> None:
            # A retried confirmation must retain the original undo image.
            if "undo" not in snapshot:
                snapshot["undo"] = undo
            checkpoint()

        try:
            self.accounts.replace(snapshot["accounts"], journal)
        except (AuthError, ValueError, RuntimeError) as exc:
            raise FirewallError("Could not restore account settings") from exc
        return True

    def rollback(self, snapshot: dict[str, Any]) -> None:
        if snapshot.get("undo") and not snapshot.get("undone"):
            try:
                self.accounts.replace(snapshot["undo"])
                snapshot["undone"] = True
            except (AuthError, ValueError, RuntimeError) as exc:
                raise FirewallError("Account rollback needs attention") from exc

    def create(self, password: str) -> bytes:
        if not self.decrypt_slots.acquire(blocking=False):
            raise BackupError("Подождите завершения другой операции с резервной копией")
        try:
            with self.firewall.lock:
                state = self.firewall.state()
                if state["dirty"] or state["pending"] or state["runtime_error"]:
                    raise Conflict(
                        "Сначала примените или отмените черновик и завершите восстановление"
                    )
                config = self.firewall.config()
                payload = BackupPayload(
                    version=VERSION,
                    created_at=time.time(),
                    hostname=socket.gethostname(),
                    config=config,
                    accounts=self.accounts.export(),
                    keys=[
                        BackupKey(id=key_id, kind=kind, secret=self.vault.secret(key_id, kind))
                        for key_id, kind in referenced_keys(config).items()
                    ],
                )
                result = encrypt_backup(payload, password)
                self.firewall.store.write(
                    {},
                    "backup_created",
                    "Encrypted application configuration, accounts and VPN keys",
                )
                return result
        finally:
            self.decrypt_slots.release()

    def preview(
        self,
        kind: Literal["rsc", "json", "backup"],
        data: str,
        password: str,
        actor: str,
        revision: int,
    ) -> dict[str, Any]:
        with self.firewall.lock:
            self.firewall.check_revision(revision)
            base = self.firewall.config()
        backup = None
        if kind == "backup":
            with self.lock:
                now = time.time()
                recent = [t for t in self.attempts.get(actor, []) if now - t < 60]
                if len(recent) >= 5:
                    raise BackupError(
                        "Слишком много попыток открытия копии; повторите через минуту"
                    )
                self.attempts[actor] = [*recent, now]
            if not self.decrypt_slots.acquire(blocking=False):
                raise BackupError("Другая резервная копия уже проверяется")
            try:
                backup = decrypt_backup(base64.b64decode(data, validate=True), password)
                config = backup.config
            finally:
                self.decrypt_slots.release()
        elif kind == "rsc":
            config = import_rsc(data)
        else:
            if len(data.encode()) > MAX_SCRIPT:
                raise BackupError("JSON-файл превышает 1 MiB")
            try:
                raw = json.loads(data)
                if raw.get("version") != 1 or not isinstance(raw.get("config"), dict):
                    raise ValueError("Invalid export")
                value = raw["config"]
                defaults = base.model_dump(mode="json")
                for key in ("network", "filter_rules", "web_domain", "applications"):
                    value.setdefault(key, defaults[key])
                config = Configuration.model_validate(value)
            except (ValueError, TypeError, AttributeError, RecursionError) as exc:
                raise BackupError("Неверный JSON-экспорт OpenMikroRout") from exc
        if backup is None and self.firewall.config_validator:
            self.firewall.config_validator(config)
        with self.firewall.lock:
            self.firewall.check_revision(revision)
        token = secrets.token_urlsafe(24)
        with self.lock:
            self.previews = OrderedDict(
                (key, value)
                for key, value in self.previews.items()
                if value.expires > time.time() and value.actor != actor
            )
            while len(self.previews) >= 4:
                self.previews.popitem(last=False)
            self.previews[token] = ImportPreview(
                actor, revision, time.time() + PREVIEW_SECONDS, config, backup
            )
        return {
            "preview_id": token,
            "expires_in": PREVIEW_SECONDS,
            "kind": kind,
            "script": export_rsc(config, max_bytes=MAX_PLAINTEXT if backup else MAX_SCRIPT),
            "before": configuration_summary(base),
            "after": configuration_summary(config),
            "source_version": backup.version if backup else None,
            "created_at": backup.created_at if backup else None,
            "accounts": [
                {
                    "username": a.username,
                    "role": a.role,
                    "enabled": a.enabled,
                    "totp_enabled": bool(a.totp_secret),
                }
                for a in backup.accounts
            ]
            if backup
            else [],
            "private_keys": len(backup.keys) if backup else 0,
            "warnings": [
                "Учётные записи и секреты не входят в текстовый экспорт. "
                "Для переноса VPN-ключей используйте зашифрованный backup."
            ]
            if backup is None
            else [],
        }

    def stage(
        self, preview_id: str, actor: str, revision: int, restore_accounts: bool
    ) -> dict[str, Any]:
        with self.lock, self.firewall.lock:
            preview = self.previews.get(preview_id)
            if not preview or preview.actor != actor or preview.expires <= time.time():
                raise Conflict("Предпросмотр истёк; выберите файл ещё раз")
            if preview.revision != revision:
                raise Conflict("Конфигурация изменилась после предпросмотра")
            self.firewall.check_revision(revision)
            accounts = []
            if restore_accounts:
                if not preview.backup or not preview.backup.accounts:
                    raise BackupError("В копии нет учётных записей")
                accounts = self.accounts.prepare(preview.backup.accounts)
            if preview.backup:
                self.vault.import_keys(
                    [(key.id, key.kind, SecretStr(key.secret)) for key in preview.backup.keys]
                )
            plan = {
                "revision": revision + 1,
                "config_hash": config_hash(preview.config),
                "accounts": accounts,
            }
            self.firewall.save(preview.config, revision, restore_plan=plan)
            self.firewall.store.write(
                {},
                "restore_staged",
                f"{actor}: validated configuration; accounts={len(accounts)}",
            )
            self.previews.pop(preview_id, None)
            return self.firewall.state()
