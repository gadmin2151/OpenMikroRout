from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.compiler import FirewallError
from app.firewall import DemoDriver
from app.main import Settings, create_app
from app.models import Configuration
from app.runtime import create_runtime


def test_recovery_failure_refuses_requests_and_records_diagnostic(tmp_path: Path) -> None:
    app = create_app(Settings(data_dir=tmp_path))
    with (
        patch.object(
            app.state.service, "recover", side_effect=FirewallError("Recovery unavailable")
        ),
        pytest.raises(RuntimeError, match="refusing to start without protection"),
        TestClient(app),
    ):
        pytest.fail("A router with failed startup recovery must not serve requests")
    assert app.state.service.store.read("runtime_error") == "Recovery unavailable"
    assert app.state.service.store.audit()[0]["event"] == "startup_failed"


def test_linux_confirmed_restore_failure_prevents_startup(tmp_path: Path) -> None:
    config = Configuration()
    runtime = create_runtime(tmp_path, config, simulated=True)
    with (
        patch("app.main.LinuxDriver", return_value=DemoDriver(config)),
        patch("app.main.create_runtime", return_value=runtime),
    ):
        app = create_app(
            Settings(mode="linux", data_dir=tmp_path, password="test-only-strong-password")
        )
    with (
        patch.object(app.state.service, "restore_confirmed", side_effect=OSError("Kernel failure")),
        pytest.raises(RuntimeError, match="refusing to start without protection"),
        TestClient(app),
    ):
        pytest.fail("Linux startup must fail if confirmed protection cannot be restored")
    assert app.state.service.store.read("runtime_error") == "Kernel failure"
