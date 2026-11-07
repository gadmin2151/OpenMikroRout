"""Validated system address-list identities shared by every rule compiler."""

import re
from typing import TYPE_CHECKING, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

if TYPE_CHECKING:
    from app.models import Configuration

# ISO 3166-1 alpha-2, plus XK used by the DB-IP dataset for Kosovo.
COUNTRY_CODES = frozenset(
    [
        "AD",
        "AE",
        "AF",
        "AG",
        "AI",
        "AL",
        "AM",
        "AO",
        "AQ",
        "AR",
        "AS",
        "AT",
        "AU",
        "AW",
        "AX",
        "AZ",
        "BA",
        "BB",
        "BD",
        "BE",
        "BF",
        "BG",
        "BH",
        "BI",
        "BJ",
        "BL",
        "BM",
        "BN",
        "BO",
        "BQ",
        "BR",
        "BS",
        "BT",
        "BV",
        "BW",
        "BY",
        "BZ",
        "CA",
        "CC",
        "CD",
        "CF",
        "CG",
        "CH",
        "CI",
        "CK",
        "CL",
        "CM",
        "CN",
        "CO",
        "CR",
        "CU",
        "CV",
        "CW",
        "CX",
        "CY",
        "CZ",
        "DE",
        "DJ",
        "DK",
        "DM",
        "DO",
        "DZ",
        "EC",
        "EE",
        "EG",
        "EH",
        "ER",
        "ES",
        "ET",
        "FI",
        "FJ",
        "FK",
        "FM",
        "FO",
        "FR",
        "GA",
        "GB",
        "GD",
        "GE",
        "GF",
        "GG",
        "GH",
        "GI",
        "GL",
        "GM",
        "GN",
        "GP",
        "GQ",
        "GR",
        "GS",
        "GT",
        "GU",
        "GW",
        "GY",
        "HK",
        "HM",
        "HN",
        "HR",
        "HT",
        "HU",
        "ID",
        "IE",
        "IL",
        "IM",
        "IN",
        "IO",
        "IQ",
        "IR",
        "IS",
        "IT",
        "JE",
        "JM",
        "JO",
        "JP",
        "KE",
        "KG",
        "KH",
        "KI",
        "KM",
        "KN",
        "KP",
        "KR",
        "KW",
        "KY",
        "KZ",
        "LA",
        "LB",
        "LC",
        "LI",
        "LK",
        "LR",
        "LS",
        "LT",
        "LU",
        "LV",
        "LY",
        "MA",
        "MC",
        "MD",
        "ME",
        "MF",
        "MG",
        "MH",
        "MK",
        "ML",
        "MM",
        "MN",
        "MO",
        "MP",
        "MQ",
        "MR",
        "MS",
        "MT",
        "MU",
        "MV",
        "MW",
        "MX",
        "MY",
        "MZ",
        "NA",
        "NC",
        "NE",
        "NF",
        "NG",
        "NI",
        "NL",
        "NO",
        "NP",
        "NR",
        "NU",
        "NZ",
        "OM",
        "PA",
        "PE",
        "PF",
        "PG",
        "PH",
        "PK",
        "PL",
        "PM",
        "PN",
        "PR",
        "PS",
        "PT",
        "PW",
        "PY",
        "QA",
        "RE",
        "RO",
        "RS",
        "RU",
        "RW",
        "SA",
        "SB",
        "SC",
        "SD",
        "SE",
        "SG",
        "SH",
        "SI",
        "SJ",
        "SK",
        "SL",
        "SM",
        "SN",
        "SO",
        "SR",
        "SS",
        "ST",
        "SV",
        "SX",
        "SY",
        "SZ",
        "TC",
        "TD",
        "TF",
        "TG",
        "TH",
        "TJ",
        "TK",
        "TL",
        "TM",
        "TN",
        "TO",
        "TR",
        "TT",
        "TV",
        "TW",
        "TZ",
        "UA",
        "UG",
        "UM",
        "US",
        "UY",
        "UZ",
        "VA",
        "VC",
        "VE",
        "VG",
        "VI",
        "VN",
        "VU",
        "WF",
        "WS",
        "XK",
        "YE",
        "YT",
        "ZA",
        "ZM",
        "ZW",
    ]
)


def country_code(value: str) -> str:
    value = value.upper()
    if value not in COUNTRY_CODES:
        raise ValueError("Choose a valid ISO country code")
    return value


def is_system_list(name: str) -> bool:
    return name.startswith(("geo_", "f2b_"))


def kernel_set_name(name: str) -> str:
    if name.startswith("geo_"):
        code = country_code(name[4:])
        if name != f"geo_{code}":
            raise ValueError("Country list names use uppercase ISO codes")
    elif not re.fullmatch(r"f2b_[a-z][a-z0-9_-]{0,19}", name):
        raise ValueError("Invalid system address list name")
    return f"omr_{name}"


class SystemAddressList(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=27)
    kind: Literal["country", "temporary"]
    country: str = ""
    profile: str = ""

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        kernel_set_name(self.name)
        if self.kind == "country":
            self.country = country_code(self.country)
            if self.name != f"geo_{self.country}" or self.profile:
                raise ValueError("Country list name must be geo_<country>; no profile is allowed")
        elif self.country or self.name != f"f2b_{self.profile}":
            raise ValueError("Temporary list name must be f2b_<profile>; no country is allowed")
        return self


class GeoIPSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    auto_update: bool = False
    check_hours: int = Field(default=24, ge=6, le=720)


class GeoIPLookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    address: str = Field(max_length=15)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        from ipaddress import IPv4Address

        return str(IPv4Address(value))


def resolved_system_lists(config: "Configuration") -> dict[str, SystemAddressList]:
    """Resolve explicit lists plus countries and temporary sets used by rules/profiles."""
    result = {item.name: item for item in config.system_lists}
    for rule in [*config.rules, *config.filter_rules]:
        for code in (rule.src_country, rule.dst_country):
            if code:
                result[f"geo_{code}"] = SystemAddressList(
                    name=f"geo_{code}", kind="country", country=code
                )
    from app.rule_protection import effective_fail2ban

    fail2ban = effective_fail2ban(config)
    profiles = {profile.id for profile in fail2ban.profiles} if fail2ban is not None else set()
    if any(
        item.kind == "temporary" and item.profile not in profiles for item in config.system_lists
    ):
        raise ValueError("Temporary system lists must belong to a configured Fail2ban profile")
    if fail2ban is not None:
        for profile in fail2ban.profiles:
            name = f"f2b_{profile.id}"
            item = SystemAddressList(name=name, kind="temporary", profile=profile.id)
            existing = result.get(name)
            if existing is not None and existing != item:
                raise ValueError(f"System list conflicts with Fail2ban profile: {name}")
            result[name] = item
            for code in {*profile.include_countries, *profile.exclude_countries}:
                code = country_code(code)
                result[f"geo_{code}"] = SystemAddressList(
                    name=f"geo_{code}", kind="country", country=code
                )
    return result


def required_system_lists(config: "Configuration") -> dict[str, SystemAddressList]:
    definitions = resolved_system_lists(config)
    needed = {
        ref
        for rule in [*config.rules, *config.filter_rules]
        if rule.enabled
        for ref in (rule.src_list, rule.dst_list)
        if ref in definitions
    }
    needed.update(
        f"geo_{code}"
        for rule in [*config.rules, *config.filter_rules]
        if rule.enabled
        for code in (rule.src_country, rule.dst_country)
        if code
    )
    needed.update(
        f"f2b_{rule.f2b_profile}"
        for rule in [*config.rules, *config.filter_rules]
        if rule.enabled and rule.f2b_profile
    )
    from app.rule_protection import effective_fail2ban

    f2b = effective_fail2ban(config)
    if f2b is not None and f2b.enabled:
        for profile in f2b.profiles:
            if profile.enabled:
                needed.add(f"f2b_{profile.id}")
                needed.update(
                    f"geo_{code}"
                    for code in [*profile.include_countries, *profile.exclude_countries]
                )
                if profile.scope:
                    needed.update(profile.scope.destination_sets)
    return {name: definitions[name] for name in sorted(needed)}
