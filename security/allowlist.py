from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Tuple

READONLY = "readonly"
CHANGE = "change"
CLIENT = "client"

SWITCH = "switch"

_DC_TAIL = r"DC=[A-Za-z0-9\-]{1,63}(?:,DC=[A-Za-z0-9\-]{1,63})*"
DC_TAIL = _DC_TAIL
_DN = r"(?:(?:OU|CN)=[A-Za-z0-9 _\-]{1,64},)*" + _DC_TAIL
_REG_KEY = (
    r"(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)"
    r"(?:\\[A-Za-z0-9 _.\-]{1,64}){1,12}"
)

VALUE_PATTERNS: Dict[str, "re.Pattern[str]"] = {
    "name": re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.\-]{0,63}"),
    "wildname": re.compile(r"[A-Za-z0-9_.\-*]{1,64}"),
    "valuename": re.compile(r"[A-Za-z0-9_.\-]{1,64}"),
    "regvalue": re.compile(r"[A-Za-z0-9_.\-]{1,64}"),
    "comment": re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.\-]{0,99}"),
    "filter": re.compile(
        r"\*|[A-Za-z]{1,32} -(?:eq|ne|like|notlike) '[A-Za-z0-9 _.\-*]{1,64}'",
        re.IGNORECASE,
    ),
    "dn": re.compile(_DN, re.IGNORECASE),
    "reg_key": re.compile(_REG_KEY, re.IGNORECASE),
    "count": re.compile(r"[1-9]|10"),
}

@dataclass(frozen=True)
class CommandSpec:
    name: str
    category: str
    params: Dict[str, str]
    required: Tuple[str, ...] = ()
    needs_approval: bool = False

COMMANDS: Tuple[CommandSpec, ...] = (
    CommandSpec("Get-ADOrganizationalUnit", READONLY,
                {"-Identity": "dn", "-Filter": "filter", "-SearchBase": "dn"}),
    CommandSpec("Get-ADUser", READONLY,
                {"-Identity": "name", "-Filter": "filter", "-SearchBase": "dn"}),
    CommandSpec("Get-ADComputer", READONLY,
                {"-Identity": "name", "-Filter": "filter", "-SearchBase": "dn"}),
    CommandSpec("Get-GPO", READONLY,
                {"-Name": "name", "-All": SWITCH}),
    CommandSpec("Get-GPInheritance", READONLY,
                {"-Target": "dn"}, required=("-Target",)),
    CommandSpec("Get-GPOReport", READONLY,
                {"-Name": "name", "-ReportType": "enum:Html,Xml"},
                required=("-Name", "-ReportType")),
    CommandSpec("Get-GPRegistryValue", READONLY,
                {"-Name": "name", "-Key": "reg_key", "-ValueName": "valuename"},
                required=("-Name", "-Key")),
    CommandSpec("Get-AppxPackage", READONLY,
                {"-Name": "wildname"}),
    CommandSpec("Get-Help", READONLY,
                {"-Name": "cmdname", "-Full": SWITCH}, required=("-Name",)),
    CommandSpec("Test-Connection", READONLY,
                {"-ComputerName": "host", "-Count": "count"},
                required=("-ComputerName",)),
    CommandSpec("New-GPO", CHANGE,
                {"-Name": "name", "-Comment": "comment"},
                required=("-Name",)),
    CommandSpec("New-GPLink", CHANGE,
                {"-Name": "name", "-Target": "ou_target",
                 "-LinkEnabled": "enum:Yes,No"},
                required=("-Name", "-Target"), needs_approval=True),
    CommandSpec("Set-GPRegistryValue", CHANGE,
                {"-Name": "name", "-Key": "set_key", "-ValueName": "valuename",
                 "-Type": "enum:DWord,String", "-Value": "regvalue"},
                required=("-Name", "-Key", "-ValueName", "-Type", "-Value")),
)

COMMANDS_BY_LOWER: Dict[str, CommandSpec] = {c.name.lower(): c for c in COMMANDS}
ALLOWED_COMMAND_NAMES = frozenset(COMMANDS_BY_LOWER)

CLIENT_COMMANDS: Tuple[str, ...] = (
    "gpupdate /force",
    "gpresult /scope user /r",
    "gpresult /scope computer /r",
)

DENY_NAME_PATTERNS: Tuple[str, ...] = (
    r"remove-.*", r"reset-.*", r"disable-.*", r"format-.*",
    r"set-adaccountpassword", r"set-addomain.*", r"install-ad.*",
    r"set-netfirewall.*", r"netsh", r"invoke-expression", r"iex",
    r"invoke-webrequest", r"invoke-restmethod", r"invoke-command",
    r"start-process", r"set-executionpolicy", r"reg", r"net",
    r"restart-computer", r"stop-computer", r"powershell", r"pwsh", r"cmd",
)
