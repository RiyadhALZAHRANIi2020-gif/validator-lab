security/ """
security/validator.py

UNTESTED on a real lab (غير مجرّب). Pure Python, no Windows needed.

validate_command() decides if a command from the AI may run.
Default deny. It fails closed: any unexpected error = rejected.
The executor must run result.normalized, never the raw text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import FrozenSet, List, Optional, Tuple

from security import allowlist as al

MAX_COMMAND_LENGTH = 500

TOOL_CATEGORY = {
    "run_readonly_check": al.READONLY,
    "run_change_command": al.CHANGE,
    "verify_on_client": al.CLIENT,
}

FORBIDDEN_CHARS = {
    "\n": "newline",
    "\r": "carriage return",
    ";": "semicolon",
    "|": "pipe",
    "`": "backtick",
    "&": "ampersand",
    "$": "dollar sign",
    "{": "open brace",
    "}": "close brace",
    ">": "greater-than",
    "<": "less-than",
    "(": "open parenthesis",
    ")": "close parenthesis",
    "@": "at sign",
    "#": "hash",
}

@dataclass(frozen=True)
class ValidatorConfig:
    allowed_hosts: FrozenSet[str]                       
    allowed_ou_names: Tuple[str, ...] = ("IT", "Research")
    allowed_set_keys: FrozenSet[str] = frozenset()

@dataclass(frozen=True)
class ValidationResult:
    allowed: bool
    reason: Optional[str] = None
    command_name: Optional[str] = None
    category: Optional[str] = None
    requires_approval: bool = False
    normalized: Optional[str] = None     

class _Reject(Exception):
    pass

@dataclass(frozen=True)
class _Token:
    text: str      
    quoted: bool
    raw: str       

def _tokenize(s: str) -> List[_Token]:
    tokens: List[_Token] = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == " ":
            i += 1
        elif c in "\"'":
            end = s.find(c, i + 1)
            if end == -1:
                raise _Reject("unterminated quote")
            if end + 1 < n and s[end + 1] != " ":
                raise _Reject("characters directly after a closing quote")
            tokens.append(_Token(s[i + 1:end], True, s[i:end + 1]))
            i = end + 1
        else:
            j = i
            while j < n and s[j] != " ":
                if s[j] in "\"'":
                    raise _Reject("quote inside an unquoted word")
                j += 1
            tokens.append(_Token(s[i:j], False, s[i:j]))
            i = j
    return tokens

def _check_value(kind: str, tok: _Token, cfg: ValidatorConfig,
                 hosts_lower: FrozenSet[str], param: str) -> str:
    text = tok.text
    if text.startswith("-"):
        raise _Reject(f"missing or invalid value for {param}")
    if not tok.quoted and "," in text:
        raise _Reject(f"comma outside quotes in value of {param}")

    if kind.startswith("enum:"):
        for option in kind[5:].split(","):
            if option.lower() == text.lower():
                return option
        raise _Reject(f"value not allowed for {param}")

    if kind == "host":
        if text.lower() not in hosts_lower:
            raise _Reject(f"host not in lab host list: {text}")
        return tok.raw

    if kind == "cmdname":
        if text.lower() not in al.ALLOWED_COMMAND_NAMES:
            raise _Reject(f"Get-Help only for allowlisted commands: {text}")
        return tok.raw

    if kind == "ou_target":
        names = [re.escape(n) for n in cfg.allowed_ou_names]
        if not names:
            raise _Reject("no OU is approved as a link target")
        pattern = "OU=(?:" + "|".join(names) + ")," + al.DC_TAIL
        if not re.fullmatch(pattern, text, re.IGNORECASE):
            raise _Reject("New-GPLink target must be an approved OU")
        return tok.raw

    if kind == "set_key":
        if not al.VALUE_PATTERNS["reg_key"].fullmatch(text):
            raise _Reject("invalid registry key format")
        approved = {k.lower() for k in cfg.allowed_set_keys}
        if text.lower() not in approved:
            raise _Reject("registry key not approved for Set-GPRegistryValue")
        return tok.raw

    pattern = al.VALUE_PATTERNS.get(kind)
    if pattern is None:
        raise _Reject(f"internal error: unknown value kind {kind}")
    if not pattern.fullmatch(text):
        raise _Reject(f"value not allowed for {param}")
    return tok.raw

def _parse_args(spec: al.CommandSpec, tokens: List[_Token],
                cfg: ValidatorConfig, hosts_lower: FrozenSet[str]) -> List[str]:
    params_lower = {p.lower(): p for p in spec.params}
    seen = set()
    out: List[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.quoted or not t.text.startswith("-"):
            raise _Reject("positional arguments are not allowed")
        canonical = params_lower.get(t.text.lower())
        if canonical is None:
            raise _Reject(f"parameter not allowed for {spec.name}: {t.text}")
        if canonical in seen:
            raise _Reject(f"duplicate parameter: {canonical}")
        seen.add(canonical)
        kind = spec.params[canonical]
        if kind == al.SWITCH:
            out.append(canonical)
            i += 1
            continue
        if i + 1 >= len(tokens):
            raise _Reject(f"missing value for {canonical}")
        value = _check_value(kind, tokens[i + 1], cfg, hosts_lower, canonical)
        out.extend([canonical, value])
        i += 2
    for req in spec.required:
        if req not in seen:
            raise _Reject(f"missing required parameter: {req}")
    return out

def _validate(tool: str, command: object, target_host: object,
              cfg: ValidatorConfig) -> ValidationResult:
    if tool not in TOOL_CATEGORY:
        raise _Reject(f"unknown tool: {tool}")
    expected = TOOL_CATEGORY[tool]

    if not isinstance(command, str) or not command.strip():
        raise _Reject("empty command")
    if len(command) > MAX_COMMAND_LENGTH:
        raise _Reject("command too long")

    for ch, name in FORBIDDEN_CHARS.items():
        if ch in command:
            raise _Reject(f"forbidden character: {name}")
    for ch in command:
        o = ord(ch)
        if o < 32 or o == 127:
            raise _Reject("control character not allowed")
        if o > 126:
            raise _Reject("non-ASCII character not allowed")

    hosts_lower = frozenset(h.lower() for h in cfg.allowed_hosts)
    if not isinstance(target_host, str) or target_host.lower() not in hosts_lower:
        raise _Reject(f"target not in lab host list: {target_host}")

    if expected == al.CLIENT:
        collapsed = " ".join(command.split()).lower()
        for allowed in al.CLIENT_COMMANDS:
            if collapsed == allowed:
                return ValidationResult(True, None, allowed.split()[0],
                                        al.CLIENT, False, allowed)
        raise _Reject("not one of the fixed client commands")

    tokens = _tokenize(command)
    if not tokens:
        raise _Reject("empty command")
    head = tokens[0]
    if head.quoted:
        raise _Reject("command name must not be quoted")

    name_l = head.text.lower()
    for pat in al.DENY_NAME_PATTERNS:
        if re.fullmatch(pat, name_l):
            raise _Reject(f"explicitly forbidden command: {head.text}")

    spec = al.COMMANDS_BY_LOWER.get(name_l)
    if spec is None:
        raise _Reject(f"command not in allowlist: {head.text}")
    if spec.category != expected:
        raise _Reject(f"{spec.name} is a {spec.category} command")

    parts = _parse_args(spec, tokens[1:], cfg, hosts_lower)
    normalized = " ".join([spec.name] + parts)
    return ValidationResult(True, None, spec.name, spec.category,
                            spec.needs_approval, normalized)

def validate_command(tool: str, command: object, target_host: object,
                     cfg: ValidatorConfig) -> ValidationResult:
    try:
        return _validate(tool, command, target_host, cfg)
    except _Reject as e:
        return ValidationResult(False, str(e))
    except Exception as e:
        return ValidationResult(False, f"internal validator error: {type(e).__name__}")
