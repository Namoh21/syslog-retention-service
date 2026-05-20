"""
KQL (Kibana Query Language) subset parser for syslog log filtering.

Supported syntax:
    field:value             text: case-insensitive contains; ip/action: exact
    field:"exact phrase"    exact case-insensitive match for text fields
    field:*text*            wildcard contains; field:text* starts with; field:*text ends with
    field:*                 field exists (not NULL)
    field:>=N               numeric/severity comparisons (>=, <=, >, <, !=, =)
    severity:error          named severity levels (emergency/alert/critical/error/warning/notice/info/debug)
    bare_word               search in message field (contains)
    "bare phrase"           search in message field (contains phrase)
    termA AND termB         both must match (AND is also implicit between adjacent terms)
    termA OR termB          either must match
    NOT term                must not match
    (expr)                  grouping for complex logic
"""
from __future__ import annotations
from sqlalchemy import and_, or_, not_
from sqlalchemy.orm import Query as SAQuery

_ESCAPE_TRANS = str.maketrans({"\\": "\\\\", "%": "\\%", "_": "\\_"})


def _esc(v: str) -> str:
    return v.translate(_ESCAPE_TRANS)


_SEV = {
    "emergency": 0, "emerg": 0,
    "alert": 1,
    "critical": 2, "crit": 2,
    "error": 3, "err": 3,
    "warning": 4, "warn": 4,
    "notice": 5,
    "informational": 6, "info": 6,
    "debug": 7,
}


def _fmap():
    """Lazy import — avoids circular dependency with database.py."""
    from database import SyslogEntry as E
    return {
        "source_ip":   (E.source_ip,   "ip"),
        "src_ip":      (E.src_ip,      "ip"),
        "dst_ip":      (E.dst_ip,      "ip"),
        "hostname":    (E.hostname,    "text"),
        "host":        (E.hostname,    "text"),
        "message":     (E.message,     "text"),
        "msg":         (E.message,     "text"),
        "severity":    (E.severity,    "severity"),
        "sev":         (E.severity,    "severity"),
        "facility":    (E.facility,    "int"),
        "action":      (E.action,      "exact"),
        "protocol":    (E.protocol,    "itext"),
        "proto":       (E.protocol,    "itext"),
        "dst_port":    (E.dst_port,    "int"),
        "port":        (E.dst_port,    "int"),
        "event_type":  (E.event_type,  "exact"),
        "type":        (E.event_type,  "exact"),
        "app":         (E.app_name,    "text"),
        "app_name":    (E.app_name,    "text"),
        "received_at": (E.received_at, "datetime"),
        "timestamp":   (E.received_at, "datetime"),
        "ts":          (E.received_at, "datetime"),
    }


# ── Tokenizer ─────────────────────────────────────────────────────────────────

class _T:
    __slots__ = ("k", "v")
    def __init__(self, k: str, v: str = ""):
        self.k = k
        self.v = v


def _lex(src: str) -> list[_T]:
    out: list[_T] = []
    i, n = 0, len(src)
    while i < n:
        while i < n and src[i].isspace():
            i += 1
        if i >= n:
            break
        c = src[i]
        if c == "(":
            out.append(_T("LP")); i += 1
        elif c == ")":
            out.append(_T("RP")); i += 1
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"':
                j += 1
            out.append(_T("QS", src[i + 1:j]))   # bare quoted string
            i = j + 1
        else:
            j = i
            while j < n and not src[j].isspace() and src[j] not in '()"':
                j += 1
            tok = src[i:j]
            up = tok.upper()
            if up == "AND":
                out.append(_T("AND"))
            elif up == "OR":
                out.append(_T("OR"))
            elif up == "NOT":
                out.append(_T("NOT"))
            elif ":" in tok:
                ci = tok.index(":")
                field = tok[:ci]
                val   = tok[ci + 1:]
                if not val and j < n and src[j] == '"':
                    # field:"quoted value"
                    k = j + 1
                    while k < n and src[k] != '"':
                        k += 1
                    out.append(_T("FQ", f"{field}\x00{src[j + 1:k]}"))
                    i = k + 1
                    continue
                out.append(_T("FV", f"{field}\x00{val}"))
            else:
                out.append(_T("W", tok))
            i = j
    out.append(_T("EOF"))
    return out


# ── Recursive-descent parser ──────────────────────────────────────────────────

class _P:
    def __init__(self, toks: list[_T]):
        self.t = toks
        self.i = 0

    def cur(self) -> _T:
        return self.t[self.i]

    def eat(self) -> _T:
        t = self.t[self.i]
        self.i += 1
        return t

    def parse(self):
        if self.cur().k == "EOF":
            return None
        return self._or()

    def _or(self):
        left = self._and()
        while self.cur().k == "OR":
            self.eat()
            right = self._and()
            left = _join_or(left, right)
        return left

    def _and(self):
        left = self._not()
        while self.cur().k not in ("OR", "RP", "EOF"):
            if self.cur().k == "AND":
                self.eat()
            right = self._not()
            left = _join_and(left, right)
        return left

    def _not(self):
        if self.cur().k == "NOT":
            self.eat()
            inner = self._not()
            return not_(inner) if inner is not None else None
        return self._atom()

    def _atom(self):
        cur = self.cur()
        if cur.k == "LP":
            self.eat()
            inner = self._or()
            if self.cur().k == "RP":
                self.eat()
            return inner
        if cur.k == "FV":
            self.eat()
            field, val = cur.v.split("\x00", 1)
            return _build(field, val, quoted=False)
        if cur.k == "FQ":
            self.eat()
            field, val = cur.v.split("\x00", 1)
            return _build(field, val, quoted=True)
        if cur.k in ("QS", "W"):
            self.eat()
            return _msg_like(f"%{_esc(cur.v)}%")
        return None


def _join_or(a, b):
    if a is None: return b
    if b is None: return a
    return or_(a, b)


def _join_and(a, b):
    if a is None: return b
    if b is None: return a
    return and_(a, b)


def _msg_like(pat: str):
    from database import SyslogEntry
    return SyslogEntry.message.ilike(pat, escape="\\")


def _wildcard(val: str) -> str:
    """Convert *-wildcards to SQL LIKE % pattern."""
    return _esc(val.replace("*", "\x01")).replace("\x01", "%")


def _build(field: str, val: str, quoted: bool):
    fmap = _fmap()
    entry = fmap.get(field.lower())

    if entry is None:
        # Unknown field — treat as message search
        return _msg_like(f"%{_esc(val)}%")

    col, ftype = entry

    if val == "*":
        return col.isnot(None)

    if ftype == "text":
        if quoted:
            return col.ilike(_esc(val), escape="\\")
        if "*" in val:
            return col.ilike(_wildcard(val), escape="\\")
        return col.ilike(f"%{_esc(val)}%", escape="\\")

    if ftype == "itext":
        if quoted:
            return col.ilike(_esc(val), escape="\\")
        return col.ilike(val, escape="\\")

    if ftype == "ip":
        if "*" in val:
            return col.ilike(_wildcard(val), escape="\\")
        return col == val

    if ftype == "exact":
        return col.ilike(val, escape="\\")

    if ftype == "datetime":
        from datetime import datetime, timezone
        op, dt_s = _split_op(val)
        try:
            dt = datetime.fromisoformat(dt_s.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return _dtcmp(col, op, dt)
        except ValueError:
            return None

    if ftype in ("int", "severity"):
        if ftype == "severity":
            stripped = val.lstrip("<>=! ")
            if stripped.lower() in _SEV:
                op_pfx = val[: len(val) - len(stripped)] or "="
                return _numcmp(col, op_pfx.strip(), _SEV[stripped.lower()])
        op, num_s = _split_op(val)
        try:
            return _numcmp(col, op, int(num_s))
        except ValueError:
            return None

    return None


def _split_op(val: str) -> tuple[str, str]:
    for op in (">=", "<=", "!=", ">", "<"):
        if val.startswith(op):
            return op, val[len(op):]
    return "=", val


def _dtcmp(col, op: str, dt):
    return {
        "=":  col == dt, "!=": col != dt,
        "<":  col <  dt, "<=": col <= dt,
        ">":  col >  dt, ">=": col >= dt,
    }.get(op, col == dt)


def _numcmp(col, op: str, num: int):
    return {
        "=":  col == num, "!=": col != num,
        "<":  col <  num, "<=": col <= num,
        ">":  col >  num, ">=": col >= num,
    }.get(op, col == num)


# ── Public API ────────────────────────────────────────────────────────────────

def apply_kql(query: SAQuery, kql_str: str) -> SAQuery:
    """
    Apply a KQL filter string to a SQLAlchemy query over SyslogEntry rows.
    Returns the modified query. On any parse error, falls back to a plain
    message LIKE search so bad syntax never returns zero results silently.
    """
    if not kql_str or not kql_str.strip():
        return query
    try:
        toks = _lex(kql_str.strip())
        cond = _P(toks).parse()
        if cond is not None:
            query = query.filter(cond)
    except Exception:
        from database import SyslogEntry
        query = query.filter(
            SyslogEntry.message.ilike(f"%{_esc(kql_str[:400])}%", escape="\\")
        )
    return query
