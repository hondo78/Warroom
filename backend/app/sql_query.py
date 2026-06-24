"""Read-only SQL access for the analyst chat.

The free-form chat LLM may answer questions with live data. Letting a model
touch the database is only safe behind hard guardrails, so every query goes
through :func:`run_select`:

  * SELECT / WITH only — a single statement, validated before execution;
  * run inside a ``READ ONLY`` transaction with a ``statement_timeout`` so a
    runaway scan (e.g. the 40GB ``firewall_logs`` table) can't hang the chat;
  * wrapped in an outer ``LIMIT`` so result size is bounded in memory;
  * the ``app_settings`` table (API keys / secrets) is denied outright.

The schema the LLM is shown is generated from the ORM metadata, so it never
drifts from the actual tables.
"""

import json
import logging
import re
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import text

from app.database import async_session
from app.models import Base

logger = logging.getLogger(__name__)

MAX_ROWS = 200
STATEMENT_TIMEOUT_MS = 8000
_CELL_MAX = 300

# Tables the chat must never read (secrets live here).
DENIED_TABLES = {"app_settings"}

# Defence-in-depth on top of the READ ONLY transaction: reject write/DDL verbs
# and server-side functions that touch the filesystem or block.
# NB: deliberately excludes verbs that collide with column names in this schema
# (e.g. "comment"); the READ ONLY transaction blocks DDL/DML regardless, so this
# list only needs to catch file/sleep functions and bulk COPY.
_FORBIDDEN_RE = re.compile(
    r"\b(insert|update|delete|drop|alter|truncate|create|grant|revoke|"
    r"copy|merge|call|vacuum|reindex|cluster|"
    r"pg_sleep|pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export|"
    r"dblink|set_config|pg_terminate_backend)\b",
    re.I,
)
_DENIED_TABLE_RE = re.compile(r"\b(" + "|".join(DENIED_TABLES) + r")\b", re.I)
_COMMENT_RE = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)


class SqlError(Exception):
    """Raised for a query that fails validation (shown back to the LLM)."""


def _validate(sql: str) -> str:
    """Return the cleaned single SELECT statement or raise SqlError."""
    # Strip comments first so they can't hide a ';' or a forbidden keyword.
    stripped = _COMMENT_RE.sub(" ", sql or "")
    s = stripped.strip().rstrip(";").strip()
    if not s:
        raise SqlError("leere Abfrage")
    if ";" in s:
        raise SqlError("nur eine einzelne Anweisung erlaubt")
    low = s.lower()
    if not (low.startswith("select") or low.startswith("with")):
        raise SqlError("nur SELECT- oder WITH-Abfragen erlaubt")
    if _FORBIDDEN_RE.search(s):
        raise SqlError("unzulaessiges Schluesselwort in der Abfrage")
    if _DENIED_TABLE_RE.search(s):
        raise SqlError("Zugriff auf diese Tabelle ist gesperrt")
    return s


def _cell(v: Any) -> Any:
    if v is None or isinstance(v, bool) or isinstance(v, int) or isinstance(v, float):
        return v
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    if isinstance(v, Decimal):
        return float(v)
    if isinstance(v, (dict, list)):
        s = json.dumps(v, ensure_ascii=False, default=str)
    else:
        s = str(v)
    return s[:_CELL_MAX] + "…" if len(s) > _CELL_MAX else s


async def run_select(sql: str) -> dict[str, Any]:
    """Execute a validated read-only SELECT and return columns + rows."""
    clean = _validate(sql)
    # Outer LIMIT bounds both server work and memory regardless of the inner
    # query (WITH/UNION/ORDER BY all survive being wrapped as a subquery).
    wrapped = f"SELECT * FROM (\n{clean}\n) AS _warroom_sub LIMIT {MAX_ROWS + 1}"
    async with async_session() as db:
        async with db.begin():
            await db.execute(text("SET TRANSACTION READ ONLY"))
            await db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))
            result = await db.execute(text(wrapped))
            cols = list(result.keys())
            raw = result.fetchall()
    truncated = len(raw) > MAX_ROWS
    rows = [[_cell(c) for c in row] for row in raw[:MAX_ROWS]]
    return {"columns": cols, "rows": rows, "row_count": len(rows), "truncated": truncated}


def _simple_type(col) -> str:
    tn = col.type.__class__.__name__.lower()
    if "json" in tn:
        return "json"
    if "datetime" in tn or "timestamp" in tn:
        return "ts"
    if "bool" in tn:
        return "bool"
    if "int" in tn:
        return "int"
    if "float" in tn or "numeric" in tn or "real" in tn:
        return "float"
    return "text"


_SCHEMA_CACHE: str | None = None


def _schema_text() -> str:
    global _SCHEMA_CACHE
    if _SCHEMA_CACHE is None:
        lines = []
        for tbl in Base.metadata.sorted_tables:
            if tbl.name in DENIED_TABLES:
                continue
            cols = ", ".join(f"{c.name}:{_simple_type(c)}" for c in tbl.columns)
            lines.append(f"{tbl.name}({cols})")
        _SCHEMA_CACHE = "\n".join(lines)
    return _SCHEMA_CACHE


def prompt_section() -> str:
    """The DB-access block appended to the analyst system prompt."""
    return (
        "DATENBANK-LESEZUGRIFF\n"
        "Du kannst die Warroom-PostgreSQL schreibgeschuetzt abfragen, um Fragen mit "
        "echten Daten zu beantworten. Wenn du dafuer Daten brauchst, antworte "
        "AUSSCHLIESSLICH mit einem JSON-Objekt (kein weiterer Text):\n"
        '{"sql": "SELECT ... LIMIT 50"}\n'
        f"Regeln: nur ein einzelnes SELECT/WITH, immer mit LIMIT (max {MAX_ROWS}), keine "
        "Schreib-/DDL-Befehle. Zeitstempel (created_at, *_at) sind UTC — nutze z.B. "
        "\"created_at >= now() - interval '24 hours'\". Grosse JSON-Spalten (raw_data, raw) "
        "moeglichst meiden. Das System fuehrt die Abfrage aus und liefert dir die Zeilen als "
        "JSON zurueck; danach antwortest du dem Nutzer auf Deutsch und haengst KEIN JSON mehr "
        "an. Brauchst du keine DB-Daten, antworte direkt normal.\n\n"
        "TABELLEN (spalte:typ — ts=Zeitstempel, json=JSONB):\n" + _schema_text()
    )
