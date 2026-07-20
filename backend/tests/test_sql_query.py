"""The chat's read-only SQL sandbox (app.sql_query._validate) is the guard that
keeps the LLM from doing anything but a single bounded SELECT. These lock that
behaviour down."""
import pytest

from app.sql_query import SqlError, _validate, DENIED_TABLES


def test_accepts_plain_select():
    assert _validate("SELECT 1").lower().startswith("select")


def test_accepts_with_cte():
    assert _validate("WITH x AS (SELECT 1) SELECT * FROM x").lower().startswith("with")


@pytest.mark.parametrize("sql", [
    "INSERT INTO firewall_logs VALUES (1)",
    "UPDATE firewall_logs SET action='x'",
    "DELETE FROM firewall_logs",
    "DROP TABLE firewall_logs",
    "TRUNCATE firewall_logs",
    "ALTER TABLE firewall_logs ADD COLUMN x int",
    "GRANT ALL ON firewall_logs TO public",
])
def test_rejects_non_select(sql):
    with pytest.raises(SqlError):
        _validate(sql)


def test_rejects_multiple_statements():
    with pytest.raises(SqlError):
        _validate("SELECT 1; SELECT 2")


def test_rejects_empty():
    with pytest.raises(SqlError):
        _validate("   ")


def test_denies_secret_table():
    assert "app_settings" in DENIED_TABLES
    with pytest.raises(SqlError):
        _validate("SELECT value FROM app_settings")


def test_comment_cannot_smuggle_forbidden_keyword():
    # comments are stripped before the single-statement / keyword checks
    with pytest.raises(SqlError):
        _validate("SELECT 1 -- ok\n; DROP TABLE firewall_logs")
