"""The chat's read-only SQL sandbox (app.sql_query._validate) is the guard that
keeps the LLM from doing anything but a single bounded SELECT. These lock that
behaviour down."""
import pytest

from app import sql_query as sq
from app.sql_query import SqlError, _validate


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
    assert "app_settings" not in sq.ALLOWED_TABLES
    with pytest.raises(SqlError):
        _validate("SELECT value FROM app_settings")


def test_comment_cannot_smuggle_forbidden_keyword():
    # comments are stripped before the single-statement / keyword checks
    with pytest.raises(SqlError):
        _validate("SELECT 1 -- ok\n; DROP TABLE firewall_logs")


# --- the allow-list ----------------------------------------------------------

def test_the_tables_holding_credentials_are_unreachable():
    """A deny-list of one table left the chat able to read attacker passwords,
    password hashes and the canary fingerprints — the last of which the API
    withholds precisely because it enables offline guessing."""
    import pytest
    for tbl in ("users", "honeypot_logins", "monitored_passwords",
                "app_settings", "kali_commands", "audit_log", "chat_messages"):
        with pytest.raises(sq.SqlError) as e:
            sq._validate(f"SELECT * FROM {tbl} LIMIT 5")
        assert tbl in str(e.value)


def test_an_ordinary_analyst_query_still_runs():
    sq._validate("SELECT source_ip, count(*) FROM firewall_logs "
                 "WHERE created_at > now() - interval '1 day' "
                 "GROUP BY 1 ORDER BY 2 DESC LIMIT 20")


def test_a_join_across_allowed_tables_is_fine():
    sq._validate("SELECT b.ip, o.abuse_score FROM blocked_ips b "
                 "JOIN osint_results o ON o.value = b.ip LIMIT 10")


def test_a_join_that_smuggles_in_a_denied_table_is_refused():
    """The FROM clause being allowed says nothing about the JOIN."""
    import pytest
    with pytest.raises(sq.SqlError):
        sq._validate("SELECT * FROM blocked_ips b JOIN users u ON u.id = b.id LIMIT 5")


def test_a_denied_table_inside_a_subquery_is_refused():
    import pytest
    with pytest.raises(sq.SqlError):
        sq._validate("SELECT * FROM (SELECT password_hash FROM users) x LIMIT 5")


def test_a_cte_name_is_not_mistaken_for_a_table():
    """WITH introduces names that are not tables. Checking them against the
    allow-list would reject perfectly good queries."""
    sq._validate("WITH recent AS (SELECT * FROM firewall_logs LIMIT 100) "
                 "SELECT count(*) FROM recent")


def test_several_ctes_are_all_recognised():
    sq._validate("WITH a AS (SELECT 1 AS x), b AS (SELECT 2 AS y) "
                 "SELECT * FROM a JOIN b ON a.x = b.y")


def test_a_cte_cannot_be_used_to_launder_a_denied_table():
    """Naming a CTE after an allowed table must not make its body unchecked."""
    import pytest
    with pytest.raises(sq.SqlError):
        sq._validate("WITH firewall_logs AS (SELECT * FROM users) "
                     "SELECT * FROM firewall_logs LIMIT 5")


def test_the_system_catalogs_are_not_reachable():
    """Schema enumeration is not the analyst chat's job, and pg_catalog is a
    reconnaissance surface."""
    import pytest
    for q in ("SELECT * FROM pg_catalog.pg_tables LIMIT 5",
              "SELECT * FROM information_schema.columns LIMIT 5",
              "SELECT * FROM pg_tables LIMIT 5"):
        with pytest.raises(sq.SqlError):
            sq._validate(q)


def test_a_set_returning_function_is_not_treated_as_a_table():
    """generate_series is a function, not a table; rejecting it would break
    legitimate time-bucketing queries."""
    sq._validate("SELECT g FROM generate_series(1, 10) AS g")


def test_a_new_table_is_denied_until_someone_allows_it():
    """The point of inverting the list: a table added later is unreadable by
    default rather than readable by oversight."""
    import pytest
    with pytest.raises(sq.SqlError):
        sq._validate("SELECT * FROM some_table_added_next_year LIMIT 1")


def test_the_model_is_only_shown_the_tables_it_may_read():
    """The schema in the prompt is the model's map. Listing a table it cannot
    query wastes turns; listing a secret-bearing one advertises it."""
    schema = sq._schema_text()
    for tbl in ("users", "app_settings", "honeypot_logins", "monitored_passwords"):
        assert tbl not in schema
    assert "firewall_logs" in schema
