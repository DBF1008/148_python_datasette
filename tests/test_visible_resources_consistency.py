"""
Regression tests for visible resource enumeration consistency.

These tests verify that the three main entry points (Homepage, API Explorer,
Create Token) all produce consistent database and table lists for the same
actor, using the shared ``collect_visible_databases_and_tables()`` utility.
"""

import pytest
import pytest_asyncio
from datasette.app import Datasette
from datasette.permissions import PermissionSQL
from datasette import hookimpl
from datasette.utils.visible_resources import collect_visible_databases_and_tables


class PermissionRulesPlugin:
    """Test plugin that provides custom permission rules."""

    def __init__(self, rules_callback):
        self.rules_callback = rules_callback

    @hookimpl
    def permission_resources_sql(self, datasette, actor, action):
        return self.rules_callback(datasette, actor, action)


@pytest_asyncio.fixture
async def ds():
    """Fresh Datasette with two databases and several tables each."""
    ds = Datasette()
    await ds.invoke_startup()

    db1 = ds.add_memory_database("analytics")
    await db1.execute_write(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)"
    )
    await db1.execute_write(
        "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY)"
    )
    await db1.execute_write(
        "CREATE TABLE IF NOT EXISTS sensitive (id INTEGER PRIMARY KEY)"
    )

    db2 = ds.add_memory_database("production")
    await db2.execute_write(
        "CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY)"
    )
    await db2.execute_write(
        "CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY)"
    )

    await ds._refresh_schemas()
    return ds


# ── collect_visible_databases_and_tables() unit tests ─────────────────────


@pytest.mark.asyncio
async def test_collect_basic_global_allow(ds):
    """With a global allow rule, actor sees all databases and tables."""

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            return PermissionSQL.allow("global allow alice")
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        result = await collect_visible_databases_and_tables(ds, {"id": "alice"})
        db_names = set(result.keys())
        assert "analytics" in db_names
        assert "production" in db_names

        assert set(result["analytics"]["tables"].keys()) == {
            "users",
            "events",
            "sensitive",
        }
        assert set(result["production"]["tables"].keys()) == {"customers", "orders"}
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_collect_exclude_memory(ds):
    """exclude_memory=True removes the _memory database."""
    # _memory is always present in a Datasette instance
    assert "_memory" in ds.databases

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            return PermissionSQL.allow("global allow alice")
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        result = await collect_visible_databases_and_tables(
            ds, {"id": "alice"}, exclude_memory=True
        )
        assert "_memory" not in result
        assert "analytics" in result
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_collect_include_memory(ds):
    """exclude_memory=False keeps the _memory database (if visible)."""

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            return PermissionSQL.allow("global allow alice")
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        result = await collect_visible_databases_and_tables(
            ds, {"id": "alice"}, exclude_memory=False
        )
        # _memory should be present (it has no tables but the db itself is visible)
        assert "_memory" in result
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_collect_hidden_table_filtering(ds):
    """include_hidden_tables=False filters out hidden tables."""
    # Create an FTS virtual table which generates hidden shadow tables
    db = ds.databases["analytics"]
    await db.execute_write(
        "CREATE VIRTUAL TABLE IF NOT EXISTS users_fts USING fts5(name, content=users)"
    )
    await ds._refresh_schemas()

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            return PermissionSQL.allow("global allow alice")
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        # With hidden tables included
        result_with_hidden = await collect_visible_databases_and_tables(
            ds, {"id": "alice"}, include_hidden_tables=True
        )
        analytics_tables_with = set(result_with_hidden["analytics"]["tables"].keys())

        # With hidden tables excluded
        result_without_hidden = await collect_visible_databases_and_tables(
            ds, {"id": "alice"}, include_hidden_tables=False
        )
        analytics_tables_without = set(
            result_without_hidden["analytics"]["tables"].keys()
        )

        # The hidden-filtered set should be a subset
        assert analytics_tables_without.issubset(analytics_tables_with)
        # Core tables should always be present
        assert "users" in analytics_tables_without
        assert "events" in analytics_tables_without
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_collect_private_flags(ds):
    """include_is_private=True populates .private on resources.

    Default permissions allow anonymous access to view-* actions.
    We override with a plugin that denies anonymous access to production,
    making production 'private' for authenticated actors.
    """

    def rules(datasette, actor, action):
        if action in ("view-database", "view-table"):
            # Deny anonymous access to production
            if actor is None:
                return PermissionSQL(
                    sql="SELECT 'production' AS parent, NULL AS child, 0 AS allow, 'deny anon production' AS reason"
                )
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        result = await collect_visible_databases_and_tables(
            ds, {"id": "alice"}, include_is_private=True
        )

        # analytics is visible to both authenticated and anonymous → not private
        assert result["analytics"]["resource"].private is False

        # production: anonymous is denied → private for authenticated actor
        assert result["production"]["resource"].private is True
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_collect_no_permissions(ds):
    """With default_deny and no plugin rules, actor sees nothing."""
    deny_ds = Datasette(default_deny=True)
    await deny_ds.invoke_startup()
    db = deny_ds.add_memory_database("testdb")
    await db.execute_write("CREATE TABLE IF NOT EXISTS t1 (id INTEGER PRIMARY KEY)")
    await deny_ds._refresh_schemas()

    result = await collect_visible_databases_and_tables(deny_ds, {"id": "nobody"})
    assert len(result) == 0


@pytest.mark.asyncio
async def test_collect_database_level_restriction(ds):
    """With default_deny, actor granted access to one db only sees that db."""
    deny_ds = Datasette(default_deny=True)
    await deny_ds.invoke_startup()

    db1 = deny_ds.add_memory_database("analytics")
    await db1.execute_write(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY)"
    )
    await db1.execute_write(
        "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY)"
    )

    db2 = deny_ds.add_memory_database("production")
    await db2.execute_write(
        "CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY)"
    )
    await deny_ds._refresh_schemas()

    def rules(datasette, actor, action):
        if actor and actor.get("role") == "analyst":
            return PermissionSQL(
                sql="SELECT 'analytics' AS parent, NULL AS child, 1 AS allow, 'analyst access' AS reason"
            )
        return None

    plugin = PermissionRulesPlugin(rules)
    deny_ds.pm.register(plugin, name="test_plugin")
    try:
        result = await collect_visible_databases_and_tables(
            deny_ds, {"id": "bob", "role": "analyst"}
        )
        db_names = set(result.keys())
        assert "analytics" in db_names
        assert "production" not in db_names
        assert "_memory" not in db_names
    finally:
        deny_ds.pm.unregister(plugin, name="test_plugin")


# ── Cross-entry-point consistency tests ───────────────────────────────────


@pytest.mark.asyncio
async def test_consistency_homepage_vs_api_explorer(ds):
    """Homepage and API Explorer should agree on visible databases and tables."""

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            return PermissionSQL.allow("global allow alice")
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        # Homepage uses: include_is_private=True, exclude_memory=False, include_hidden_tables=True
        homepage_result = await collect_visible_databases_and_tables(
            ds,
            {"id": "alice"},
            include_is_private=True,
            exclude_memory=False,
            include_hidden_tables=True,
        )

        # API Explorer uses: include_is_private=False, exclude_memory=False, include_hidden_tables=False
        api_explorer_result = await collect_visible_databases_and_tables(
            ds,
            {"id": "alice"},
            include_is_private=False,
            exclude_memory=False,
            include_hidden_tables=False,
        )

        # The database sets should be identical (both don't exclude _memory)
        assert set(homepage_result.keys()) == set(api_explorer_result.keys())

        # API Explorer filters hidden tables, so its table sets should be subsets
        for db_name in homepage_result:
            homepage_tables = set(homepage_result[db_name]["tables"].keys())
            api_tables = set(api_explorer_result[db_name]["tables"].keys())
            assert api_tables.issubset(homepage_tables), (
                f"API Explorer shows tables not in Homepage for db '{db_name}': "
                f"{api_tables - homepage_tables}"
            )
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_consistency_homepage_vs_create_token(ds):
    """Homepage and Create Token should show consistent databases and tables."""

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            return PermissionSQL.allow("global allow alice")
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        # Homepage uses: include_is_private=True, exclude_memory=False, include_hidden_tables=True
        homepage_result = await collect_visible_databases_and_tables(
            ds,
            {"id": "alice"},
            include_is_private=True,
            exclude_memory=False,
            include_hidden_tables=True,
        )

        # Create Token uses: include_is_private=False, exclude_memory=True, include_hidden_tables=False
        token_result = await collect_visible_databases_and_tables(
            ds,
            {"id": "alice"},
            include_is_private=False,
            exclude_memory=True,
            include_hidden_tables=False,
        )

        # Create Token excludes _memory, so every db in token must be in homepage
        for db_name in token_result:
            assert db_name in homepage_result, (
                f"Create Token shows db '{db_name}' not in Homepage"
            )
            token_tables = set(token_result[db_name]["tables"].keys())
            homepage_tables = set(homepage_result[db_name]["tables"].keys())
            assert token_tables.issubset(homepage_tables), (
                f"Create Token shows tables not in Homepage for db '{db_name}': "
                f"{token_tables - homepage_tables}"
            )

        # _memory should be excluded from token result
        assert "_memory" not in token_result
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_consistency_all_three_entry_points(ds):
    """All three entry points should agree on non-memory, non-hidden tables."""

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            return PermissionSQL.allow("global allow alice")
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        # Baseline: strictest settings (Create Token)
        baseline = await collect_visible_databases_and_tables(
            ds,
            {"id": "alice"},
            include_is_private=False,
            exclude_memory=True,
            include_hidden_tables=False,
        )

        # Homepage (most permissive)
        homepage = await collect_visible_databases_and_tables(
            ds,
            {"id": "alice"},
            include_is_private=True,
            exclude_memory=False,
            include_hidden_tables=True,
        )

        # API Explorer (middle ground)
        api_explorer = await collect_visible_databases_and_tables(
            ds,
            {"id": "alice"},
            include_is_private=False,
            exclude_memory=False,
            include_hidden_tables=False,
        )

        for db_name in baseline:
            baseline_tables = set(baseline[db_name]["tables"].keys())

            # Homepage should include all baseline tables
            assert db_name in homepage
            homepage_tables = set(homepage[db_name]["tables"].keys())
            assert baseline_tables.issubset(homepage_tables)

            # API Explorer should include all baseline tables
            assert db_name in api_explorer
            api_tables = set(api_explorer[db_name]["tables"].keys())
            assert baseline_tables.issubset(api_tables)
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_consistency_with_database_level_deny():
    """With default_deny and database-level allow, all entry points consistently filter."""
    ds = Datasette(default_deny=True)
    await ds.invoke_startup()

    db1 = ds.add_memory_database("analytics")
    await db1.execute_write("CREATE TABLE IF NOT EXISTS t1 (id INTEGER PRIMARY KEY)")

    db2 = ds.add_memory_database("production")
    await db2.execute_write("CREATE TABLE IF NOT EXISTS t2 (id INTEGER PRIMARY KEY)")
    await ds._refresh_schemas()

    def rules(datasette, actor, action):
        if actor and actor.get("id") == "alice":
            if action in ("view-database", "view-table"):
                # Allow only analytics
                return PermissionSQL(
                    sql="SELECT 'analytics' AS parent, NULL AS child, 1 AS allow, 'analytics only' AS reason"
                )
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        for kwargs in [
            {"include_is_private": True, "exclude_memory": False, "include_hidden_tables": True},
            {"include_is_private": False, "exclude_memory": False, "include_hidden_tables": False},
            {"include_is_private": False, "exclude_memory": True, "include_hidden_tables": False},
        ]:
            result = await collect_visible_databases_and_tables(
                ds, {"id": "alice"}, **kwargs
            )
            assert "production" not in result, (
                f"production should be denied with kwargs={kwargs}"
            )
            assert "analytics" in result
    finally:
        ds.pm.unregister(plugin, name="test_plugin")


@pytest.mark.asyncio
async def test_consistency_anonymous_actor():
    """Anonymous actor (None) with default_deny sees only what's explicitly allowed."""
    ds = Datasette(default_deny=True)
    await ds.invoke_startup()

    db1 = ds.add_memory_database("analytics")
    await db1.execute_write("CREATE TABLE IF NOT EXISTS t1 (id INTEGER PRIMARY KEY)")

    db2 = ds.add_memory_database("production")
    await db2.execute_write("CREATE TABLE IF NOT EXISTS t2 (id INTEGER PRIMARY KEY)")
    await ds._refresh_schemas()

    def rules(datasette, actor, action):
        # Allow anonymous to see only analytics
        if actor is None and action in ("view-database", "view-table"):
            return PermissionSQL(
                sql="SELECT 'analytics' AS parent, NULL AS child, 1 AS allow, 'anon analytics' AS reason"
            )
        return None

    plugin = PermissionRulesPlugin(rules)
    ds.pm.register(plugin, name="test_plugin")
    try:
        result = await collect_visible_databases_and_tables(
            ds, None, exclude_memory=True, include_hidden_tables=False
        )
        assert set(result.keys()) == {"analytics"}
        assert "production" not in result
        assert "_memory" not in result
    finally:
        ds.pm.unregister(plugin, name="test_plugin")
