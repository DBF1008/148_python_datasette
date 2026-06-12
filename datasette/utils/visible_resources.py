"""
Shared utility for collecting visible databases and tables for an actor.

All three main entry points (IndexView, ApiExplorerView, CreateTokenView) use this
module to ensure they present a consistent view of which databases and tables an
actor can see.  The single source of truth is ``Datasette.allowed_resources()``
which uses the efficient CTE-based bulk SQL path.
"""

from typing import Any


async def collect_visible_databases_and_tables(
    datasette: Any,
    actor: dict | None,
    *,
    include_is_private: bool = False,
    exclude_memory: bool = False,
    include_hidden_tables: bool = True,
    include_views: bool = True,
) -> dict[str, dict]:
    """Collect all databases and tables visible to *actor* in a single pass.

    Returns a dict keyed by database name::

        {
            "mydb": {
                "resource": <DatabaseResource>,   # with .private if requested
                "tables": {
                    "mytable": <TableResource>,   # with .private if requested
                    ...
                },
            },
            ...
        }

    Parameters
    ----------
    datasette:
        The Datasette application instance.
    actor:
        The actor dict (or ``None`` for anonymous).
    include_is_private:
        When ``True`` each returned Resource carries a ``.private`` attribute
        indicating whether anonymous users cannot see it.
    exclude_memory:
        When ``True`` the ``_memory`` database is excluded from results.
    include_hidden_tables:
        When ``False`` tables reported by ``db.hidden_table_names()`` (FTS
        shadow tables, config-hidden tables, SpatiaLite internals, …) are
        removed from the ``tables`` mapping.
    include_views:
        When ``False`` views reported by ``db.view_names()`` are removed
        from the ``tables`` mapping.
    """

    # ── 1. Fetch visible databases ────────────────────────────────────────
    db_page = await datasette.allowed_resources(
        "view-database", actor, include_is_private=include_is_private
    )
    allowed_databases = [r async for r in db_page.all()]

    # ── 2. Fetch visible tables ─────────────────────────────────────────
    table_page = await datasette.allowed_resources(
        "view-table", actor, include_is_private=include_is_private
    )

    tables_by_db: dict[str, dict] = {}
    async for t in table_page.all():
        tables_by_db.setdefault(t.parent, {})[t.child] = t

    # ── 3. Assemble result ──────────────────────────────────────────────
    result: dict[str, dict] = {}
    for db_resource in allowed_databases:
        db_name = db_resource.parent

        if exclude_memory and db_name == "_memory":
            continue

        tables = tables_by_db.get(db_name, {})

        # Optionally filter out hidden tables and/or views
        if tables and (not include_hidden_tables or not include_views):
            db = datasette.databases.get(db_name)
            if db is not None:
                exclude_names: set = set()
                if not include_hidden_tables:
                    exclude_names.update(await db.hidden_table_names())
                if not include_views:
                    exclude_names.update(await db.view_names())
                if exclude_names:
                    tables = {
                        name: res
                        for name, res in tables.items()
                        if name not in exclude_names
                    }

        result[db_name] = {
            "resource": db_resource,
            "tables": tables,
        }

    return result
