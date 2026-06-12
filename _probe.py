import asyncio
from datasette.app import Datasette
from datasette.utils.actions_sql import build_allowed_resources_sql


async def main():
    db = "secretdb"
    config = {"databases": {db: {"allow": {"id": "user"}}}}
    actor = {"id": "user", "_r": {"r": {db: {"table2": ["vt"], "table3": ["vt"]}}}}
    ds = Datasette(config=config)
    await ds.invoke_startup()
    d = ds.add_memory_database(db)
    for t in ("table1", "table2", "table3", "table4"):
        await d.execute_write(f"create table {t} (id integer primary key)")
    await ds._refresh_schemas()

    sql, params = await build_allowed_resources_sql(ds, actor, "view-table", parent=db)
    print("########## SQL ##########")
    print(sql)
    print("########## PARAMS ##########")
    for k, v in params.items():
        print(f"  {k} = {v!r}")


asyncio.run(main())
