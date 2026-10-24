#!/usr/bin/env python3
"""Ad-hoc SQL over the event log with DuckDB -- no server, no hot-path coupling.

This is the lighter-than-Postgres analytics path: DuckDB reads the JSONL (and
gzip-rotated *.jsonl.gz) files in place and gives you full SQL, so "research on
the concerned sessions" is a query, not a scan script. It is an analyst-side
tool; DuckDB is NOT a dependency of the sensor and is never in the write path.

    pip install duckdb        # one-time, on the analyst box
    python3 scripts/query_log.py data/events          # overview
    python3 scripts/query_log.py data/events --sql "SELECT face, count(*) FROM events GROUP BY 1"
    python3 scripts/query_log.py data/events --sql "..." --format json

A view named `events` is registered over every log file. Fields that only some
event kinds carry (indicators, web_attack, standard, family, ...) are unioned
by name, so a column is just NULL where an event kind did not set it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_OVERVIEW = [
    ("events by kind", "SELECT kind, count(*) AS n FROM events GROUP BY 1 ORDER BY n DESC"),
    ("requests by face", "SELECT face, count(*) AS n FROM events WHERE kind='request' GROUP BY 1 ORDER BY n DESC"),
    ("hunt families seen", "SELECT family, count(*) AS n FROM events WHERE kind='hunt' GROUP BY 1 ORDER BY n DESC"),
    ("web-app attack tags", "SELECT web_attack, count(*) AS n FROM events WHERE web_attack IS NOT NULL GROUP BY 1 ORDER BY n DESC"),
    ("busiest actors",
     "SELECT actor, actor_basis, count(*) AS events, count(DISTINCT ip) AS ips "
     "FROM events WHERE actor IS NOT NULL GROUP BY 1,2 ORDER BY events DESC LIMIT 10"),
]


def _relation_sql(log_dir: Path) -> str:
    # One glob covers *.jsonl and *.jsonl.gz (DuckDB reads gzip by extension).
    pattern = str(log_dir / "*.jsonl*").replace("'", "''")
    return (
        f"read_json_auto('{pattern}', format='newline_delimited', "
        "union_by_name=true, ignore_errors=true)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage-crawl-query-log")
    parser.add_argument("log_dir", nargs="?", default="data/events")
    parser.add_argument("--sql", help="SQL to run against the `events` view")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    args = parser.parse_args(argv)

    try:
        import duckdb
    except ImportError:
        print("duckdb is not installed. Run:  pip install duckdb", file=sys.stderr)
        return 2

    log_dir = Path(args.log_dir)
    if not any(log_dir.glob("*.jsonl*")):
        print(f"no log files in {log_dir}", file=sys.stderr)
        return 1

    con = duckdb.connect()
    con.execute(f"CREATE VIEW events AS SELECT * FROM {_relation_sql(log_dir)}")

    def run(sql: str) -> None:
        rel = con.sql(sql)
        if args.format == "json":
            import json
            cols = rel.columns
            print(json.dumps([dict(zip(cols, row)) for row in rel.fetchall()],
                             indent=2, default=str))
        else:
            rel.show(max_rows=100)

    if args.sql:
        run(args.sql)
    else:
        total = con.sql("SELECT count(*) FROM events").fetchone()[0]
        print(f"events view: {total} rows from {log_dir}\n")
        for title, sql in _OVERVIEW:
            print(f"-- {title}")
            try:
                run(sql)
            except Exception as exc:  # a column may be absent in a young log
                print(f"   (skipped: {exc})")
            print()
        print("Pass --sql \"SELECT ... FROM events ...\" for your own query.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
