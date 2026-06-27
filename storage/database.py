import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "wifiguard.db"
MAX_SAVED_REPORTS = 50


def get_database_path(database_path=None):
    if database_path is None:
        return DATABASE_PATH

    return Path(database_path)


def get_connection(database_path=None):
    database_path = get_database_path(database_path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialise_database(database_path=None):
    with get_connection(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                device_name TEXT,
                wifi_name TEXT,
                risk_level TEXT,
                risk_score INTEGER,
                summary TEXT
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS check_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                check_name TEXT NOT NULL,
                status TEXT,
                message TEXT,
                raw_value TEXT,
                FOREIGN KEY(report_id) REFERENCES reports(id)
            )
            """
        )


def prepare_raw_value(raw_value):
    if raw_value is None:
        return None

    if isinstance(raw_value, str):
        return raw_value

    return json.dumps(raw_value, default=str)


def parse_raw_value(raw_value):
    if raw_value is None:
        return None

    try:
        return json.loads(raw_value)
    except (TypeError, ValueError):
        return raw_value


def save_report(
    device_name,
    wifi_name,
    risk_result,
    check_results,
    database_path=None
):
    initialise_database(database_path)
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection(database_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO reports (
                created_at,
                device_name,
                wifi_name,
                risk_level,
                risk_score,
                summary
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                device_name,
                wifi_name,
                risk_result.get("level"),
                risk_result.get("score"),
                risk_result.get("summary"),
            ),
        )

        report_id = cursor.lastrowid

        for check_result in check_results:
            connection.execute(
                """
                INSERT INTO check_results (
                    report_id,
                    check_name,
                    status,
                    message,
                    raw_value
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    check_result.get("check_name"),
                    check_result.get("status"),
                    check_result.get("message"),
                    prepare_raw_value(check_result.get("raw_value")),
                ),
            )

    return report_id


def prune_old_reports(max_reports=MAX_SAVED_REPORTS, database_path=None):
    initialise_database(database_path)

    # The connection context manager keeps these deletes in one transaction.
    with get_connection(database_path) as connection:
        old_report_rows = connection.execute(
            """
            SELECT id
            FROM reports
            ORDER BY created_at DESC, id DESC
            LIMIT -1 OFFSET ?
            """,
            (max_reports,),
        ).fetchall()

        old_report_ids = [row[0] for row in old_report_rows]

        if not old_report_ids:
            return 0

        placeholders = ",".join("?" for _ in old_report_ids)

        # Delete dependent check results first so no orphaned check rows remain.
        connection.execute(
            f"DELETE FROM check_results WHERE report_id IN ({placeholders})",
            old_report_ids,
        )
        connection.execute(
            f"DELETE FROM reports WHERE id IN ({placeholders})",
            old_report_ids,
        )

    return len(old_report_ids)


def clear_all_reports(database_path=None):
    initialise_database(database_path)

    # The connection context manager keeps these deletes in one transaction.
    with get_connection(database_path) as connection:
        deleted_report_count = connection.execute(
            "SELECT COUNT(*) FROM reports"
        ).fetchone()[0]

        # Delete dependent check results before reports to satisfy foreign keys.
        connection.execute("DELETE FROM check_results")
        connection.execute("DELETE FROM reports")

    return deleted_report_count


def get_recent_reports(limit=5, database_path=None):
    initialise_database(database_path)

    with get_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT
                id,
                created_at,
                device_name,
                wifi_name,
                risk_level,
                risk_score,
                summary
            FROM reports
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_report_by_id(report_id, database_path=None):
    initialise_database(database_path)

    with get_connection(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            """
            SELECT
                id,
                created_at,
                device_name,
                wifi_name,
                risk_level,
                risk_score,
                summary
            FROM reports
            WHERE id = ?
            """,
            (report_id,),
        ).fetchone()

        if row is None:
            return None

        check_result_rows = connection.execute(
            """
            SELECT
                check_name,
                status,
                message,
                raw_value
            FROM check_results
            WHERE report_id = ?
            ORDER BY id ASC
            """,
            (report_id,),
        ).fetchall()

    report = dict(row)
    report["check_results"] = []

    for check_result_row in check_result_rows:
        check_result = dict(check_result_row)
        check_result["raw_value"] = parse_raw_value(check_result.get("raw_value"))
        report["check_results"].append(check_result)

    return report
