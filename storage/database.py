import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "wifiguard.db"


def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialise_database():
    with get_connection() as connection:
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


def save_report(device_name, wifi_name, risk_result, check_results):
    initialise_database()
    created_at = datetime.now(timezone.utc).isoformat()

    with get_connection() as connection:
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


def get_recent_reports(limit=5):
    initialise_database()

    with get_connection() as connection:
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
