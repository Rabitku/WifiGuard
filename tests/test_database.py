from storage import database


def sample_risk_result(level="Medium risk", score=25, summary="Sample summary."):
    return {
        "level": level,
        "score": score,
        "summary": summary,
        "findings": ["Sample finding."],
        "recommendations": ["Sample recommendation."]
    }


def sample_check_results():
    return [
        {
            "check_name": "macOS firewall",
            "status": "Enabled",
            "message": "Your firewall is active.",
            "raw_value": {
                "Status": "Enabled",
                "message": "Your firewall is active."
            }
        },
        {
            "check_name": "VPN / tunnel routing",
            "status": "Not detected",
            "message": "VPN routing was not confirmed.",
            "raw_value": {
                "status": "Not detected",
                "confidence": "Low"
            }
        }
    ]


def save_sample_report(
    database_path,
    device_name="Test-Mac.local",
    wifi_name="Test Wi-Fi",
    risk_level="Medium risk",
    risk_score=25,
    summary="Sample summary.",
    check_results=None
):
    return database.save_report(
        device_name=device_name,
        wifi_name=wifi_name,
        risk_result=sample_risk_result(
            level=risk_level,
            score=risk_score,
            summary=summary
        ),
        check_results=check_results or sample_check_results(),
        database_path=database_path
    )


def fetch_count(database_path, table_name):
    with database.get_connection(database_path) as connection:
        return connection.execute(
            f"SELECT COUNT(*) FROM {table_name}"
        ).fetchone()[0]


def fetch_check_results(database_path, report_id):
    with database.get_connection(database_path) as connection:
        return connection.execute(
            """
            SELECT report_id, check_name, status, message, raw_value
            FROM check_results
            WHERE report_id = ?
            ORDER BY id
            """,
            (report_id,),
        ).fetchall()


def test_initialise_database_creates_required_tables_and_enables_foreign_keys(tmp_path):
    database_path = tmp_path / "wifiguard.db"

    database.initialise_database(database_path=database_path)

    assert database_path.exists()

    with database.get_connection(database_path) as connection:
        table_rows = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
        table_names = {row[0] for row in table_rows}
        foreign_keys_enabled = connection.execute(
            "PRAGMA foreign_keys"
        ).fetchone()[0]

    assert "reports" in table_names
    assert "check_results" in table_names
    assert foreign_keys_enabled == 1


def test_save_report_returns_retrievable_report(tmp_path):
    database_path = tmp_path / "wifiguard.db"

    report_id = save_sample_report(
        database_path=database_path,
        device_name="Pawels-MacBook-Air.local",
        wifi_name="Hidden by macOS privacy settings",
        risk_level="Medium risk",
        risk_score=25,
        summary="Some recommended protections are missing or could not be confirmed."
    )
    report = database.get_report_by_id(report_id, database_path=database_path)

    assert isinstance(report_id, int)
    assert report["device_name"] == "Pawels-MacBook-Air.local"
    assert report["wifi_name"] == "Hidden by macOS privacy settings"
    assert report["risk_level"] == "Medium risk"
    assert report["risk_score"] == 25
    assert report["summary"] == "Some recommended protections are missing or could not be confirmed."


def test_recent_reports_are_newest_first_and_respect_limit(tmp_path):
    database_path = tmp_path / "wifiguard.db"

    first_id = save_sample_report(database_path, device_name="Device 1")
    second_id = save_sample_report(database_path, device_name="Device 2")
    third_id = save_sample_report(database_path, device_name="Device 3")

    recent_reports = database.get_recent_reports(
        limit=2,
        database_path=database_path
    )

    assert [report["id"] for report in recent_reports] == [third_id, second_id]
    assert [report["device_name"] for report in recent_reports] == ["Device 3", "Device 2"]
    assert first_id not in [report["id"] for report in recent_reports]


def test_get_report_by_id_returns_matching_report_or_none(tmp_path):
    database_path = tmp_path / "wifiguard.db"

    report_id = save_sample_report(
        database_path,
        device_name="Lookup-Mac.local",
        risk_level="Lower risk",
        risk_score=15
    )

    report = database.get_report_by_id(report_id, database_path=database_path)
    missing_report = database.get_report_by_id(9999, database_path=database_path)

    assert report["id"] == report_id
    assert report["device_name"] == "Lookup-Mac.local"
    assert report["risk_level"] == "Lower risk"
    assert report["risk_score"] == 15
    assert missing_report is None


def test_check_results_are_linked_to_the_correct_report(tmp_path):
    database_path = tmp_path / "wifiguard.db"
    first_check_results = sample_check_results()
    second_check_results = [
        {
            "check_name": "Risk engine",
            "status": "Lower risk",
            "message": "Your current setup appears lower risk.",
            "raw_value": {
                "level": "Lower risk",
                "score": 15
            }
        }
    ]

    first_report_id = save_sample_report(
        database_path,
        device_name="First-Mac.local",
        check_results=first_check_results
    )
    second_report_id = save_sample_report(
        database_path,
        device_name="Second-Mac.local",
        check_results=second_check_results
    )

    first_rows = fetch_check_results(database_path, first_report_id)
    second_rows = fetch_check_results(database_path, second_report_id)

    assert [row[0] for row in first_rows] == [first_report_id, first_report_id]
    assert [row[1] for row in first_rows] == ["macOS firewall", "VPN / tunnel routing"]
    assert [row[0] for row in second_rows] == [second_report_id]
    assert [row[1] for row in second_rows] == ["Risk engine"]


def test_pruning_removes_old_reports_and_check_results(tmp_path):
    database_path = tmp_path / "wifiguard.db"

    first_id = save_sample_report(database_path, device_name="Oldest")
    second_id = save_sample_report(database_path, device_name="Middle")
    third_id = save_sample_report(database_path, device_name="Newest")

    deleted_count = database.prune_old_reports(
        max_reports=2,
        database_path=database_path
    )
    remaining_reports = database.get_recent_reports(
        limit=10,
        database_path=database_path
    )

    with database.get_connection(database_path) as connection:
        orphan_count = connection.execute(
            """
            SELECT COUNT(*)
            FROM check_results
            LEFT JOIN reports ON reports.id = check_results.report_id
            WHERE reports.id IS NULL
            """
        ).fetchone()[0]
        check_report_ids = [
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT report_id FROM check_results ORDER BY report_id"
            ).fetchall()
        ]

    assert deleted_count == 1
    assert [report["id"] for report in remaining_reports] == [third_id, second_id]
    assert first_id not in [report["id"] for report in remaining_reports]
    assert check_report_ids == [second_id, third_id]
    assert orphan_count == 0


def test_clear_all_reports_removes_reports_and_check_results(tmp_path):
    database_path = tmp_path / "wifiguard.db"

    save_sample_report(database_path, device_name="First-Mac.local")
    save_sample_report(database_path, device_name="Second-Mac.local")

    deleted_count = database.clear_all_reports(database_path=database_path)
    second_deleted_count = database.clear_all_reports(database_path=database_path)

    assert deleted_count == 2
    assert second_deleted_count == 0
    assert fetch_count(database_path, "reports") == 0
    assert fetch_count(database_path, "check_results") == 0
