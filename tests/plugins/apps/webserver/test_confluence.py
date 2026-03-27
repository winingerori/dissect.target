from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.webserver.confluence import (
    ConfluencePlugin,
    _clean,
    _match_access_line,
    RE_ACCESS_CONF_ACCESS_LOG,
)

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


# ---------------------------------------------------------------------------
# Sample log content
# ---------------------------------------------------------------------------

ACCESS_LOG_COMBINED = textwrap.dedent("""\
    192.168.1.10 - - [15/Jan/2023:10:00:01 +0000] "GET /wiki/index.action HTTP/1.1" 200 12345 "https://confluence.example.com/wiki/" "Mozilla/5.0 (Windows NT 10.0)"
    10.0.0.1 - admin [15/Jan/2023:10:00:05 +0000] "POST /wiki/dologin.action HTTP/1.1" 302 0 "https://confluence.example.com/wiki/login.action" "Mozilla/5.0 (Macintosh)"
    172.16.0.5 - - [15/Jan/2023:10:00:10 +0000] "GET /wiki/rest/api/content?limit=25 HTTP/1.1" 200 4567 "-" "python-requests/2.28.1"
    192.168.1.20 - bob [15/Jan/2023:10:01:00 +0000] "GET /wiki/pages/viewpage.action?pageId=12345 HTTP/1.1" 200 23456 "-" "curl/7.84.0"
    10.0.0.99 - - [15/Jan/2023:10:01:30 +0000] "GET /$%7B%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%7D HTTP/1.1" 400 789 "-" "Go-http-client/1.1"
""")

# Confluence 7.11+ conf_access_log format:
# %t %{X-AUSERNAME}o %I %h %r %s %Dms %b %{Referer}i %{User-Agent}i
ACCESS_LOG_CONF_ACCESS_LOG = textwrap.dedent("""\
    [15/Jan/2023:10:00:01 +0000] admin http-nio-8090-exec-1 192.168.1.10 GET /wiki/index.action HTTP/1.1 200 342ms 12345 https://confluence.example.com/ Mozilla/5.0 (Windows NT 10.0; Win64; x64)
    [15/Jan/2023:10:00:05 +0000] - http-nio-8090-exec-2 10.0.0.1 POST /wiki/dologin.action HTTP/1.1 302 56ms 0 - -
    [15/Jan/2023:10:01:30 +0000] - http-nio-8090-exec-3 10.0.0.99 GET /$%7B%40java.lang.Runtime%40getRuntime%28%29%7D HTTP/1.1 400 12ms 789 - python-requests/2.28.1
""")

# Confluence 7.x+ format: IP CF-Connecting-IP logname user [time] X-Forwarded-For "request" status bytes ms
ACCESS_LOG_7PLUS = textwrap.dedent("""\
    192.168.1.10 - - - [16/Jan/2023:09:00:00 +0000] - "GET /wiki/index.action HTTP/1.1" 200 12345 456
    10.0.0.2 - 10.0.0.2 alice [16/Jan/2023:09:00:05 +0000] 10.0.0.2 "POST /wiki/dologin.action HTTP/1.1" 302 0 123
    172.16.0.5 - - - [16/Jan/2023:09:01:00 +0000] - "GET /wiki/rest/api/content HTTP/1.1" 200 5678 789
""")

APP_LOG = textwrap.dedent("""\
    2023-01-15 10:00:00,123 INFO  [main] [com.atlassian.confluence.lifecycle.ConfluenceLifecycle] Confluence is starting up
    2023-01-15 10:00:01,456 INFO  [main] [com.atlassian.confluence.setup.ConfluenceSetup] Setup complete
    2023-01-15 10:23:45,789 ERROR [http-nio-8090-exec-5] [com.atlassian.confluence.pages.PageManager] Error loading page with id 99999
    java.lang.NullPointerException: null
    \tat com.atlassian.confluence.pages.DefaultPageManager.getPage(DefaultPageManager.java:123)
    \tat com.atlassian.confluence.pages.DefaultPageManager.getById(DefaultPageManager.java:456)
    2023-01-15 10:25:00,000 WARN  [http-nio-8090-exec-3] [com.atlassian.confluence.search.DefaultSearchManager] Search index is out of date
    2023-01-15 10:30:00,111 INFO  [Confluence feature thread pool-1] [com.atlassian.confluence.cluster.ClusterManager] Node joined cluster
""")

# Older Confluence (<= 6.x) thread name style: http-8080-exec-N
APP_LOG_OLDER = textwrap.dedent("""\
    2016-07-01 08:00:00,000 INFO  [Catalina-startStop-1] [com.atlassian.confluence.lifecycle.ConfluenceLifecycle] Confluence started
    2016-07-01 08:05:00,000 WARN  [http-8080-exec-2] [com.atlassian.confluence.pages.PageManager] Low memory detected
""")

SECURITY_LOG = textwrap.dedent("""\
    2023-01-15 10:01:00,100 INFO  [http-nio-8090-exec-1] [com.atlassian.confluence.security.login.ConfluenceSecurityFilter] login - SUCCESS - login for admin - at IP: 192.168.1.10 - with username: admin
    2023-01-15 10:01:05,200 INFO  [http-nio-8090-exec-2] [com.atlassian.confluence.security.login.ConfluenceSecurityFilter] login - SUCCESS - login for bob - at IP: 10.0.0.1 - with username: bob
    2023-01-15 10:02:00,300 WARN  [http-nio-8090-exec-4] [com.atlassian.confluence.security.login.ConfluenceSecurityFilter] login - FAILED - login for unknown - at IP: 10.0.0.99 - with username: unknown
    2023-01-15 10:02:01,400 WARN  [http-nio-8090-exec-4] [com.atlassian.confluence.security.login.ConfluenceSecurityFilter] login - FAILED - login for admin - at IP: 10.0.0.99 - with username: admin
    2023-01-15 10:30:00,500 INFO  [http-nio-8090-exec-6] [com.atlassian.confluence.security.login.ConfluenceSecurityFilter] logout - SUCCESS - logout for admin - at IP: 192.168.1.10 - with username: admin
""")

INIT_PROPERTIES = textwrap.dedent("""\
    # This file specifies the home directory for this Confluence installation.
    # confluence.home=/old/path
    confluence.home=/var/atlassian/application-data/confluence
""")


def _fh(content: str) -> BytesIO:
    return BytesIO(content.encode())


# ---------------------------------------------------------------------------
# _match_access_line unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("line", "expected_format", "expected_remote_ip", "expected_method", "expected_status"),
    [
        pytest.param(
            '192.168.1.10 - - [15/Jan/2023:10:00:01 +0000] "GET /wiki/index.action HTTP/1.1" 200 12345 "https://ref/" "Mozilla/5.0"',
            "combined",
            "192.168.1.10",
            "GET",
            "200",
            id="combined-with-referer-ua",
        ),
        pytest.param(
            '192.168.1.10 - admin [15/Jan/2023:10:00:01 +0000] "POST /wiki/dologin.action HTTP/1.1" 302 0',
            "combined",
            "192.168.1.10",
            "POST",
            "302",
            id="combined-no-referer-ua",
        ),
        pytest.param(
            "[15/Jan/2023:10:00:01 +0000] admin http-nio-8090-exec-1 192.168.1.10 GET /wiki/index.action HTTP/1.1 200 342ms 12345 - Mozilla/5.0",
            "conf_access_log",
            "192.168.1.10",
            "GET",
            "200",
            id="conf_access_log-with-ua",
        ),
        pytest.param(
            "[15/Jan/2023:10:00:05 +0000] - http-nio-8090-exec-2 10.0.0.1 POST /wiki/dologin.action HTTP/1.1 302 56ms 0 - -",
            "conf_access_log",
            "10.0.0.1",
            "POST",
            "302",
            id="conf_access_log-no-ua",
        ),
        pytest.param(
            '10.0.0.5 - - - [16/Jan/2023:09:01:00 +0000] - "GET /wiki/rest/api/content HTTP/1.1" 200 5678 789',
            "confluence_7plus",
            "10.0.0.5",
            "GET",
            "200",
            id="confluence-7plus-all-dashes",
        ),
        pytest.param(
            '10.0.0.1 - 10.0.0.1 alice [16/Jan/2023:09:00:05 +0000] 10.0.0.1 "POST /wiki/dologin.action HTTP/1.1" 302 0 123',
            "confluence_7plus",
            "10.0.0.1",
            "POST",
            "302",
            id="confluence-7plus-with-cf-ip-replaces-remote-ip",
        ),
    ],
)
def test_match_access_line(
    line: str,
    expected_format: str,
    expected_remote_ip: str,
    expected_method: str,
    expected_status: str,
) -> None:
    log, fmt = _match_access_line(line)
    assert fmt == expected_format
    assert log is not None
    assert log["remote_ip"] == expected_remote_ip
    assert log["method"] == expected_method
    assert log["status_code"] == expected_status


def test_match_access_line_no_match() -> None:
    log, fmt = _match_access_line("not a log line at all")
    assert log is None
    assert fmt is None


# ---------------------------------------------------------------------------
# _clean unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("-", None),
        ("", None),
        ("admin", "admin"),
        ("Mozilla/5.0", "Mozilla/5.0"),
    ],
)
def test_clean(value: str, expected: str | None) -> None:
    assert _clean(value) == expected


# ---------------------------------------------------------------------------
# Access logs: combined format (Confluence 5.x–6.x default)
# ---------------------------------------------------------------------------


def test_access_combined(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Parse Tomcat access log in Apache combined format (Confluence 5.x–6.x default)."""
    fs_unix.map_file_fh(
        "opt/atlassian/confluence/logs/localhost_access_log.2023-01-15.txt",
        _fh(ACCESS_LOG_COMBINED),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.access())

    assert len(results) == 5

    first = results[0]
    assert first.ts == datetime(2023, 1, 15, 10, 0, 1, tzinfo=timezone.utc)
    assert str(first.remote_ip) == "192.168.1.10"
    assert first.method == "GET"
    assert first.uri == "/wiki/index.action"
    assert first.protocol == "HTTP/1.1"
    assert first.status_code == 200
    assert first.bytes_sent == 12345

    second = results[1]
    assert second.remote_user == "admin"
    assert second.method == "POST"
    assert second.status_code == 302

    # Exploitation attempt (CVE-2022-26134 style)
    fifth = results[4]
    assert fifth.status_code == 400
    assert "%" in fifth.uri


# ---------------------------------------------------------------------------
# Access logs: Confluence 7.x+ format
# ---------------------------------------------------------------------------


def test_access_confluence_7plus(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Parse Tomcat access log in Confluence 7.x+ custom format (with XFF/CF-IP fields)."""
    fs_unix.map_file_fh(
        "opt/atlassian/confluence/logs/localhost_access_log.2023-01-16.txt",
        _fh(ACCESS_LOG_7PLUS),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.access())

    assert len(results) == 3

    first = results[0]
    assert first.ts == datetime(2023, 1, 16, 9, 0, 0, tzinfo=timezone.utc)
    assert first.method == "GET"
    assert first.status_code == 200

    # CF-Connecting-IP (10.0.0.2) replaces the remote_ip when it's not "-"
    second = results[1]
    assert str(second.remote_ip) == "10.0.0.2"


# ---------------------------------------------------------------------------
# Access logs: conf_access_log format (Confluence 7.11+ default)
# ---------------------------------------------------------------------------


def test_access_conf_access_log(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Parse conf_access_log format (Confluence 7.11+ default, prefix=conf_access_log)."""
    fs_unix.map_file_fh(
        "opt/atlassian/confluence/logs/conf_access_log.2023-01-15.log",
        _fh(ACCESS_LOG_CONF_ACCESS_LOG),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.access())

    assert len(results) == 3

    first = results[0]
    assert first.ts == datetime(2023, 1, 15, 10, 0, 1, tzinfo=timezone.utc)
    assert str(first.remote_ip) == "192.168.1.10"
    assert first.remote_user == "admin"
    assert first.method == "GET"
    assert first.uri == "/wiki/index.action"
    assert first.protocol == "HTTP/1.1"
    assert first.status_code == 200
    assert first.response_time_ms == 342

    # Anonymous request (username "-" → None)
    second = results[1]
    assert second.remote_user is None
    assert second.status_code == 302

    # Exploitation attempt
    third = results[2]
    assert third.status_code == 400
    assert "%" in third.uri


# ---------------------------------------------------------------------------
# Access logs: access_log.* naming (Confluence 8.x+ deployments)
# ---------------------------------------------------------------------------


def test_access_log_new_naming(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """access_log.* filenames (used in some 8.x+ deployments) are discovered."""
    fs_unix.map_file_fh(
        "opt/atlassian/confluence/logs/access_log.2023-01-15.txt",
        _fh(ACCESS_LOG_COMBINED),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.access())

    assert len(results) == 5


# ---------------------------------------------------------------------------
# Application logs
# ---------------------------------------------------------------------------


def test_app_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Parse Confluence application log (atlassian-confluence.log)."""
    fs_unix.map_file_fh(
        "var/atlassian/application-data/confluence/logs/atlassian-confluence.log",
        _fh(APP_LOG),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.logs())

    # 2 INFO + 1 ERROR (multi-line) + 1 WARN + 1 INFO = 5 records
    assert len(results) == 5

    # Multi-line stack trace is folded into a single record
    error_record = next(r for r in results if r.level == "ERROR")
    assert "NullPointerException" in error_record.message
    assert "DefaultPageManager" in error_record.message

    first = results[0]
    assert first.level == "INFO"
    assert first.thread == "main"
    assert first.classname == "com.atlassian.confluence.lifecycle.ConfluenceLifecycle"


def test_app_logs_older_thread_names(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Thread name style from Confluence 5.x–6.x (http-8080-exec-N, Catalina-startStop-N) is parsed."""
    fs_unix.map_file_fh(
        "var/atlassian/application-data/confluence/logs/atlassian-confluence.log",
        _fh(APP_LOG_OLDER),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.logs())

    assert len(results) == 2
    assert results[0].thread == "Catalina-startStop-1"
    assert results[1].thread == "http-8080-exec-2"


def test_app_log_rotated_file(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Rotated app log files (atlassian-confluence.*.log) are discovered."""
    fs_unix.map_file_fh(
        "var/atlassian/application-data/confluence/logs/atlassian-confluence.2023-01-14-00-00-00.log",
        _fh(APP_LOG_OLDER),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.logs())

    assert len(results) == 2


# ---------------------------------------------------------------------------
# Security logs
# ---------------------------------------------------------------------------


def test_security_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Parse Confluence security log (atlassian-confluence-security.log)."""
    fs_unix.map_file_fh(
        "var/atlassian/application-data/confluence/logs/atlassian-confluence-security.log",
        _fh(SECURITY_LOG),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.security())

    assert len(results) == 5

    logins = [r for r in results if "login - SUCCESS" in r.message]
    assert len(logins) == 2

    failures = [r for r in results if "FAILED" in r.message]
    assert len(failures) == 2
    assert all(r.level == "WARN" for r in failures)


def test_security_log_rotated_file(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Rotated security log files (atlassian-confluence-security.*.log) are discovered."""
    fs_unix.map_file_fh(
        "var/atlassian/application-data/confluence/logs/atlassian-confluence-security.2023-01-14-00-00-00.log",
        _fh(SECURITY_LOG),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.security())

    assert len(results) == 5


# ---------------------------------------------------------------------------
# Home directory discovery via confluence-init.properties
# ---------------------------------------------------------------------------


def test_home_dir_from_init_properties(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Home directory is resolved from confluence-init.properties when it exists."""
    # Install dir exists but default home dir (/var/atlassian/...) is NOT mapped.
    # Home must be resolved from the init.properties which points to /var/atlassian/...
    fs_unix.map_file_fh(
        "opt/atlassian/confluence/confluence/WEB-INF/classes/confluence-init.properties",
        _fh(INIT_PROPERTIES),
    )
    fs_unix.map_file_fh(
        "var/atlassian/application-data/confluence/logs/atlassian-confluence-security.log",
        _fh(SECURITY_LOG),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.security())

    assert len(results) == 5


# ---------------------------------------------------------------------------
# Versioned install directories
# ---------------------------------------------------------------------------


def test_versioned_install_dir(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Versioned install directories like /opt/atlassian/confluence-7.0.0 are discovered."""
    fs_unix.map_file_fh(
        "opt/atlassian/confluence-7.0.0/logs/localhost_access_log.2023-01-15.txt",
        _fh(ACCESS_LOG_COMBINED),
    )

    target_unix.add_plugin(ConfluencePlugin)
    results = list(target_unix.confluence.access())

    assert len(results) == 5


# ---------------------------------------------------------------------------
# check_compatible
# ---------------------------------------------------------------------------


def test_check_compatible_no_confluence(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """UnsupportedPluginError is raised when no Confluence installation is present."""
    from dissect.target.exceptions import UnsupportedPluginError

    target_unix.add_plugin(ConfluencePlugin)
    with pytest.raises(UnsupportedPluginError):
        target_unix.confluence.check_compatible()
