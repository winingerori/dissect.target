from __future__ import annotations

import re
from datetime import datetime
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.apps.webserver.webserver import WebserverAccessLogRecord

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target

ConfluenceLogRecord = TargetRecordDescriptor(
    "application/log/confluence/app",
    [
        ("datetime", "ts"),
        ("string", "level"),
        ("string", "thread"),
        ("string", "classname"),
        ("string", "message"),
        ("path", "source"),
    ],
)

# Log4j log format used by Confluence application and security logs across all versions.
# Pre-6.x thread names look like: [http-8080-exec-1] or [Catalina-startStop-1]
# 6.x+ thread names look like:   [http-nio-8090-exec-5] or [Confluence feature thread pool-1]
# Example:
#   2023-01-15 10:23:45,123 ERROR [http-nio-8090-exec-5] [com.atlassian.confluence.SomeClass] message
RE_LOG4J = re.compile(
    r"""
        (?P<ts>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3})
        \s+
        (?P<level>\S+)
        \s+
        \[(?P<thread>[^\]]*)\]
        \s+
        \[(?P<classname>[^\]]*)\]
        \s+
        (?P<message>.*)
    """,
    re.VERBOSE,
)

# Tomcat access log in Apache combined format.
# Used by Confluence 5.x–6.x default configuration and any deployment with pattern="combined".
# Example:
#   1.2.3.4 - admin [15/Jan/2023:10:23:45 +0000] "GET /wiki/index.action HTTP/1.1" 200 12345 "http://ref/" "Mozilla/5.0"
RE_ACCESS_COMBINED = re.compile(
    r"""
        (?P<remote_ip>\S+)\s+
        (?P<remote_logname>\S+)\s+
        (?P<remote_user>\S+)\s+
        \[(?P<ts>[^\]]+)\]\s+
        "(?:-|(?P<method>\S+)\s+(?P<uri>\S+)\s*(?P<protocol>HTTP/[^"]*)?)"
        \s+(?P<status_code>\d{3})
        \s+(?P<bytes_sent>-|\d+)
        (?:\s+"(?P<referer>[^"]*)"\s+"(?P<useragent>[^"]*)")?
        (?:\s+(?P<response_time_ms>\d+))?
    """,
    re.VERBOSE,
)

# Tomcat access log in Confluence 7.x+ custom format.
# Adds CF-Connecting-IP and X-Forwarded-For fields, removes referer/user-agent.
# Pattern: %a %{CF-Connecting-IP}i %l %u %t %{X-Forwarded-For}i "%r" %s %b %D
# Example:
#   1.2.3.4 - - admin [15/Jan/2023:10:23:45 +0000] 10.0.0.1 "GET /wiki/index.action HTTP/1.1" 200 12345 567
RE_ACCESS_CONFLUENCE_7PLUS = re.compile(
    r"""
        (?P<remote_ip>\S+)\s+
        (?P<cf_ip>\S+)\s+
        (?P<remote_logname>\S+)\s+
        (?P<remote_user>\S+)\s+
        \[(?P<ts>[^\]]+)\]\s+
        (?P<xff>\S+)\s+
        "(?:-|(?P<method>\S+)\s+(?P<uri>\S+)\s*(?P<protocol>HTTP/[^"]*)?)"
        \s+(?P<status_code>\d{3})
        \s+(?P<bytes_sent>-|\d+)
        (?:\s+(?P<response_time_ms>\d+))?
    """,
    re.VERBOSE,
)


class ConfluencePlugin(Plugin):
    """Atlassian Confluence on-premise (Server and Data Center) plugin.

    Supports Confluence versions 5.x through 9.x on Linux and Windows.

    Parses:
    - Tomcat HTTP access logs (``localhost_access_log.*.txt`` / ``access_log.*.txt``)
    - Application logs (``atlassian-confluence.log`` and rotated variants)
    - Security/audit logs (``atlassian-confluence-security.log`` and rotated variants)

    References:
        - https://confluence.atlassian.com/doc/working-with-confluence-logs-108364722.html
        - https://confluence.atlassian.com/conf85/working-with-confluence-logs-1283368208.html
    """

    __namespace__ = "confluence"

    # Linux default install directories.
    # Versioned installs (e.g. /opt/atlassian/confluence-7.0.0/) are discovered via glob.
    DEFAULT_INSTALL_DIRS_LINUX = (
        "/opt/atlassian/confluence",
        "/usr/local/atlassian/confluence",
        "/opt/confluence",
    )

    # Windows default install directories (sysvol-prefixed).
    DEFAULT_INSTALL_DIRS_WINDOWS = (
        "sysvol/Program Files/Atlassian/Confluence",
        "sysvol/Program Files (x86)/Atlassian/Confluence",
    )

    # Linux default home directories.
    DEFAULT_HOME_DIRS_LINUX = (
        "/var/atlassian/application-data/confluence",
        "/opt/atlassian/application-data/confluence",
    )

    # Windows default home directories.
    DEFAULT_HOME_DIRS_WINDOWS = (
        "sysvol/ProgramData/Atlassian/Application Data/Confluence",
    )

    # Path of confluence-init.properties relative to the install root.
    # This file specifies the home directory for the installation.
    INIT_PROPERTIES_PATH = "confluence/WEB-INF/classes/confluence-init.properties"

    # Tomcat access log filename patterns relative to the install dir.
    # "localhost_access_log" is used by Confluence 5.x–7.x; "access_log" appears in some 8.x+ deployments.
    TOMCAT_ACCESS_LOG_PATTERNS = (
        "logs/localhost_access_log.*.txt",
        "logs/localhost_access_log.*.log",
        "logs/access_log.*.txt",
        "logs/access_log.*.log",
    )

    # Application log patterns relative to the home dir (current + rotated).
    # Rotation suffix format changed across versions:
    #   5.x–7.x: atlassian-confluence.log, atlassian-confluence.log.1, ...
    #   8.x+:     atlassian-confluence.log, atlassian-confluence.2023-01-15-10-23-45.log, ...
    APP_LOG_PATTERNS = (
        "logs/atlassian-confluence.log",
        "logs/atlassian-confluence.*.log",
    )

    # Security log patterns relative to the home dir (current + rotated).
    SECURITY_LOG_PATTERNS = (
        "logs/atlassian-confluence-security.log",
        "logs/atlassian-confluence-security.*.log",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.home_dirs: set[Path] = set()
        self.install_dirs: set[Path] = set()
        self._find_installations()

    def check_compatible(self) -> None:
        if not self.home_dirs and not self.install_dirs:
            raise UnsupportedPluginError("No Confluence installation found on target")

    def _find_installations(self) -> None:
        """Discover Confluence install and home directories on the target."""

        # Linux install dirs – also discover versioned installs e.g. /opt/atlassian/confluence-7.0.0
        for install_path in self.DEFAULT_INSTALL_DIRS_LINUX:
            path = self.target.fs.path(install_path)
            parent = path.parent
            name = path.name
            for entry in parent.glob(f"{name}*"):
                if entry.is_dir():
                    self._add_install_dir(entry)

        # Windows install dirs
        for install_path in self.DEFAULT_INSTALL_DIRS_WINDOWS:
            entry = self.target.fs.path(install_path)
            if entry.is_dir():
                self._add_install_dir(entry)

        # Default home dirs
        for home_path in self.DEFAULT_HOME_DIRS_LINUX + self.DEFAULT_HOME_DIRS_WINDOWS:
            p = self.target.fs.path(home_path)
            if p.is_dir():
                self.home_dirs.add(p)

    def _add_install_dir(self, install_dir: Path) -> None:
        """Register an install directory and resolve its configured home directory."""
        self.install_dirs.add(install_dir)

        init_props = install_dir / self.INIT_PROPERTIES_PATH
        if init_props.exists():
            home = self._read_home_from_properties(init_props)
            if home and home.is_dir():
                self.home_dirs.add(home)

    def _read_home_from_properties(self, props_path: Path) -> Path | None:
        """Parse ``confluence-init.properties`` and return the configured home directory path."""
        try:
            for line in props_path.open("rt"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "confluence.home" in line:
                    _, _, value = line.partition("=")
                    value = value.strip()
                    if value:
                        return self.target.fs.path(value)
        except Exception as e:
            self.target.log.warning("Failed to read Confluence init properties %s: %s", props_path, e)
        return None

    @export(record=WebserverAccessLogRecord)
    def access(self) -> Iterator[WebserverAccessLogRecord]:
        """Return Tomcat HTTP access log entries from Confluence installations.

        Confluence runs on Apache Tomcat and produces access logs in Apache combined log format
        (pre-7.x default) or the Confluence 7.x+ custom format that adds ``CF-Connecting-IP``
        and ``X-Forwarded-For`` fields. Both formats are parsed automatically.

        Both old-style (``localhost_access_log.*.txt``, used by 5.x–7.x) and new-style
        (``access_log.*.txt``, used by some 8.x+ deployments) filename patterns are discovered.

        Access logs are critical for detecting exploitation of known Confluence CVEs such as
        CVE-2022-26134 (OGNL injection) and CVE-2023-22515 (privilege escalation).

        References:
            - https://confluence.atlassian.com/doc/working-with-confluence-logs-108364722.html
        """
        seen: set[Path] = set()
        for install_dir in self.install_dirs:
            for pattern in self.TOMCAT_ACCESS_LOG_PATTERNS:
                for log_file in install_dir.glob(pattern):
                    if log_file not in seen:
                        seen.add(log_file)
                        yield from self._parse_access_log(log_file)

    @export(record=ConfluenceLogRecord)
    def logs(self) -> Iterator[ConfluenceLogRecord]:
        """Return Confluence application log entries.

        Parses ``atlassian-confluence.log`` and all rotated variants from the Confluence home
        directory. This log captures application events, errors, startup/shutdown activity,
        and plugin lifecycle events across all supported versions (5.x–9.x).

        References:
            - https://confluence.atlassian.com/doc/working-with-confluence-logs-108364722.html
        """
        seen: set[Path] = set()
        for home_dir in self.home_dirs:
            for pattern in self.APP_LOG_PATTERNS:
                for log_file in home_dir.glob(pattern):
                    if log_file not in seen:
                        seen.add(log_file)
                        yield from self._parse_log4j_log(log_file)

    @export(record=ConfluenceLogRecord)
    def security(self) -> Iterator[ConfluenceLogRecord]:
        """Return Confluence security log entries.

        Parses ``atlassian-confluence-security.log`` and all rotated variants. This log records
        authentication events (login, logout, failed login attempts) and is valuable for detecting
        brute-force attacks and unauthorized access.

        References:
            - https://confluence.atlassian.com/doc/working-with-confluence-logs-108364722.html
        """
        seen: set[Path] = set()
        for home_dir in self.home_dirs:
            for pattern in self.SECURITY_LOG_PATTERNS:
                for log_file in home_dir.glob(pattern):
                    if log_file not in seen:
                        seen.add(log_file)
                        yield from self._parse_log4j_log(log_file)

    def _parse_access_log(self, path: Path) -> Iterator[WebserverAccessLogRecord]:
        """Parse a Tomcat access log file, auto-detecting combined or Confluence 7.x+ format."""
        for line in open_decompress(path, "rt"):
            line = line.strip()
            if not line:
                continue

            log, format_name = _match_access_line(line)
            if log is None:
                self.target.log.warning(
                    "Could not match Confluence access log format for line %r in %s", line, path
                )
                continue

            ts = None
            try:
                ts = datetime.strptime(log["ts"], "%d/%b/%Y:%H:%M:%S %z")
            except ValueError:
                pass

            yield WebserverAccessLogRecord(
                ts=ts,
                remote_user=_clean(log.get("remote_user")),
                remote_ip=log.get("remote_ip"),
                local_ip=None,
                pid=None,
                method=log.get("method"),
                uri=log.get("uri"),
                protocol=log.get("protocol"),
                status_code=log.get("status_code"),
                bytes_sent=_clean(log.get("bytes_sent")) or 0,
                referer=_clean(log.get("referer")),
                useragent=log.get("useragent"),
                response_time_ms=log.get("response_time_ms"),
                source=path,
                _target=self.target,
            )

    def _parse_log4j_log(self, path: Path) -> Iterator[ConfluenceLogRecord]:
        """Parse a Confluence Log4j log file, preserving multi-line entries (e.g. stack traces)."""
        current: dict | None = None

        for line in open_decompress(path, "rt"):
            line = line.rstrip("\n\r")
            if not line:
                if current is not None:
                    yield _make_log4j_record(current, path, self.target)
                    current = None
                continue

            if match := RE_LOG4J.match(line):
                if current is not None:
                    yield _make_log4j_record(current, path, self.target)
                current = match.groupdict()
            elif current is not None:
                # Continuation line (stack trace or wrapped message).
                current["message"] += "\n" + line
            else:
                self.target.log.warning("Skipping unmatched Confluence log line %r in %s", line, path)

        if current is not None:
            yield _make_log4j_record(current, path, self.target)


def _match_access_line(line: str) -> tuple[dict | None, str | None]:
    """Try to match a Tomcat access log line against known Confluence access log formats.

    Returns a ``(fields_dict, format_name)`` tuple, or ``(None, None)`` if no format matched.

    The Confluence 7.x+ format inserts two extra fields between the remote user and the
    timestamp, so we distinguish formats by counting space-separated tokens before the
    first ``[`` bracket.
    """
    bracket_pos = line.find("[")
    if bracket_pos > 0:
        prefix_tokens = line[:bracket_pos].split()
        # Combined: IP logname user [time] → 3 tokens
        # Confluence 7.x+: IP cf_ip logname user [time] xff → 4 tokens before [
        if len(prefix_tokens) == 4:
            if match := RE_ACCESS_CONFLUENCE_7PLUS.match(line):
                log = match.groupdict()
                # Prefer CF-Connecting-IP as the real client IP when it's not a placeholder.
                cf_ip = log.pop("cf_ip", None)
                if cf_ip and cf_ip != "-":
                    log["remote_ip"] = cf_ip
                log.pop("xff", None)
                return log, "confluence_7plus"

    if match := RE_ACCESS_COMBINED.match(line):
        return match.groupdict(), "combined"

    return None, None


def _make_log4j_record(log: dict, path: Path, target: Target) -> ConfluenceLogRecord:
    """Build a ``ConfluenceLogRecord`` from a parsed Log4j log entry."""
    ts = None
    try:
        # Log4j timestamps are in local server time without a UTC offset.
        naive = datetime.strptime(log["ts"], "%Y-%m-%d %H:%M:%S,%f")  # noqa: DTZ007
        ts = target.datetime.local(naive)
    except ValueError:
        pass

    return ConfluenceLogRecord(
        ts=ts,
        level=log.get("level"),
        thread=log.get("thread"),
        classname=log.get("classname"),
        message=log.get("message", "").strip(),
        source=path,
        _target=target,
    )


def _clean(value: str | None) -> str | None:
    """Replace ``-`` placeholder or empty string with ``None``."""
    if value in ("-", ""):
        return None
    return value
