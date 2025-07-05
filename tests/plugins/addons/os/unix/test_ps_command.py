"""Tests for the Linux ps command plugin."""

from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch, PropertyMock

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.addons.command_parser.table_parser import TableParser, LinuxTableCommandParser
from dissect.target.plugins.addons.os.unix.ps_command import PsCommandPlugin
from tests._utils import absolute_path


@pytest.fixture
def target_with_ps_outputs(target_bare: Target) -> Target:
    """Create a target with ps command outputs."""
    fs = VirtualFilesystem()
    
    # Create the command_outputs directory structure
    fs.makedirs("/command_outputs")
    
    # Map the test data files
    ps_basic = absolute_path("_data/command_outputs/ps.txt")
    ps_aux = absolute_path("_data/command_outputs/ps_aux.txt")
    ps_ef = absolute_path("_data/command_outputs/ps_-ef.txt")
    ps_custom = absolute_path("_data/command_outputs/ps_-eo_pid,ppid,user,command.txt")
    ps_tree = absolute_path("_data/command_outputs/ps_axjf.txt")
    ps_custom_order = absolute_path("_data/command_outputs/ps_custom_order.txt")
    
    fs.map_file("/command_outputs/ps.txt", ps_basic)
    fs.map_file("/command_outputs/ps_aux.txt", ps_aux)
    fs.map_file("/command_outputs/ps_-ef.txt", ps_ef)
    fs.map_file("/command_outputs/ps_-eo_pid,ppid,user,command.txt", ps_custom)
    fs.map_file("/command_outputs/ps_axjf.txt", ps_tree)
    fs.map_file("/command_outputs/ps_custom_order.txt", ps_custom_order)
    
    target_bare.filesystems.add(fs)
    target_bare.fs.mount("/", fs)
    
    # Mock the hostname property to avoid plugin dependency
    with patch("dissect.target.target.Target.hostname", PropertyMock(return_value="test-hostname"), create=True):
        yield target_bare


def test_table_parser_basic() -> None:
    """Test basic table parser functionality."""
    header = "PID TTY          TIME CMD"
    parser = TableParser(header)
    
    columns = parser.get_column_names()
    assert columns == ["PID", "TTY", "TIME", "CMD"]
    
    # Test parsing a data line
    data_line = " 1234 pts/0    00:00:01 bash"
    parsed = parser.parse_data_line(data_line)
    
    assert parsed["PID"] == "1234"
    assert parsed["TTY"] == "pts/0"
    assert parsed["TIME"] == "00:00:01"
    assert parsed["CMD"] == "bash"


def test_table_parser_complex_header() -> None:
    """Test table parser with complex header."""
    header = "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    parser = TableParser(header)
    
    columns = parser.get_column_names()
    expected_columns = ["USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND"]
    assert columns == expected_columns
    
    # Test parsing a data line
    data_line = "root         1  0.0  0.1  19356  1516 ?        Ss   Jan01   0:01 /sbin/init"
    parsed = parser.parse_data_line(data_line)
    
    assert parsed["USER"] == "root"
    assert parsed["PID"] == "1"
    assert parsed["%CPU"] == "0.0"
    assert parsed["%MEM"] == "0.1"
    assert parsed["VSZ"] == "19356"
    assert parsed["RSS"] == "1516"
    assert parsed["TTY"] == "?"
    assert parsed["STAT"] == "Ss"
    assert parsed["START"] == "Jan01"
    assert parsed["TIME"] == "0:01"
    assert parsed["COMMAND"] == "/sbin/init"


def test_linux_table_command_parser() -> None:
    """Test Linux table command parser header detection."""
    parser = LinuxTableCommandParser()
    
    lines = [
        "",
        "# This is a comment",
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND",
        "root         1  0.0  0.1  19356  1516 ?        Ss   Jan01   0:01 /sbin/init",
        "root         2  0.0  0.0      0     0 ?        S    Jan01   0:00 [kthreadd]",
    ]
    
    header_index = parser.detect_header_line(lines)
    assert header_index == 2
    
    # Test full parsing
    parsed_rows = parser.parse_table_output(lines)
    assert len(parsed_rows) == 2
    
    assert parsed_rows[0]["USER"] == "root"
    assert parsed_rows[0]["PID"] == "1"
    assert parsed_rows[0]["COMMAND"] == "/sbin/init"
    
    assert parsed_rows[1]["USER"] == "root"
    assert parsed_rows[1]["PID"] == "2"
    assert parsed_rows[1]["COMMAND"] == "[kthreadd]"


def test_ps_plugin_compatible(target_with_ps_outputs: Target) -> None:
    """Test that the plugin is compatible when command_outputs directory exists."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Should not raise an exception
    plugin.check_compatible()


def test_ps_plugin_incompatible(target_bare: Target) -> None:
    """Test that the plugin is incompatible when command_outputs directory doesn't exist."""
    plugin = PsCommandPlugin(target_bare)
    
    with pytest.raises(Exception):
        plugin.check_compatible()


def test_ps_get_command_name(target_with_ps_outputs: Target) -> None:
    """Test getting the command name."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    assert plugin.get_command_name() == "ps"


def test_ps_get_supported_arguments(target_with_ps_outputs: Target) -> None:
    """Test getting supported arguments."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    supported_args = plugin.get_supported_arguments()
    assert "" in supported_args  # Basic ps
    assert "aux" in supported_args  # BSD style
    assert "-ef" in supported_args  # System V style
    assert "-eo" in supported_args  # Custom format
    assert "axjf" in supported_args  # Tree format


def test_ps_get_command_output_files(target_with_ps_outputs: Target) -> None:
    """Test getting command output files."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    files = list(plugin.get_command_output_files())
    file_names = [f.name for f in files]
    
    assert "ps.txt" in file_names
    assert "ps_aux.txt" in file_names
    assert "ps_-ef.txt" in file_names
    assert "ps_-eo_pid,ppid,user,command.txt" in file_names
    assert "ps_axjf.txt" in file_names
    assert "ps_custom_order.txt" in file_names
    assert len(files) == 6


def test_ps_parse_command_arguments(target_with_ps_outputs: Target) -> None:
    """Test parsing command arguments from filenames (now metadata only)."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Test basic filename
    args = plugin.parse_command_arguments("ps.txt")
    assert args["arguments"] == []
    assert args["format_info"] == "basic"
    
    # Test aux format
    args = plugin.parse_command_arguments("ps_aux.txt")
    assert args["arguments"] == ["aux"]
    assert args["format_info"] == "bsd_all_processes"
    
    # Test -ef format
    args = plugin.parse_command_arguments("ps_-ef.txt")
    assert args["arguments"] == ["-ef"]
    assert args["format_info"] == "sysv_full_format"
    
    # Test custom format
    args = plugin.parse_command_arguments("ps_-eo_pid,ppid,user,command.txt")
    assert args["arguments"] == ["-eo", "pid,ppid,user,command"]
    assert args["format_info"] == "custom_format"
    
    # Test tree format
    args = plugin.parse_command_arguments("ps_axjf.txt")
    assert args["arguments"] == ["axjf"]
    assert args["format_info"] == "tree_format"


def test_ps_parse_basic_output(target_with_ps_outputs: Target) -> None:
    """Test parsing basic ps output."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Get all records
    records = list(plugin.ps())
    
    # Filter records from basic output (ps.txt)
    basic_records = [r for r in records if r.source_file == "ps.txt"]
    
    assert len(basic_records) == 2
    
    # Check first process (bash)
    bash_record = next((r for r in basic_records if r.pid == "1234"), None)
    assert bash_record is not None
    assert bash_record.pid == "1234"
    assert bash_record.tty == "pts/0"
    assert bash_record.time == "00:00:01"
    assert bash_record.command == "bash"
    
    # Check second process (ps)
    ps_record = next((r for r in basic_records if r.pid == "5678"), None)
    assert ps_record is not None
    assert ps_record.pid == "5678"
    assert ps_record.command == "ps"


def test_ps_parse_aux_output(target_with_ps_outputs: Target) -> None:
    """Test parsing ps aux output."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Get all records
    records = list(plugin.ps())
    
    # Filter records from aux output
    aux_records = [r for r in records if r.source_file == "ps_aux.txt"]
    
    assert len(aux_records) == 8
    
    # Check init process
    init_record = next((r for r in aux_records if r.pid == "1"), None)
    assert init_record is not None
    assert init_record.pid == "1"
    assert init_record.user == "root"
    assert init_record.cpu_percent == "0.0"
    assert init_record.mem_percent == "0.1"
    assert init_record.vsz == "19356"
    assert init_record.rss == "1516"
    assert init_record.tty == "?"
    assert init_record.state == "Ss"
    assert init_record.start_time == "Jan01"
    assert init_record.time == "0:01"
    assert init_record.args == "/sbin/init"
    
    # Check user process
    user_record = next((r for r in aux_records if r.pid == "1234"), None)
    assert user_record is not None
    assert user_record.user == "user"
    assert user_record.tty == "pts/0"
    assert user_record.args == "-bash"


def test_ps_parse_ef_output(target_with_ps_outputs: Target) -> None:
    """Test parsing ps -ef output."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Get all records
    records = list(plugin.ps())
    
    # Filter records from -ef output
    ef_records = [r for r in records if r.source_file == "ps_-ef.txt"]
    
    assert len(ef_records) == 8
    
    # Check init process
    init_record = next((r for r in ef_records if r.pid == "1"), None)
    assert init_record is not None
    assert init_record.pid == "1"
    assert init_record.ppid == "0"
    assert init_record.uid == "root"  # UID column maps to uid field
    assert init_record.tty == "?"
    assert init_record.time == "00:00:01"
    assert init_record.command == "/sbin/init"  # CMD column maps to command field
    
    # Check bash process
    bash_record = next((r for r in ef_records if r.pid == "1234"), None)
    assert bash_record is not None
    assert bash_record.ppid == "456"
    assert bash_record.uid == "user"


def test_ps_parse_custom_format_output(target_with_ps_outputs: Target) -> None:
    """Test parsing ps custom format output."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Get all records
    records = list(plugin.ps())
    
    # Filter records from custom format output
    custom_records = [r for r in records if r.source_file == "ps_-eo_pid,ppid,user,command.txt"]
    
    assert len(custom_records) == 8
    
    # Check init process
    init_record = next((r for r in custom_records if r.pid == "1"), None)
    assert init_record is not None
    assert init_record.pid == "1"
    assert init_record.ppid == "0"
    assert init_record.user == "root"
    assert init_record.args == "/sbin/init"  # COMMAND column maps to args field
    
    # Check that other fields are empty (not in this format)
    assert init_record.tty == ""
    assert init_record.cpu_percent == ""
    assert init_record.mem_percent == ""


def test_ps_parse_tree_format_output(target_with_ps_outputs: Target) -> None:
    """Test parsing ps tree format output."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Get all records
    records = list(plugin.ps())
    
    # Filter records from tree format output
    tree_records = [r for r in records if r.source_file == "ps_axjf.txt"]
    
    assert len(tree_records) == 8
    
    # Check init process
    init_record = next((r for r in tree_records if r.pid == "1"), None)
    assert init_record is not None
    assert init_record.pid == "1"
    assert init_record.ppid == "0"
    assert init_record.tty == "?"
    assert init_record.state == "Ss"
    assert init_record.uid == "0"
    assert init_record.time == "0:01"
    assert init_record.args == "/sbin/init"  # COMMAND column maps to args field
    
    # Check bash process with tree indentation
    bash_record = next((r for r in tree_records if r.pid == "1234"), None)
    assert bash_record is not None
    assert bash_record.ppid == "456"
    assert bash_record.args == "\\_ -bash"  # Should preserve tree formatting


def test_ps_column_mapping(target_with_ps_outputs: Target) -> None:
    """Test column name mapping functionality."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Test mapping
    test_row = {
        "PID": "1234",
        "PPID": "456",
        "USER": "testuser",
        "%CPU": "1.5",
        "%MEM": "2.3",
        "VSZ": "12345",
        "RSS": "6789",
        "STAT": "S",
        "TTY": "pts/0",
        "TIME": "00:01:23",
        "COMMAND": "/bin/bash",
    }
    
    mapped = plugin.map_columns_to_fields(test_row, plugin.column_mappings)
    
    assert mapped["pid"] == "1234"
    assert mapped["ppid"] == "456"
    assert mapped["user"] == "testuser"
    assert mapped["cpu_percent"] == "1.5"
    assert mapped["mem_percent"] == "2.3"
    assert mapped["vsz"] == "12345"
    assert mapped["rss"] == "6789"
    assert mapped["state"] == "S"
    assert mapped["tty"] == "pts/0"
    assert mapped["time"] == "00:01:23"
    assert mapped["args"] == "/bin/bash"


def test_ps_record_fields(target_with_ps_outputs: Target) -> None:
    """Test that all record fields are properly populated."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    records = list(plugin.ps())
    assert len(records) > 0
    
    # Check a specific record from aux output
    aux_record = next((r for r in records if r.source_file == "ps_aux.txt" and r.pid == "1"), None)
    assert aux_record is not None
    
    # Check all fields are present
    assert hasattr(aux_record, "pid")
    assert hasattr(aux_record, "ppid")
    assert hasattr(aux_record, "user")
    assert hasattr(aux_record, "uid")
    assert hasattr(aux_record, "gid")
    assert hasattr(aux_record, "command")
    assert hasattr(aux_record, "args")
    assert hasattr(aux_record, "state")
    assert hasattr(aux_record, "tty")
    assert hasattr(aux_record, "time")
    assert hasattr(aux_record, "cpu_percent")
    assert hasattr(aux_record, "mem_percent")
    assert hasattr(aux_record, "vsz")
    assert hasattr(aux_record, "rss")
    assert hasattr(aux_record, "priority")
    assert hasattr(aux_record, "nice")
    assert hasattr(aux_record, "start_time")
    assert hasattr(aux_record, "elapsed_time")
    assert hasattr(aux_record, "wchan")
    assert hasattr(aux_record, "flags")
    assert hasattr(aux_record, "arguments")
    assert hasattr(aux_record, "source_file")
    assert hasattr(aux_record, "raw_data")
    
    # Check field types
    assert isinstance(aux_record.pid, str)
    assert isinstance(aux_record.arguments, list)
    assert isinstance(aux_record.raw_data, str)
    
    # Check that raw_data contains original parsed columns as JSON
    import json
    raw_data_dict = json.loads(aux_record.raw_data)
    assert "USER" in raw_data_dict
    assert "PID" in raw_data_dict
    assert "COMMAND" in raw_data_dict


def test_ps_error_handling(target_with_ps_outputs: Target) -> None:
    """Test error handling in parsing."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Test parsing lines with no header
    malformed_lines = [
        "this is not a valid ps output",
        "no header here",
        "1234 pts/0 bash",
    ]
    
    arguments = {"arguments": []}
    records = list(plugin.parse_command_output(malformed_lines, arguments))
    
    # Should handle malformed lines gracefully
    assert len(records) == 0  # No valid records from malformed data


def test_ps_normalize_column_name(target_with_ps_outputs: Target) -> None:
    """Test column name normalization."""
    parser = LinuxTableCommandParser()
    
    assert parser.normalize_column_name("PID") == "pid"
    assert parser.normalize_column_name("%CPU") == "cpu"
    assert parser.normalize_column_name("%MEM") == "mem"
    assert parser.normalize_column_name("COMMAND") == "command"
    assert parser.normalize_column_name("USER-NAME") == "user_name"
    assert parser.normalize_column_name("__TEST__") == "test"


def test_ps_header_driven_parsing(target_with_ps_outputs: Target) -> None:
    """Test that parsing works purely based on headers, regardless of parameters."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Test comprehensive column mapping
    test_mappings = [
        # Basic mappings
        ("PID", "pid"),
        ("PPID", "ppid"),
        ("USER", "user"),
        ("EUSER", "user"),
        ("RUSER", "ruser"),
        ("UID", "uid"),
        ("EUID", "uid"),
        ("RUID", "ruid"),
        ("GID", "gid"),
        ("EGID", "gid"),
        ("RGID", "rgid"),
        
        # Command variations
        ("CMD", "command"),
        ("COMMAND", "args"),
        ("COMM", "command"),
        ("ARGS", "args"),
        ("UCMD", "command"),
        ("EXE", "command"),
        
        # State variations
        ("STAT", "state"),
        ("S", "state"),
        ("STATE", "state"),
        
        # Memory variations
        ("VSZ", "vsz"),
        ("VSIZE", "vsz"),
        ("SIZE", "vsz"),
        ("RSS", "rss"),
        ("RSSIZE", "rss"),
        ("RSZ", "rss"),
        
        # CPU variations
        ("%CPU", "cpu_percent"),
        ("PCPU", "cpu_percent"),
        ("CP", "cpu_utilization"),
        ("C", "cpu_utilization"),
        
        # Time variations
        ("TIME", "time"),
        ("CPUTIME", "time"),
        ("ETIME", "elapsed_time"),
        ("ELAPSED", "elapsed_time"),
        ("START", "start_time"),
        ("STARTED", "start_time"),
        ("LSTART", "start_time"),
        ("STIME", "start_time"),
        
        # Priority variations
        ("PRI", "priority"),
        ("PRIORITY", "priority"),
        ("OPRI", "priority"),
        ("NI", "nice"),
        ("NICE", "nice"),
        
        # Other variations
        ("TTY", "tty"),
        ("TT", "tty"),
        ("TNAME", "tty"),
        ("WCHAN", "wchan"),
        ("ADDR", "wchan"),
        ("F", "flags"),
        ("FLAGS", "flags"),
        ("FLAG", "flags"),
        ("PGID", "pgid"),
        ("SID", "sid"),
        ("SESS", "sid"),
    ]
    
    # Test that all mappings work correctly
    for header, expected_field in test_mappings:
        test_row = {header: "test_value"}
        mapped = plugin.map_columns_to_fields(test_row, plugin.column_mappings)
        assert expected_field in mapped, f"Header '{header}' should map to field '{expected_field}'"
        assert mapped[expected_field] == "test_value", f"Header '{header}' mapping failed"
    
    # Test that the parser handles unknown columns gracefully
    unknown_row = {"UNKNOWN_COLUMN": "value", "PID": "123"}
    mapped = plugin.map_columns_to_fields(unknown_row, plugin.column_mappings)
    assert "pid" in mapped
    assert mapped["pid"] == "123"
    # Unknown columns should be preserved (normalized to lowercase)
    assert "unknown_column" in mapped
    assert mapped["unknown_column"] == "value"


def test_ps_parameter_agnostic_parsing(target_with_ps_outputs: Target) -> None:
    """Test that parsing works the same regardless of filename parameters."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Get records from different format files
    all_records = list(plugin.ps())
    
    # Group records by source file
    records_by_file = {}
    for record in all_records:
        source = record.source_file
        if source not in records_by_file:
            records_by_file[source] = []
        records_by_file[source].append(record)
    
    # Verify that each file produces valid records with populated fields
    for source_file, records in records_by_file.items():
        assert len(records) > 0, f"No records found for {source_file}"
        
        # Check that at least some core fields are populated
        for record in records:
            # Every record should have a PID (most basic ps field)
            assert hasattr(record, 'pid'), f"Record from {source_file} missing pid field"
            
            # Verify that the record has all expected fields (even if empty)
            expected_fields = [
                'pid', 'ppid', 'user', 'uid', 'gid', 'command', 'args', 'state',
                'tty', 'time', 'cpu_percent', 'mem_percent', 'vsz', 'rss',
                'priority', 'nice', 'start_time', 'elapsed_time', 'wchan', 'flags',
                'pgid', 'sid', 'tpgid', 'ruid', 'rgid', 'cpu_utilization',
                'arguments', 'source_file', 'raw_data'
            ]
            
            for field in expected_fields:
                assert hasattr(record, field), f"Record from {source_file} missing field: {field}"
            
            # Verify metadata fields
            assert record.source_file == source_file
            assert record.raw_data  # Should contain JSON data
            
            # Verify that raw_data is valid JSON
            import json
            try:
                raw_data = json.loads(record.raw_data)
                assert isinstance(raw_data, dict), "raw_data should be a JSON object"
            except json.JSONDecodeError:
                assert False, f"Invalid JSON in raw_data for {source_file}"


def test_ps_custom_column_order(target_with_ps_outputs: Target) -> None:
    """Test parsing with unusual column ordering to verify header-driven approach."""
    plugin = PsCommandPlugin(target_with_ps_outputs)
    
    # Get records from the custom order file
    all_records = list(plugin.ps())
    custom_records = [r for r in all_records if r.source_file == "ps_custom_order.txt"]
    
    assert len(custom_records) == 5
    
    # Check that the parser correctly mapped columns despite unusual order
    # The test file has: COMMAND USER PID PPID RSS %CPU STAT TTY TIME
    
    # Check init process
    init_record = next((r for r in custom_records if r.pid == "1"), None)
    assert init_record is not None
    assert init_record.pid == "1"
    assert init_record.ppid == "0"
    assert init_record.user == "root"
    assert init_record.args == "/sbin/init"  # COMMAND maps to args
    assert init_record.rss == "1516"
    assert init_record.cpu_percent == "0.0"
    assert init_record.state == "Ss"
    assert init_record.tty == "?"
    assert init_record.time == "0:01"
    
    # Check user process
    bash_record = next((r for r in custom_records if r.pid == "1234"), None)
    assert bash_record is not None
    assert bash_record.pid == "1234"
    assert bash_record.ppid == "456"
    assert bash_record.user == "user"
    assert bash_record.args == "bash"  # COMMAND maps to args
    assert bash_record.rss == "2048"
    assert bash_record.cpu_percent == "1.5"
    assert bash_record.state == "S"
    assert bash_record.tty == "pts/0"
    assert bash_record.time == "0:05"
    
    # Check python process
    python_record = next((r for r in custom_records if r.pid == "5678"), None)
    assert python_record is not None
    assert python_record.args == "python3"
    assert python_record.cpu_percent == "5.2"
    assert python_record.state == "R"
    
    # Verify that fields not in this format are empty
    assert init_record.vsz == ""  # Not in this format
    assert init_record.mem_percent == ""  # Not in this format
    assert init_record.command == ""  # No CMD column in this format 