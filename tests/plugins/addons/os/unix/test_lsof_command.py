import pytest
from unittest.mock import PropertyMock, patch

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.addons.os.unix.lsof_command import LsofCommandPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


@pytest.fixture
def target_unix():
    target = Target()
    target.filesystems.add(VirtualFilesystem())
    target.fs.mount("/", target.filesystems[0])
    return target


@pytest.fixture
def lsof_plugin(target_unix):
    return LsofCommandPlugin(target_unix)


def test_lsof_command_plugin_compatibility(lsof_plugin, target_unix):
    """Test plugin compatibility detection."""
    # No command files - should not be compatible
    assert not lsof_plugin.check_compatible()
    
    # Add command file - should be compatible
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    assert lsof_plugin.check_compatible()


def test_lsof_command_basic_parsing(lsof_plugin, target_unix):
    """Test basic lsof command parsing."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    assert len(records) > 0
    
    # Test first record (systemd)
    record = records[0]
    assert record.command == "systemd"
    assert record.pid == 1
    assert record.user == "root"
    assert record.fd == "cwd"
    assert record.type == "DIR"
    assert record.device == "8,1"
    assert record.size_off == "4096"
    assert record.node == "2"
    assert record.name == "/"
    assert record.source_file == "/command_outputs/lsof.txt"
    assert record.raw_data.startswith("systemd")


def test_lsof_command_network_parsing(lsof_plugin, target_unix):
    """Test lsof -i network parsing."""
    target_unix.fs.map_file("/command_outputs/lsof_-i.txt", absolute_path("_data/command_outputs/lsof_-i.txt"))
    
    records = list(lsof_plugin.lsof_command())
    assert len(records) > 0
    
    # Test SSH listening record
    ssh_record = next(r for r in records if r.command == "sshd" and r.fd == "3u")
    assert ssh_record.command == "sshd"
    assert ssh_record.pid == 845
    assert ssh_record.user == "root"
    assert ssh_record.fd == "3u"
    assert ssh_record.type == "IPv4"
    assert ssh_record.device == "12345"
    assert ssh_record.size_off == "0t0"
    assert ssh_record.name == "TCP *:22 (LISTEN)"
    
    # Test established connection
    firefox_record = next(r for r in records if r.command == "firefox" and "ESTABLISHED" in r.name)
    assert firefox_record.command == "firefox"
    assert firefox_record.pid == 1567
    assert firefox_record.user == "user"
    assert firefox_record.type == "IPv4"
    assert "ESTABLISHED" in firefox_record.name


def test_lsof_command_process_specific(lsof_plugin, target_unix):
    """Test lsof -p PID parsing."""
    target_unix.fs.map_file("/command_outputs/lsof_-p_1234.txt", absolute_path("_data/command_outputs/lsof_-p_1234.txt"))
    
    records = list(lsof_plugin.lsof_command())
    assert len(records) > 0
    
    # All records should be for vim process PID 1234
    for record in records:
        assert record.command == "vim"
        assert record.pid == 1234
        assert record.user == "user"
    
    # Test various file descriptor types
    fd_types = {r.fd for r in records}
    assert "cwd" in fd_types  # Current working directory
    assert "txt" in fd_types  # Text/executable
    assert "mem" in fd_types  # Memory mapped files
    assert any(fd.endswith("u") for fd in fd_types)  # Open files


def test_lsof_command_user_specific(lsof_plugin, target_unix):
    """Test lsof -u USER parsing."""
    target_unix.fs.map_file("/command_outputs/lsof_-u_user.txt", absolute_path("_data/command_outputs/lsof_-u_user.txt"))
    
    records = list(lsof_plugin.lsof_command())
    assert len(records) > 0
    
    # All records should be for user 'user'
    for record in records:
        assert record.user == "user"
    
    # Should have multiple processes
    commands = {r.command for r in records}
    assert len(commands) > 1
    assert "bash" in commands
    assert "vim" in commands
    assert "firefox" in commands


def test_lsof_command_file_types(lsof_plugin, target_unix):
    """Test different file types in lsof output."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Check various file types
    types = {r.type for r in records}
    assert "DIR" in types      # Directory
    assert "REG" in types      # Regular file
    assert "CHR" in types      # Character device
    assert "sock" in types     # Socket
    assert "IPv4" in types     # IPv4 socket
    assert "IPv6" in types     # IPv6 socket
    assert "FIFO" in types     # Named pipe
    assert "unix" in types     # Unix domain socket


def test_lsof_command_fd_variations(lsof_plugin, target_unix):
    """Test various file descriptor formats."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Check various FD formats
    fds = {r.fd for r in records}
    assert "cwd" in fds       # Current working directory
    assert "rtd" in fds       # Root directory
    assert "txt" in fds       # Text/executable
    assert "mem" in fds       # Memory mapped
    assert any(fd.endswith("u") for fd in fds)  # Read/write
    assert any(fd.endswith("r") for fd in fds)  # Read only
    assert any(fd.endswith("w") for fd in fds)  # Write only
    assert any(fd.isdigit() for fd in fds if fd not in ["cwd", "rtd", "txt", "mem"])  # Numeric FDs


def test_lsof_command_network_connections(lsof_plugin, target_unix):
    """Test network connection parsing."""
    target_unix.fs.map_file("/command_outputs/lsof_-i.txt", absolute_path("_data/command_outputs/lsof_-i.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Test listening sockets
    listening = [r for r in records if "LISTEN" in r.name]
    assert len(listening) > 0
    
    # Test established connections
    established = [r for r in records if "ESTABLISHED" in r.name]
    assert len(established) > 0
    
    # Test UDP sockets
    udp_sockets = [r for r in records if "UDP" in r.name]
    assert len(udp_sockets) > 0
    
    # Test IPv6 connections
    ipv6_connections = [r for r in records if r.type == "IPv6"]
    assert len(ipv6_connections) > 0


def test_lsof_command_device_formats(lsof_plugin, target_unix):
    """Test various device number formats."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Check device number formats
    devices = {r.device for r in records if r.device}
    assert any("," in dev for dev in devices)  # Major,minor format
    assert any(dev.startswith("0x") for dev in devices if dev)  # Hex format


def test_lsof_command_size_offset_formats(lsof_plugin, target_unix):
    """Test size/offset field variations."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Check size/offset formats
    size_offs = {r.size_off for r in records if r.size_off}
    assert any(so.startswith("0t") for so in size_offs)  # Offset format
    assert any(so.isdigit() for so in size_offs)  # Size format


def test_lsof_command_error_handling(lsof_plugin, target_unix):
    """Test error handling for malformed files."""
    # Create a file with invalid content
    target_unix.fs.map_file_fh("/command_outputs/lsof_invalid.txt", 
                              b"Invalid content without proper header\nmore invalid content")
    
    # Should not crash, might produce warnings
    records = list(lsof_plugin.lsof_command())
    # May be empty or contain partial data, but should not crash


def test_lsof_command_empty_file(lsof_plugin, target_unix):
    """Test handling of empty files."""
    target_unix.fs.map_file_fh("/command_outputs/lsof_empty.txt", b"")
    
    records = list(lsof_plugin.lsof_command())
    assert len(records) == 0


def test_lsof_command_header_only(lsof_plugin, target_unix):
    """Test handling of header-only files."""
    target_unix.fs.map_file_fh("/command_outputs/lsof_header_only.txt", 
                              b"COMMAND     PID USER   FD      TYPE             DEVICE   SIZE/OFF                NODE NAME\n")
    
    records = list(lsof_plugin.lsof_command())
    assert len(records) == 0


def test_lsof_command_special_names(lsof_plugin, target_unix):
    """Test parsing of special file names and paths."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Check for special file names
    names = {r.name for r in records}
    assert any("/dev/" in name for name in names)  # Device files
    assert any("/proc/" in name for name in names)  # Proc files
    assert any("type=" in name for name in names)  # Socket types
    assert any("pipe" in name for name in names)  # Pipes


def test_lsof_command_multiple_files(lsof_plugin, target_unix):
    """Test parsing multiple lsof output files."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    target_unix.fs.map_file("/command_outputs/lsof_-i.txt", absolute_path("_data/command_outputs/lsof_-i.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Should have records from both files
    sources = {r.source_file for r in records}
    assert "/command_outputs/lsof.txt" in sources
    assert "/command_outputs/lsof_-i.txt" in sources
    
    # Should have a reasonable number of records
    assert len(records) > 50  # Combined from both files


def test_lsof_command_column_mapping(lsof_plugin, target_unix):
    """Test column mapping functionality."""
    # Test that column mapping works correctly
    mapping = lsof_plugin.COLUMN_MAPPING
    
    # Standard columns
    assert mapping["COMMAND"] == "command"
    assert mapping["PID"] == "pid"
    assert mapping["USER"] == "user"
    assert mapping["FD"] == "fd"
    assert mapping["TYPE"] == "type"
    assert mapping["DEVICE"] == "device"
    assert mapping["SIZE/OFF"] == "size_off"
    assert mapping["NODE"] == "node"
    assert mapping["NAME"] == "name"
    
    # Alternative columns
    assert mapping["CMD"] == "command"
    assert mapping["SIZE"] == "size_off"
    assert mapping["OFF"] == "size_off"
    assert mapping["FILENAME"] == "name"


def test_lsof_command_data_integrity(lsof_plugin, target_unix):
    """Test data integrity and completeness."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # All records should have required fields
    for record in records:
        assert record.command is not None
        assert record.pid is not None
        assert record.user is not None
        assert record.source_file is not None
        assert record.raw_data is not None
        
        # PID should be valid integer
        assert isinstance(record.pid, int)
        assert record.pid >= 0


def test_lsof_command_forensic_context(lsof_plugin, target_unix):
    """Test forensic context preservation."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    records = list(lsof_plugin.lsof_command())
    
    # Check forensic context
    for record in records:
        # Source tracking
        assert record.source_file.startswith("/command_outputs/")
        assert record.source_file.endswith(".txt")
        
        # Raw data preservation
        assert len(record.raw_data) > 0
        assert record.command in record.raw_data


def test_lsof_command_performance(lsof_plugin, target_unix):
    """Test parsing performance with larger files."""
    target_unix.fs.map_file("/command_outputs/lsof.txt", absolute_path("_data/command_outputs/lsof.txt"))
    
    # Should parse reasonably quickly
    import time
    start = time.time()
    records = list(lsof_plugin.lsof_command())
    end = time.time()
    
    # Should complete within reasonable time
    assert end - start < 5.0  # 5 seconds max
    assert len(records) > 0 