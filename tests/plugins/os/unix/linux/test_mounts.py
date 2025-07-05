from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugins.os.unix.linux.mounts import MountsPlugin
from dissect.target.plugin import find_functions

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_mounts_plugin_success(target_linux_users: Target, fs_linux: VirtualFilesystem) -> None:
    """Test that MountsPlugin works when proc filesystem is available."""
    # Create a mock /proc/mounts file
    fs_linux.makedirs("/proc")
    mounts_content = """sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
udev /dev devtmpfs rw,nosuid,relatime 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
securityfs /sys/kernel/security securityfs rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0
"""
    fs_linux.map_file_fh("/proc/mounts", BytesIO(mounts_content.encode()))
    
    # Add the MountsPlugin
    target_linux_users.add_plugin(MountsPlugin)
    
    # Test the mounts function
    results = list(target_linux_users.mounts())
    assert len(results) == 8
    
    # Check some specific mounts
    assert results[0].source == "sysfs"
    assert results[0].target == "/sys"
    assert results[0].fstype == "sysfs"
    assert results[0].options == "rw,nosuid,nodev,noexec,relatime"
    assert results[0].dump == "0"
    assert results[0].passno == "0"
    
    assert results[5].source == "/dev/sda1"
    assert results[5].target == "/"
    assert results[5].fstype == "ext4"


def test_mounts_plugin_no_proc(target_linux_users: Target, fs_linux: VirtualFilesystem) -> None:
    """Test that MountsPlugin fails when proc filesystem is not available."""
    # Don't create /proc directory
    with pytest.raises(UnsupportedPluginError, match="proc filesystem not available"):
        target_linux_users.add_plugin(MountsPlugin)


def test_mounts_plugin_empty_proc(target_linux_users: Target, fs_linux: VirtualFilesystem) -> None:
    """Test that MountsPlugin fails when proc filesystem exists but mounts file doesn't."""
    # Create /proc directory but not /proc/mounts
    fs_linux.makedirs("/proc")
    
    target_linux_users.add_plugin(MountsPlugin)
    
    # Should fail when trying to access /proc/mounts
    with pytest.raises(FileNotFoundError):
        list(target_linux_users.mounts())


def test_mounts_plugin_malformed_line(target_linux_users: Target, fs_linux: VirtualFilesystem) -> None:
    """Test that MountsPlugin handles malformed mount lines gracefully."""
    # Create a mock /proc/mounts file with some malformed lines
    fs_linux.makedirs("/proc")
    mounts_content = """sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
this is a malformed line
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
another malformed line without enough fields
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
"""
    fs_linux.map_file_fh("/proc/mounts", BytesIO(mounts_content.encode()))
    
    # Add the MountsPlugin
    target_linux_users.add_plugin(MountsPlugin)
    
    # Test the mounts function - should only return valid lines
    results = list(target_linux_users.mounts())
    assert len(results) == 3  # Only 3 valid mount lines
    
    assert results[0].source == "sysfs"
    assert results[1].source == "proc"
    assert results[2].source == "/dev/sda1"


def test_mounts_plugin_with_escape_sequences(target_linux_users: Target, fs_linux: VirtualFilesystem) -> None:
    """Test that MountsPlugin handles paths with escape sequences."""
    # Create a mock /proc/mounts file with escape sequences in paths
    fs_linux.makedirs("/proc")
    mounts_content = r"""sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 /media/my\040folder ext4 rw,relatime 0 0
tmpfs /tmp\040with\040spaces tmpfs rw,nosuid,nodev 0 0
"""
    fs_linux.map_file_fh("/proc/mounts", BytesIO(mounts_content.encode()))
    
    # Add the MountsPlugin
    target_linux_users.add_plugin(MountsPlugin)
    
    # Test the mounts function
    results = list(target_linux_users.mounts())
    assert len(results) == 3
    
    # Check escape sequences are preserved in the raw data
    assert results[1].target == r"/media/my\040folder"
    assert results[2].target == r"/tmp\040with\040spaces"


def test_mounts_plugin_function_discovery(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    """Test that mounts function is discoverable when target is detected as Linux."""
    # Create the required Linux structure for detection
    fs_linux.makedirs("/proc")
    fs_linux.makedirs("/sys")  # Required for Linux detection
    fs_linux.makedirs("/etc")
    fs_linux.makedirs("/var")
    
    # Create a mock /proc/mounts file
    mounts_content = """sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0
"""
    fs_linux.map_file_fh("/proc/mounts", BytesIO(mounts_content.encode()))
    
    # The target should be detected as Linux and have mounts function available
    assert target_linux.os == "linux"
    
    # Test function discovery
    funcs, invalid = find_functions("mounts", target_linux)
    assert len(funcs) == 1
    assert funcs[0].name == "mounts"
    assert funcs[0].path == "os.unix.linux.mounts.mounts"
    assert len(invalid) == 0
    
    # Test that the function works
    results = list(target_linux.mounts())
    assert len(results) == 3
    assert results[0].source == "sysfs"
    assert results[1].source == "proc"
    assert results[2].source == "/dev/sda1"