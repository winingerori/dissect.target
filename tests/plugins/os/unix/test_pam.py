from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.pam import PamPlugin
from dissect.target.target import Target
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_pam_conf_format(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test parsing /etc/pam.conf format configuration."""
    pam_conf_file = absolute_path("_data/plugins/os/unix/pam/pam.conf")
    fs_unix.map_file("/etc/pam.conf", pam_conf_file)

    target_unix.add_plugin(PamPlugin)
    results = list(target_unix.pam_modules())

    # Should have parsed multiple entries from pam.conf
    assert len(results) > 20
    
    # Test specific entries
    other_auth = [r for r in results if r.service == "OTHER" and r.module_type == "auth"][0]
    assert other_auth.service == "OTHER"
    assert other_auth.module_type == "auth"
    assert other_auth.control_flag == "required"
    assert other_auth.module_path == "pam_deny.so"
    assert other_auth.module_name == "pam_deny.so"
    assert other_auth.arguments == []
    assert "/etc/pam.conf" in str(other_auth.config_file)

    # Test SSH authentication with arguments
    sshd_auth = [r for r in results if r.service == "sshd" and r.module_type == "auth" and r.module_name == "pam_unix.so"][0]
    assert sshd_auth.service == "sshd"
    assert sshd_auth.module_type == "auth"
    assert sshd_auth.control_flag == "required"
    assert sshd_auth.module_path == "pam_unix.so"
    assert sshd_auth.module_name == "pam_unix.so"
    assert sshd_auth.arguments == ["nullok"]

    # Test complex control flag
    login_auth = [r for r in results if r.service == "login" and "[success=ok" in r.control_flag][0]
    assert login_auth.service == "login"
    assert login_auth.module_type == "auth"
    assert login_auth.control_flag == "[success=ok new_authtok_reqd=ok ignore=ignore default=bad]"
    assert login_auth.module_name == "pam_unix.so"
    assert login_auth.arguments == ["nullok"]

    # Test module with absolute path
    custom_auth = [r for r in results if r.service == "custom"][0]
    assert custom_auth.service == "custom"
    assert custom_auth.module_path == "/usr/local/lib/security/pam_custom.so"
    assert custom_auth.module_name == "pam_custom.so"
    assert custom_auth.arguments == ["debug", "verbose"]

    # Test MySQL module with complex arguments
    mysql_auth = [r for r in results if r.service == "mysqld"][0]
    assert mysql_auth.service == "mysqld"
    assert mysql_auth.module_name == "pam_mysql.so"
    assert "user=passwd_query" in mysql_auth.arguments
    assert any("[query=" in arg for arg in mysql_auth.arguments)


def test_pam_d_format(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test parsing /etc/pam.d/ format configuration files."""
    # Map the test files
    common_auth_file = absolute_path("_data/plugins/os/unix/pam/pam.d/common-auth")
    sshd_file = absolute_path("_data/plugins/os/unix/pam/pam.d/sshd")
    sudo_file = absolute_path("_data/plugins/os/unix/pam/pam.d/sudo")
    
    fs_unix.map_file("/etc/pam.d/common-auth", common_auth_file)
    fs_unix.map_file("/etc/pam.d/sshd", sshd_file)
    fs_unix.map_file("/etc/pam.d/sudo", sudo_file)

    target_unix.add_plugin(PamPlugin)
    results = list(target_unix.pam_modules())

    # Should have parsed multiple entries from all pam.d files
    assert len(results) > 10

    # Test common-auth entries
    common_auth_results = [r for r in results if r.service == "common-auth"]
    assert len(common_auth_results) == 3  # Should find 3 non-comment lines
    
    unix_auth = [r for r in common_auth_results if r.module_name == "pam_unix.so"][0]
    assert unix_auth.service == "common-auth"
    assert unix_auth.module_type == "auth"
    assert unix_auth.control_flag == "[success=1 default=ignore]"
    assert unix_auth.module_name == "pam_unix.so"
    assert unix_auth.arguments == ["nullok"]

    # Test sshd entries 
    sshd_results = [r for r in results if r.service == "sshd"]
    assert len(sshd_results) > 5  # Should have multiple entries

    nologin_entry = [r for r in sshd_results if r.module_name == "pam_nologin.so"][0]
    assert nologin_entry.service == "sshd"
    assert nologin_entry.module_type == "account"
    assert nologin_entry.control_flag == "required"
    assert nologin_entry.module_name == "pam_nologin.so"

    # Test sudo entries
    sudo_results = [r for r in results if r.service == "sudo"]
    assert len(sudo_results) > 3

    rootok_entry = [r for r in sudo_results if r.module_name == "pam_rootok.so"][0]
    assert rootok_entry.service == "sudo"
    assert rootok_entry.module_type == "auth"
    assert rootok_entry.control_flag == "sufficient"
    assert rootok_entry.module_name == "pam_rootok.so"


def test_pam_both_formats(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test that both pam.conf and pam.d formats are parsed together."""
    # Map both types of configuration
    pam_conf_file = absolute_path("_data/plugins/os/unix/pam/pam.conf")
    common_auth_file = absolute_path("_data/plugins/os/unix/pam/pam.d/common-auth")
    
    fs_unix.map_file("/etc/pam.conf", pam_conf_file)
    fs_unix.map_file("/etc/pam.d/common-auth", common_auth_file)

    target_unix.add_plugin(PamPlugin)
    results = list(target_unix.pam_modules())

    # Should have results from both pam.conf and pam.d
    pam_conf_results = [r for r in results if "pam.conf" in str(r.config_file)]
    pam_d_results = [r for r in results if "pam.d" in str(r.config_file)]
    
    assert len(pam_conf_results) > 20
    assert len(pam_d_results) == 3
    assert len(results) == len(pam_conf_results) + len(pam_d_results)


def test_pam_module_extraction() -> None:
    """Test the _extract_module_name method."""
    target = Target.open("/dev/null")
    plugin = PamPlugin(target)
    
    # Test .so module extraction
    assert plugin._extract_module_name("pam_unix.so") == "pam_unix.so"
    assert plugin._extract_module_name("/lib/security/pam_unix.so") == "pam_unix.so"
    assert plugin._extract_module_name("/usr/lib64/security/pam_krb5.so") == "pam_krb5.so"
    
    # Test non-.so modules 
    assert plugin._extract_module_name("system-auth") == "system-auth"
    assert plugin._extract_module_name("/etc/pam.d/common-auth") == "common-auth"


def test_pam_argument_parsing() -> None:
    """Test the _parse_arguments method."""
    target = Target.open("/dev/null")
    plugin = PamPlugin(target)
    
    # Test simple arguments
    assert plugin._parse_arguments("nullok") == ["nullok"]
    assert plugin._parse_arguments("nullok obscure min=4 max=8") == ["nullok", "obscure", "min=4", "max=8"]
    
    # Test empty arguments
    assert plugin._parse_arguments("") == []
    assert plugin._parse_arguments(None) == []
    
    # Test complex arguments with brackets
    complex_args = "user=passwd_query passwd=mada db=eminence [query=select user_name from table where user='%u']"
    expected = ["user=passwd_query", "passwd=mada", "db=eminence", "[query=select user_name from table where user='%u']"]
    assert plugin._parse_arguments(complex_args) == expected
    
    # Test multiple bracket groups
    multi_bracket = "arg1 [bracket1 content] arg2 [bracket2 content] arg3"
    expected = ["arg1", "[bracket1 content]", "arg2", "[bracket2 content]", "arg3"]
    assert plugin._parse_arguments(multi_bracket) == expected


def test_pam_no_config_files(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test behavior when no PAM configuration files exist."""
    target_unix.add_plugin(PamPlugin)
    results = list(target_unix.pam_modules())
    
    # Should return empty list when no config files exist
    assert len(results) == 0


def test_pam_empty_config_file(target_unix: Target, fs_unix: VirtualFilesystem, tmp_path) -> None:
    """Test behavior with empty configuration file."""
    empty_file = tmp_path / "empty_pam.conf"
    empty_file.write_text("")
    
    fs_unix.map_file("/etc/pam.conf", empty_file)
    
    target_unix.add_plugin(PamPlugin)
    results = list(target_unix.pam_modules())
    
    # Should return empty list for empty config file
    assert len(results) == 0


def test_pam_comments_and_whitespace(target_unix: Target, fs_unix: VirtualFilesystem, tmp_path) -> None:
    """Test that comments and whitespace are properly ignored."""
    test_content = """
# This is a comment
   # Another comment with whitespace

# Valid entry after comments
sshd    auth    required    pam_unix.so    nullok
    
    # More comments and whitespace
    
    # Another valid entry  
    login   auth    sufficient  pam_krb5.so
"""
    
    test_file = tmp_path / "test_pam.conf"
    test_file.write_text(test_content)
    
    fs_unix.map_file("/etc/pam.conf", test_file)
    
    target_unix.add_plugin(PamPlugin)
    results = list(target_unix.pam_modules())
    
    # Should only parse the 2 non-comment lines
    assert len(results) == 2
    
    services = [r.service for r in results]
    assert "sshd" in services
    assert "login" in services


@pytest.mark.parametrize(
    ("config_line", "expected_service", "expected_module", "expected_args"),
    [
        # Basic pam.conf line
        ("sshd auth required pam_unix.so nullok", "sshd", "pam_unix.so", ["nullok"]),
        
        # Complex control flag
        ("login auth [success=ok default=bad] pam_unix.so", "login", "pam_unix.so", []),
        
        # Multiple arguments
        ("ftpd auth required pam_listfile.so onerr=succeed item=user sense=deny", "ftpd", "pam_listfile.so", 
         ["onerr=succeed", "item=user", "sense=deny"]),
        
        # No arguments
        ("OTHER session required pam_deny.so", "OTHER", "pam_deny.so", []),
        
        # Absolute path module
        ("custom auth required /usr/local/lib/pam_custom.so debug", "custom", "pam_custom.so", ["debug"]),
    ],
)
def test_pam_line_parsing(
    target_unix: Target, 
    fs_unix: VirtualFilesystem, 
    tmp_path,
    config_line: str,
    expected_service: str,
    expected_module: str,
    expected_args: list[str]
) -> None:
    """Test parsing of individual PAM configuration lines."""
    test_file = tmp_path / "test_pam.conf"
    test_file.write_text(config_line)
    
    fs_unix.map_file("/etc/pam.conf", test_file)
    
    target_unix.add_plugin(PamPlugin)
    results = list(target_unix.pam_modules())
    
    assert len(results) == 1
    result = results[0]
    
    assert result.service == expected_service
    assert result.module_name == expected_module
    assert result.arguments == expected_args 