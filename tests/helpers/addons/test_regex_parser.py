from __future__ import annotations

import re
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.addons.regex import RegexPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


class MockRegexPlugin(RegexPlugin):
    """Mock plugin that inherits from RegexPlugin for testing."""
    
    def __init__(self, target: Target):
        super().__init__(target)


def test_regex_plugin_initialization(target_bare: Target) -> None:
    """Test that RegexPlugin initializes correctly."""
    plugin = MockRegexPlugin(target_bare)
    
    assert plugin._patterns == {}
    assert plugin._flags == 0
    assert plugin.list_patterns() == []


def test_add_pattern(target_bare: Target) -> None:
    """Test adding a single pattern."""
    plugin = MockRegexPlugin(target_bare)
    
    plugin.add_pattern("test", r"(\d+)")
    
    assert "test" in plugin._patterns
    assert plugin.has_pattern("test")
    assert plugin.get_pattern("test") is not None


def test_add_patterns(target_bare: Target) -> None:
    """Test adding multiple patterns at once."""
    plugin = MockRegexPlugin(target_bare)
    
    patterns = {
        "number": r"(\d+)",
        "word": r"(\w+)",
        "email": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    }
    
    plugin.add_patterns(patterns)
    
    for name in patterns:
        assert plugin.has_pattern(name)
        assert plugin.get_pattern(name) is not None


def test_add_pattern_with_flags(target_bare: Target) -> None:
    """Test adding a pattern with flags."""
    plugin = MockRegexPlugin(target_bare)
    
    plugin.add_pattern("case_insensitive", r"test", re.IGNORECASE)
    
    pattern = plugin.get_pattern("case_insensitive")
    assert pattern is not None
    assert pattern.flags & re.IGNORECASE


def test_add_pattern_overwrite_warning(target_bare: Target) -> None:
    """Test that overwriting a pattern logs a warning."""
    plugin = MockRegexPlugin(target_bare)
    
    plugin.add_pattern("test", r"(\d+)")
    plugin.add_pattern("test", r"(\w+)")  # Overwrite
    
    # Should have the new pattern
    assert plugin.get_pattern("test").pattern == r"(\w+)"


def test_add_invalid_pattern(target_bare: Target) -> None:
    """Test that adding an invalid pattern raises an error."""
    plugin = MockRegexPlugin(target_bare)
    
    with pytest.raises(re.error):
        plugin.add_pattern("invalid", r"([unclosed")


def test_match_success(target_bare: Target) -> None:
    """Test successful pattern matching."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    match = plugin.match("number", "123abc")
    assert match is not None
    assert match.group(1) == "123"


def test_match_failure(target_bare: Target) -> None:
    """Test failed pattern matching."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    match = plugin.match("number", "abc")
    assert match is None


def test_match_nonexistent_pattern(target_bare: Target) -> None:
    """Test that matching a nonexistent pattern raises KeyError."""
    plugin = MockRegexPlugin(target_bare)
    
    with pytest.raises(KeyError, match="Pattern 'nonexistent' not found"):
        plugin.match("nonexistent", "test")


def test_search_success(target_bare: Target) -> None:
    """Test successful pattern searching."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    match = plugin.search("number", "abc123def")
    assert match is not None
    assert match.group(1) == "123"


def test_search_failure(target_bare: Target) -> None:
    """Test failed pattern searching."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    match = plugin.search("number", "abcdef")
    assert match is None


def test_findall(target_bare: Target) -> None:
    """Test finding all matches."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    matches = plugin.findall("number", "123abc456def789")
    assert matches == ["123", "456", "789"]


def test_finditer(target_bare: Target) -> None:
    """Test finding all matches as iterator."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    matches = list(plugin.finditer("number", "123abc456def789"))
    assert len(matches) == 3
    assert matches[0].group(1) == "123"
    assert matches[1].group(1) == "456"
    assert matches[2].group(1) == "789"


def test_replace(target_bare: Target) -> None:
    """Test pattern replacement."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    result = plugin.replace("number", "abc123def456", "X")
    assert result == "abcXdefX"


def test_replace_all(target_bare: Target) -> None:
    """Test replacing all matches."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("number", r"(\d+)")
    
    result = plugin.replace_all("number", "abc123def456", "X")
    assert result == "abcXdefX"


def test_split(target_bare: Target) -> None:
    """Test splitting by pattern."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("delimiter", r"\s+")
    
    result = plugin.split("delimiter", "a  b   c")
    assert result == ["a", "b", "c"]


def test_split_with_maxsplit(target_bare: Target) -> None:
    """Test splitting with maxsplit limit."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("delimiter", r"\s+")
    
    result = plugin.split("delimiter", "a  b   c", maxsplit=1)
    assert result == ["a", "b   c"]


def test_get_pattern(target_bare: Target) -> None:
    """Test getting a pattern by name."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("test", r"(\d+)")
    
    pattern = plugin.get_pattern("test")
    assert pattern is not None
    assert pattern.pattern == r"(\d+)"
    
    # Test getting nonexistent pattern
    assert plugin.get_pattern("nonexistent") is None


def test_has_pattern(target_bare: Target) -> None:
    """Test checking if a pattern exists."""
    plugin = MockRegexPlugin(target_bare)
    
    assert not plugin.has_pattern("test")
    
    plugin.add_pattern("test", r"(\d+)")
    assert plugin.has_pattern("test")


def test_list_patterns(target_bare: Target) -> None:
    """Test listing all pattern names."""
    plugin = MockRegexPlugin(target_bare)
    
    assert plugin.list_patterns() == []
    
    plugin.add_patterns({
        "number": r"(\d+)",
        "word": r"(\w+)",
        "email": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    })
    
    patterns = plugin.list_patterns()
    assert len(patterns) == 3
    assert "number" in patterns
    assert "word" in patterns
    assert "email" in patterns


def test_remove_pattern(target_bare: Target) -> None:
    """Test removing a pattern."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("test", r"(\d+)")
    
    assert plugin.has_pattern("test")
    
    # Remove existing pattern
    assert plugin.remove_pattern("test") is True
    assert not plugin.has_pattern("test")
    
    # Remove nonexistent pattern
    assert plugin.remove_pattern("nonexistent") is False


def test_clear_patterns(target_bare: Target) -> None:
    """Test clearing all patterns."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_patterns({
        "number": r"(\d+)",
        "word": r"(\w+)",
        "email": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})"
    })
    
    assert len(plugin.list_patterns()) == 3
    
    plugin.clear_patterns()
    assert len(plugin.list_patterns()) == 0


def test_named_groups(target_bare: Target) -> None:
    """Test using named groups in patterns."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("log_entry", r"(?P<timestamp>\d{4}-\d{2}-\d{2}) (?P<level>\w+) (?P<message>.+)")
    
    match = plugin.match("log_entry", "2023-01-15 INFO Test message")
    assert match is not None
    assert match.group("timestamp") == "2023-01-15"
    assert match.group("level") == "INFO"
    assert match.group("message") == "Test message"


def test_case_insensitive_matching(target_bare: Target) -> None:
    """Test case insensitive pattern matching."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("word", r"test", re.IGNORECASE)
    
    # Should match regardless of case
    assert plugin.match("word", "TEST") is not None
    assert plugin.match("word", "test") is not None
    assert plugin.match("word", "Test") is not None


def test_multiline_matching(target_bare: Target) -> None:
    """Test multiline pattern matching."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("line_start", r"^start", re.MULTILINE)
    
    text = "start line 1\nmiddle line\nstart line 2"
    matches = list(plugin.finditer("line_start", text))
    assert len(matches) == 2


def test_dotall_matching(target_bare: Target) -> None:
    """Test dotall pattern matching."""
    plugin = MockRegexPlugin(target_bare)
    plugin.add_pattern("multiline", r"start.*end", re.DOTALL)
    
    text = "start\nmiddle\nend"
    match = plugin.search("multiline", text)
    assert match is not None
    assert match.group(0) == "start\nmiddle\nend"


def test_plugin_inheritance_compatibility(target_bare: Target) -> None:
    """Test that RegexPlugin works correctly with plugin inheritance."""
    plugin = MockRegexPlugin(target_bare)
    
    # Should have all the standard plugin attributes
    assert hasattr(plugin, 'target')
    assert hasattr(plugin, 'is_compatible')
    assert hasattr(plugin, 'check_compatible')
    
    # Should work with regex functionality
    plugin.add_pattern("test", r"(\d+)")
    match = plugin.match("test", "123")
    assert match is not None
    assert match.group(1) == "123"


def test_error_handling_for_nonexistent_patterns(target_bare: Target) -> None:
    """Test that all methods properly handle nonexistent patterns."""
    plugin = MockRegexPlugin(target_bare)
    
    methods = [
        ("match", ["nonexistent", "test"]),
        ("search", ["nonexistent", "test"]),
        ("findall", ["nonexistent", "test"]),
        ("finditer", ["nonexistent", "test"]),
        ("replace", ["nonexistent", "test", "replacement"]),
        ("replace_all", ["nonexistent", "test", "replacement"]),
        ("split", ["nonexistent", "test"]),
    ]
    
    for method_name, args in methods:
        method = getattr(plugin, method_name)
        with pytest.raises(KeyError, match="Pattern 'nonexistent' not found"):
            method(*args) 