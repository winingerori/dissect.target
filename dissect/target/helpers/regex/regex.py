from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Iterator

from dissect.target.plugin import Plugin

if TYPE_CHECKING:
    from collections.abc import Sequence

    from dissect.target.target import Target


class RegexPlugin(Plugin):
    """Base plugin class that provides regex pattern parsing capabilities.
    
    This plugin provides convenient regex pattern matching and caching
    functionality that can be inherited by other plugins to reduce
    boilerplate code.
    
    Example:
        class MyLogParser(RegexPlugin):
            def __init__(self, target: Target):
                super().__init__(target)
                self.add_patterns({
                    "timestamp": r"(\d{4}-\d{2}-\d{2})",
                    "ip_address": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
                })
            
            @export(record=LogRecord)
            def parse_logs(self) -> Iterator[Record]:
                for line in self.target.fs.path("/var/log/example.log").open():
                    if match := self.match("timestamp", line):
                        # ...
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self._patterns: dict[str, re.Pattern] = {}
        self._flags: int = 0

    def add_pattern(self, name: str, pattern: str, flags: int = 0) -> None:
        """Add a named pattern to the plugin.
        
        Args:
            name: The name to identify this pattern.
            pattern: The regex pattern string.
            flags: Regex flags to use when compiling the pattern.
        """
        if name in self._patterns:
            self.target.log.warning("Pattern '%s' already exists, overwriting", name)
        
        try:
            self._patterns[name] = re.compile(pattern, flags)
        except re.error as e:
            self.target.log.error("Invalid regex pattern '%s': %s", pattern, e)
            raise

    def add_patterns(self, patterns: dict[str, str], flags: int = 0) -> None:
        """Add multiple patterns at once.
        
        Args:
            patterns: Dictionary mapping pattern names to regex strings.
            flags: Regex flags to use when compiling all patterns.
        """
        for name, pattern in patterns.items():
            self.add_pattern(name, pattern, flags)

    def match(self, name: str, text: str) -> re.Match | None:
        """Match a pattern against text.
        
        Args:
            name: The name of the pattern to use.
            text: The text to match against.
            
        Returns:
            A match object if the pattern matches, None otherwise.
            
        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")
        
        return self._patterns[name].match(text)

    def search(self, name: str, text: str) -> re.Match | None:
        """Search for a pattern in text.
        
        Args:
            name: The name of the pattern to use.
            text: The text to search in.
            
        Returns:
            A match object if the pattern is found, None otherwise.
            
        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")
        
        return self._patterns[name].search(text)

    def findall(self, name: str, text: str) -> list:
        """Find all matches of a pattern in text.
        
        Args:
            name: The name of the pattern to use.
            text: The text to search in.
            
        Returns:
            A list of all matches found.
            
        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")
        
        return self._patterns[name].findall(text)

    def finditer(self, name: str, text: str) -> Iterator[re.Match]:
        """Find all matches as an iterator.
        
        Args:
            name: The name of the pattern to use.
            text: The text to search in.
            
        Returns:
            An iterator of match objects.
            
        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")
        
        return self._patterns[name].finditer(text)

    def replace(self, name: str, text: str, repl: str) -> str:
        """Replace matches of a pattern in text.
        
        Args:
            name: The name of the pattern to use.
            text: The text to search and replace in.
            repl: The replacement string.
            
        Returns:
            The text with replacements made.
            
        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")
        
        return self._patterns[name].sub(repl, text)

    def replace_all(self, name: str, text: str, repl: str) -> str:
        """Replace all matches of a pattern in text.
        
        Args:
            name: The name of the pattern to use.
            text: The text to search and replace in.
            repl: The replacement string.
            
        Returns:
            The text with all replacements made.
            
        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")
        
        return self._patterns[name].sub(repl, text)

    def split(self, name: str, text: str, maxsplit: int = 0) -> list[str]:
        """Split text by a pattern.
        
        Args:
            name: The name of the pattern to use.
            text: The text to split.
            maxsplit: Maximum number of splits to perform.
            
        Returns:
            A list of strings split by the pattern.
            
        Raises:
            KeyError: If the pattern name doesn't exist.
        """
        if name not in self._patterns:
            raise KeyError(f"Pattern '{name}' not found")
        
        return self._patterns[name].split(text, maxsplit)

    def get_pattern(self, name: str) -> re.Pattern | None:
        """Get a compiled pattern by name.
        
        Args:
            name: The name of the pattern.
            
        Returns:
            The compiled pattern or None if not found.
        """
        return self._patterns.get(name)

    def has_pattern(self, name: str) -> bool:
        """Check if a pattern exists.
        
        Args:
            name: The name of the pattern to check.
            
        Returns:
            True if the pattern exists, False otherwise.
        """
        return name in self._patterns

    def list_patterns(self) -> list[str]:
        """Get a list of all pattern names.
        
        Returns:
            A list of pattern names.
        """
        return list(self._patterns.keys())

    def remove_pattern(self, name: str) -> bool:
        """Remove a pattern by name.
        
        Args:
            name: The name of the pattern to remove.
            
        Returns:
            True if the pattern was removed, False if it didn't exist.
        """
        if name in self._patterns:
            del self._patterns[name]
            return True
        return False

    def clear_patterns(self) -> None:
        """Remove all patterns."""
        self._patterns.clear() 