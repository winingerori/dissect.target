# RegexPlugin Documentation

## Overview

The `RegexPlugin` is a base plugin class that provides regex pattern parsing capabilities with caching and convenience methods. It's designed to reduce boilerplate code for plugins that need regex functionality while maintaining consistency with the existing plugin architecture.

## Key Features

- **Pattern Caching**: Regex patterns are compiled once and cached for performance
- **Convenient Methods**: Provides common regex operations (match, search, findall, etc.)
- **Type Safety**: Full type hints following project standards
- **Error Handling**: Proper error handling with logging
- **Plugin Integration**: Seamlessly integrates with the existing plugin system
- **Flexible Pattern Management**: Add, remove, and manage patterns dynamically

## Basic Usage

### Inheriting from RegexPlugin

```python
from dissect.target.helpers.regex import RegexPlugin
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export

class MyLogParser(RegexPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        
        # Add patterns during initialization
        self.add_patterns({
            "timestamp": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            "level": r"(INFO|WARN|ERROR|DEBUG)",
            "ip_address": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        })
```

## Pattern Management

### Adding Patterns

```python
# Add a single pattern
self.add_pattern("email", r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")

# Add multiple patterns at once
self.add_patterns({
    "number": r"(\d+)",
    "word": r"(\w+)",
    "uuid": r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
})

# Add pattern with flags
self.add_pattern("case_insensitive", r"test", re.IGNORECASE)
```

### Pattern Information

```python
# Check if pattern exists
if self.has_pattern("timestamp"):
    # Use the pattern

# List all pattern names
patterns = self.list_patterns()

# Get compiled pattern object
pattern = self.get_pattern("timestamp")

# Remove a pattern
self.remove_pattern("old_pattern")

# Clear all patterns
self.clear_patterns()
```

## Regex Operations

### Matching

```python
# Match from beginning of string
match = self.match("timestamp", line)
if match:
    timestamp = match.group(1)

# Search anywhere in string
match = self.search("ip_address", text)
if match:
    ip = match.group(1)
```

### Finding Multiple Matches

```python
# Find all matches as strings
numbers = self.findall("number", "123 abc 456 def 789")
# Returns: ["123", "456", "789"]

# Find all matches as match objects (with positions)
for match in self.finditer("ip_address", log_text):
    ip = match.group(1)
    position = match.start()
```

### Text Processing

```python
# Replace matches
cleaned = self.replace("number", "abc123def", "X")
# Returns: "abcXdef"

# Split by pattern
parts = self.split("delimiter", "a,b,c")
# Returns: ["a", "b", "c"]
```

## Real-World Example: Log Parser

```python
from datetime import datetime
from typing import Iterator
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.regex import RegexPlugin
from dissect.target.plugin import export

# Define record structure
LogEntryRecord = TargetRecordDescriptor(
    "system/log_entry",
    [
        ("datetime", "timestamp"),
        ("string", "level"),
        ("string", "message"),
        ("string", "source_ip"),
        ("path", "source"),
    ],
)

class SystemLogParser(RegexPlugin):
    """Parse system log files with structured regex patterns."""
    
    def __init__(self, target: Target):
        super().__init__(target)
        
        # Define all patterns upfront
        self.add_patterns({
            # Named groups for easy extraction
            "log_entry": r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
                        r"(?P<level>\w+) "
                        r"(?P<message>.+)",
            
            # Extract IP addresses from messages
            "ip_address": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            
            # Clean up log messages
            "clean_brackets": r"\[.*?\]",
        })

    @export(record=LogEntryRecord)
    def parse_system_logs(self) -> Iterator[LogEntryRecord]:
        """Parse system log files and extract structured data."""
        log_paths = [
            "/var/log/syslog",
            "/var/log/messages",
            "/var/log/system.log"
        ]
        
        for log_path in log_paths:
            log_file = self.target.fs.path(log_path)
            if not log_file.exists():
                continue
                
            with log_file.open("r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Use named groups for clean extraction
                    if match := self.match("log_entry", line):
                        # Extract basic fields
                        timestamp_str = match.group("timestamp")
                        level = match.group("level")
                        message = match.group("message")
                        
                        # Clean up message
                        clean_message = self.replace("clean_brackets", message, "")
                        
                        # Extract IP if present
                        source_ip = None
                        if ip_match := self.search("ip_address", message):
                            source_ip = ip_match.group(1)
                        
                        # Parse timestamp
                        try:
                            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            self.target.log.warning("Invalid timestamp: %s", timestamp_str)
                            continue
                        
                        yield LogEntryRecord(
                            timestamp=timestamp,
                            level=level,
                            message=clean_message.strip(),
                            source_ip=source_ip,
                            source=log_path,
                        )
```

## Advanced Patterns

### Using Regex Flags

```python
# Case insensitive matching
self.add_pattern("error_keywords", r"(error|exception|fail)", re.IGNORECASE)

# Multiline matching
self.add_pattern("multiline_block", r"^START.*?^END", re.MULTILINE | re.DOTALL)

# Verbose patterns for readability
self.add_pattern("complex_email", r"""
    (?P<local>[a-zA-Z0-9._%+-]+)    # Local part
    @                               # @ symbol
    (?P<domain>[a-zA-Z0-9.-]+)      # Domain
    \.                              # Dot
    (?P<tld>[a-zA-Z]{2,})          # Top level domain
""", re.VERBOSE)
```

### Named Groups

```python
# Define pattern with named groups
self.add_pattern("user_action", r"User (?P<username>\w+) performed (?P<action>\w+)")

# Extract using named groups
match = self.match("user_action", "User john performed login")
if match:
    username = match.group("username")  # "john"
    action = match.group("action")      # "login"
```

## Best Practices

### 1. Pattern Organization

```python
def __init__(self, target: Target):
    super().__init__(target)
    
    # Group related patterns logically
    self._setup_timestamp_patterns()
    self._setup_ip_patterns()
    self._setup_user_patterns()

def _setup_timestamp_patterns(self):
    """Setup patterns for various timestamp formats."""
    self.add_patterns({
        "iso_timestamp": r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",
        "syslog_timestamp": r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})",
        "apache_timestamp": r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]"
    })
```

### 2. Error Handling

```python
def safe_parse_entry(self, line: str) -> dict | None:
    """Safely parse a log entry with error handling."""
    try:
        if match := self.match("log_entry", line):
            return {
                "timestamp": match.group("timestamp"),
                "level": match.group("level"),
                "message": match.group("message")
            }
    except Exception as e:
        self.target.log.warning("Failed to parse line: %s - %s", line, e)
    
    return None
```

### 3. Performance Considerations

```python
def __init__(self, target: Target):
    super().__init__(target)
    
    # Add all patterns during initialization for best performance
    # Patterns are compiled once and cached
    self.add_patterns({
        # All your patterns here
    })

def process_large_file(self, file_path: str):
    """Process large files efficiently."""
    # Use finditer for memory efficiency with large files
    with self.target.fs.path(file_path).open("r") as fh:
        content = fh.read()
        
        # Process matches one at a time instead of loading all into memory
        for match in self.finditer("log_entry", content):
            yield self._process_match(match)
```

### 4. Testing Your Plugin

```python
def test_my_log_parser(target_bare):
    """Test the log parser plugin."""
    plugin = MyLogParser(target_bare)
    
    # Test individual patterns
    test_line = "2023-01-15 10:30:45 INFO User logged in"
    assert plugin.match("log_entry", test_line) is not None
    
    # Test extraction
    match = plugin.match("log_entry", test_line)
    assert match.group("timestamp") == "2023-01-15 10:30:45"
    assert match.group("level") == "INFO"
```

## Migration from Traditional Regex

### Before (Traditional Approach)

```python
import re

# Module-level patterns (scattered throughout file)
TIMESTAMP_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")
LEVEL_PATTERN = re.compile(r"(INFO|WARN|ERROR|DEBUG)")
IP_PATTERN = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

class OldLogParser(Plugin):
    def parse_logs(self):
        for line in log_lines:
            timestamp_match = TIMESTAMP_PATTERN.match(line)
            level_match = LEVEL_PATTERN.search(line)
            # ... more pattern matching
```

### After (RegexPlugin Approach)

```python
class NewLogParser(RegexPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        # All patterns organized in one place
        self.add_patterns({
            "timestamp": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            "level": r"(INFO|WARN|ERROR|DEBUG)",
            "ip_address": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        })

    def parse_logs(self):
        for line in log_lines:
            timestamp_match = self.match("timestamp", line)
            level_match = self.search("level", line)
            # ... cleaner pattern usage
```

## Common Patterns Library

Here are some commonly used patterns you can copy into your plugins:

```python
COMMON_PATTERNS = {
    # Timestamps
    "iso_timestamp": r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)",
    "unix_timestamp": r"(\d{10}(?:\.\d+)?)",
    "syslog_timestamp": r"(\w{3} \d{1,2} \d{2}:\d{2}:\d{2})",
    
    # Network
    "ipv4": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    "ipv6": r"([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})",
    "mac_address": r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}",
    "port": r"(:(\d{1,5}))",
    "url": r"(https?://[^\s]+)",
    
    # Identifiers
    "uuid": r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "email": r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    "username": r"([a-zA-Z0-9._-]+)",
    
    # File paths
    "windows_path": r"([A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*)",
    "unix_path": r"(/(?:[^/\s]+/)*[^/\s]*)",
    
    # Log levels
    "log_level": r"(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)",
    
    # Numbers
    "integer": r"(\d+)",
    "float": r"(\d+\.\d+)",
    "hex": r"(0x[0-9a-fA-F]+)",
}
```

## API Reference

### RegexPlugin Methods

#### Pattern Management
- `add_pattern(name: str, pattern: str, flags: int = 0) -> None`
- `add_patterns(patterns: dict[str, str], flags: int = 0) -> None`
- `remove_pattern(name: str) -> bool`
- `clear_patterns() -> None`
- `has_pattern(name: str) -> bool`
- `list_patterns() -> list[str]`
- `get_pattern(name: str) -> re.Pattern | None`

#### Regex Operations
- `match(name: str, text: str) -> re.Match | None`
- `search(name: str, text: str) -> re.Match | None`
- `findall(name: str, text: str) -> list`
- `finditer(name: str, text: str) -> Iterator[re.Match]`
- `replace(name: str, text: str, repl: str) -> str`
- `split(name: str, text: str, maxsplit: int = 0) -> list[str]`

All methods raise `KeyError` if the pattern name doesn't exist.

## Troubleshooting

### Common Issues

1. **Pattern not found error**: Make sure you've added the pattern before using it
2. **Invalid regex**: Check your regex syntax, especially escape sequences
3. **Performance issues**: Add patterns during `__init__`, not during processing
4. **Import errors**: Make sure to import from `dissect.target.helpers.regex`

### Debugging Tips

```python
# Check what patterns are available
self.target.log.debug("Available patterns: %s", self.list_patterns())

# Test pattern compilation
try:
    self.add_pattern("test", r"invalid[regex")
except re.error as e:
    self.target.log.error("Invalid regex: %s", e)

# Log match results for debugging
match = self.search("pattern", text)
if match:
    self.target.log.debug("Match found: %s at position %d", match.group(), match.start())
```

This documentation provides a comprehensive guide for using the RegexPlugin effectively while following the project's standards and best practices. 