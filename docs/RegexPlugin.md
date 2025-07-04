# RegexPlugin Documentation

## Overview

The `RegexPlugin` is a base plugin class that provides regex pattern parsing capabilities. It serves as a foundation for other plugins that need to parse text files using regular expressions, reducing boilerplate code and providing consistent regex functionality.

## Features

- **Pattern Management**: Add, remove, and manage named regex patterns
- **Pattern Caching**: Compiled regex patterns are cached for performance
- **Multiple Search Methods**: Support for match, search, findall, finditer operations
- **String Operations**: Replace and split operations using named patterns
- **Error Handling**: Graceful handling of invalid regex patterns

## Basic Usage

### Inheriting from RegexPlugin

```python
from dissect.target.helpers.regex.regex import RegexPlugin
from dissect.target.plugin import export

class MyLogParser(RegexPlugin):
    def __init__(self, target):
        super().__init__(target)
        
        # Add regex patterns for parsing
        self.add_patterns({
            "timestamp": r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
            "ip_address": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            "log_level": r"\[(DEBUG|INFO|WARN|ERROR)\]"
        })
    
    @export(record=LogRecord)
    def parse_logs(self):
        for line in self.target.fs.path("/var/log/app.log").open():
            if match := self.match("timestamp", line):
                timestamp = match.group(1)
                # Process the line...
```

### Available Methods

#### Pattern Management
- `add_pattern(name, pattern, flags=0)`: Add a single pattern
- `add_patterns(patterns, flags=0)`: Add multiple patterns at once
- `remove_pattern(name)`: Remove a pattern by name
- `clear_patterns()`: Remove all patterns
- `list_patterns()`: Get list of all pattern names
- `has_pattern(name)`: Check if a pattern exists
- `get_pattern(name)`: Get compiled pattern object

#### Pattern Matching
- `match(name, text)`: Match pattern at beginning of text
- `search(name, text)`: Search for pattern anywhere in text
- `findall(name, text)`: Find all matches as a list
- `finditer(name, text)`: Find all matches as an iterator

#### String Operations
- `replace(name, text, repl)`: Replace first match
- `replace_all(name, text, repl)`: Replace all matches
- `split(name, text, maxsplit=0)`: Split text by pattern

## PAM Plugin Example

The PAM (Pluggable Authentication Modules) plugin is a comprehensive example of using the RegexPlugin:

### Usage

```python
from dissect.target import Target

# Load a target (filesystem image, etc.)
target = Target.open("path/to/filesystem")

# Get PAM module information
for module in target.pam_modules():
    print(f"Service: {module.service}")
    print(f"Module: {module.module_name}")
    print(f"Type: {module.module_type}")
    print(f"Control: {module.control_flag}")
    print(f"Arguments: {module.arguments}")
    print("---")
```

### Implementation Details

The PAM plugin demonstrates several RegexPlugin features:

1. **Complex Pattern Matching**: Handles both simple and complex PAM control flags
2. **Multiple File Formats**: Parses both `/etc/pam.conf` and `/etc/pam.d/*` formats  
3. **Advanced Parsing**: Handles line continuations, comments, and include directives
4. **Argument Parsing**: Custom logic for parsing complex argument strings

### Patterns Used

```python
self.add_patterns({
    # PAM configuration line patterns
    "pam_conf_line": r"^\s*([^\s#]+)\s+([^\s]+)\s+(\[[^\]]+\]|[^\s]+)\s+([^\s]+)(?:\s+(.*))?$",
    "pam_d_line": r"^\s*([^\s]+)\s+(\[[^\]]+\]|[^\s]+)\s+([^\s]+)(?:\s+(.*))?$",
    
    # Helper patterns
    "include_directive": r"^\s*@include\s+([^\s]+).*$",
    "so_module": r"([^/\s]+\.so)(?:\s|$)",
    "comment_or_empty": r"^\s*(?:#.*)?$",
})
```

## Best Practices

1. **Pattern Organization**: Group related patterns logically
2. **Error Handling**: Always check if patterns exist before using them
3. **Performance**: Use compiled patterns for repeated operations
4. **Documentation**: Document your regex patterns clearly
5. **Testing**: Create comprehensive tests for all pattern variations

## Common Patterns

### Date/Time Patterns
```python
"iso_date": r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",
"syslog_date": r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
"unix_timestamp": r"(\d{10})",
```

### Network Patterns  
```python
"ipv4": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
"ipv6": r"([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}",
"mac_address": r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}",
```

### File System Patterns
```python
"unix_path": r"(/[^/\s]*)+",  
"windows_path": r"[A-Za-z]:\\\\[^\\s]*",
"filename": r"([^/\\\\]+\.[^/\\\\]+)$",
```

This foundation enables rapid development of text-parsing plugins while maintaining consistency and reducing code duplication across the codebase. 