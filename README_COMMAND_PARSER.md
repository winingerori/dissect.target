# Command Parser Framework for dissect.target

A flexible, header-driven framework for parsing command line tool outputs in digital forensics investigations.

## Overview

The Command Parser Framework provides a robust architecture for parsing outputs from various command line tools found in forensic images. The framework is designed to be completely **parameter-agnostic** and **header-driven**, making it highly flexible and future-proof.

## Architecture

### Core Components

```
dissect/target/helpers/addons/command_parser/
├── command_parser.py          # Base CommandParserPlugin class
└── table_parser.py           # Generic table parsing utilities

dissect/target/plugins/addons/os/unix/
└── ps_command.py             # Linux ps command plugin (reference implementation)

tests/
├── _data/command_outputs/    # Test data files
└── plugins/addons/os/unix/
    └── test_ps_command.py    # Comprehensive test suite
```

### Key Classes

- **`CommandParserPlugin`**: Abstract base class for command output parsers
- **`TableParser`**: Generic table parser with intelligent column boundary detection
- **`LinuxTableCommandParser`**: Linux-specific table parser with header detection
- **`PsCommandPlugin`**: Reference implementation for Linux ps command

## Features

### 🎯 Header-Driven Parsing
- **Zero parameter dependency** - parsing logic is completely independent of command arguments
- **Automatic column detection** - intelligently identifies table headers and boundaries
- **Dynamic field mapping** - maps any column header to standardized field names
- **Format agnostic** - works with any table format, column order, or spacing

### 🚀 Extensible Design
- **Plugin architecture** - easy to add support for new commands
- **Comprehensive field mapping** - handles 50+ column variations out of the box
- **Unknown column handling** - gracefully processes custom or unknown columns
- **Future-proof** - new formats work automatically without code changes

### 🛡️ Robust Error Handling
- **Malformed data resilience** - continues processing despite invalid lines
- **Missing file handling** - graceful degradation when files are unavailable
- **Encoding flexibility** - handles various text encodings with fallback

## Usage

### Command Output Storage

Store command outputs in the `/command_outputs` directory with the naming convention:
```
/command_outputs/
├── ps.txt                           # Basic ps output
├── ps_aux.txt                       # BSD-style all processes
├── ps_-ef.txt                       # System V style full format
├── ps_-eo_pid,ppid,user,command.txt # Custom format
├── ps_axjf.txt                      # Tree format
└── netstat_-tulpn.txt              # Future: netstat support
```

### Basic Usage

```python
from dissect.target import Target
from dissect.target.plugins.addons.os.unix.ps_command import PsCommandPlugin

# Load target with command outputs
target = Target.open("/path/to/forensic/image")

# Create plugin instance
ps_plugin = PsCommandPlugin(target)

# Parse all ps command outputs
for process_record in ps_plugin.ps():
    print(f"PID: {process_record.pid}")
    print(f"User: {process_record.user}")
    print(f"Command: {process_record.command}")
    print(f"Arguments: {process_record.args}")
    print(f"Source: {process_record.source_file}")
    print("---")
```

## Linux ps Command Parser

### Supported Formats

The ps command parser automatically handles **any ps format** by analyzing table headers:

#### Standard Formats
- **Basic**: `ps` - Shows processes for current terminal
- **BSD All**: `ps aux` - All processes with user info
- **System V**: `ps -ef` - Full format listing
- **Long Format**: `ps -l` - Detailed process information
- **Tree Format**: `ps axjf` - Process hierarchy tree

#### Custom Formats
- **Custom Fields**: `ps -eo pid,ppid,user,command` - User-defined columns
- **Memory Focus**: `ps -eo pid,vsz,rss,pmem,comm` - Memory usage details
- **Time Focus**: `ps -eo pid,etime,time,stime,comm` - Timing information

#### Any Column Order
The parser works regardless of column arrangement:
```bash
# Standard order
PID TTY TIME CMD

# Unusual order  
COMMAND USER PID PPID RSS %CPU STAT TTY TIME

# Custom mix
USER PID %MEM VSZ COMMAND STAT
```

### Field Mapping

The parser maps 50+ column variations to standardized fields:

| Column Headers | Mapped Field | Description |
|----------------|--------------|-------------|
| `PID` | `pid` | Process ID |
| `PPID` | `ppid` | Parent Process ID |
| `USER`, `EUSER`, `RUSER` | `user` | Process owner |
| `UID`, `EUID`, `RUID` | `uid` | User ID |
| `CMD`, `COMM` | `command` | Command name |
| `COMMAND`, `ARGS` | `args` | Full command line |
| `STAT`, `S`, `STATE` | `state` | Process state |
| `TTY`, `TT`, `TNAME` | `tty` | Terminal |
| `TIME`, `CPUTIME` | `time` | CPU time |
| `%CPU`, `PCPU` | `cpu_percent` | CPU percentage |
| `%MEM`, `PMEM` | `mem_percent` | Memory percentage |
| `VSZ`, `VSIZE`, `SIZE` | `vsz` | Virtual memory size |
| `RSS`, `RSSIZE` | `rss` | Resident set size |
| `PRI`, `PRIORITY` | `priority` | Process priority |
| `NI`, `NICE` | `nice` | Nice value |
| `START`, `STARTED`, `LSTART`, `STIME` | `start_time` | Start time |
| `ETIME`, `ELAPSED` | `elapsed_time` | Elapsed time |
| `WCHAN`, `ADDR` | `wchan` | Wait channel |
| `F`, `FLAGS` | `flags` | Process flags |

### Output Record

Each parsed process creates a `PsRecord` with comprehensive fields:

```python
PsRecord(
    pid="1234",                    # Process ID
    ppid="456",                    # Parent Process ID  
    user="alice",                  # Process owner
    uid="1000",                    # User ID
    gid="1000",                    # Group ID
    command="bash",                # Command name
    args="/bin/bash -l",          # Full command line
    state="S",                     # Process state
    tty="pts/0",                   # Terminal
    time="00:00:05",              # CPU time
    cpu_percent="1.5",            # CPU percentage
    mem_percent="0.2",            # Memory percentage
    vsz="12345",                  # Virtual memory
    rss="2048",                   # Resident memory
    priority="20",                # Priority
    nice="0",                     # Nice value
    start_time="Jan01",           # Start time
    elapsed_time="05:23",         # Elapsed time
    wchan="wait",                 # Wait channel
    flags="4194304",              # Process flags
    # ... additional fields
    arguments=["-l"],             # Parsed arguments
    source_file="ps_aux.txt",     # Source file
    raw_data='{"USER":"alice"...}', # Original parsed data as JSON
    hostname="forensic-host",     # Target hostname
    domain="example.com"          # Target domain
)
```

## Creating New Command Parsers

### Step 1: Define Record Descriptor

```python
from dissect.target.helpers.record import TargetRecordDescriptor

MyCommandRecord = TargetRecordDescriptor(
    "command/mycommand",
    [
        ("string", "field1"),
        ("string", "field2"),
        ("string[]", "list_field"),
        ("string", "source_file"),
        ("string", "raw_data"),
    ],
)
```

### Step 2: Implement Plugin Class

```python
from dissect.target.helpers.addons.command_parser.command_parser import CommandParserPlugin
from dissect.target.helpers.addons.command_parser.table_parser import LinuxTableCommandParser

class MyCommandPlugin(CommandParserPlugin, LinuxTableCommandParser):
    def __init__(self, target):
        CommandParserPlugin.__init__(self, target)
        LinuxTableCommandParser.__init__(self)
        
        # Define column mappings
        self.column_mappings = {
            'HEADER1': 'field1',
            'HEADER2': 'field2',
            # ... more mappings
        }
    
    def get_command_name(self) -> str:
        return "mycommand"
    
    def get_supported_arguments(self) -> List[str]:
        return ["-a", "-l", "--verbose"]  # Informational only
    
    @export(record=MyCommandRecord)
    def mycommand(self) -> Iterator[MyCommandRecord]:
        for file_path in self.get_command_output_files():
            lines = self.read_command_output(file_path)
            arguments = self.parse_command_arguments(file_path.name)
            yield from self.parse_command_output(lines, arguments)
    
    def parse_command_output(self, lines, arguments):
        parsed_rows = self.parse_table_output(lines)
        
        for row in parsed_rows:
            mapped_row = self.map_columns_to_fields(row, self.column_mappings)
            
            record_data = {
                'field1': mapped_row.get('field1', ''),
                'field2': mapped_row.get('field2', ''),
                'source_file': arguments.get('source_file', ''),
                'raw_data': json.dumps(row),
                '_target': self.target,
            }
            
            yield MyCommandRecord(**record_data)
```

### Step 3: Add Tests

```python
def test_my_command_plugin(target_with_outputs):
    plugin = MyCommandPlugin(target_with_outputs)
    records = list(plugin.mycommand())
    
    assert len(records) > 0
    assert records[0].field1
    assert records[0].source_file
```

## Testing

### Running Tests

```bash
# Run all command parser tests
python -m pytest tests/plugins/addons/os/unix/test_ps_command.py -v

# Run specific test categories
python -m pytest tests/plugins/addons/os/unix/test_ps_command.py::test_ps_header_driven_parsing -v
python -m pytest tests/plugins/addons/os/unix/test_ps_command.py::test_ps_parameter_agnostic_parsing -v
```

### Test Coverage

The test suite includes 21 comprehensive tests covering:

- ✅ **Table parsing** - Basic and complex header detection
- ✅ **Plugin compatibility** - File discovery and initialization  
- ✅ **Format parsing** - All major ps output formats
- ✅ **Column mapping** - 65+ header-to-field mappings
- ✅ **Parameter handling** - Argument parsing (metadata only)
- ✅ **Error handling** - Malformed data and missing files
- ✅ **Header-driven parsing** - Format-agnostic processing
- ✅ **Custom column orders** - Unusual arrangements
- ✅ **Field validation** - Record structure and types

## Design Principles

### 1. Header-Driven Architecture
The parser analyzes table headers to determine parsing strategy, making it completely independent of command parameters or filename conventions.

### 2. Zero-Configuration Flexibility  
New formats work automatically without code changes. The parser adapts to any column arrangement, spacing, or header variation.

### 3. Comprehensive Field Mapping
Extensive mapping covers variations across different Unix systems, ensuring compatibility with diverse ps implementations.

### 4. Graceful Degradation
The parser continues processing even when encountering unknown columns, malformed data, or missing files.

### 5. Forensic-First Design
Built specifically for digital forensics with features like:
- Source file tracking for evidence chain
- Raw data preservation for verification
- Hostname/domain context for multi-system investigations
- Comprehensive field coverage for analysis

## Future Extensions

The framework is designed to easily support additional commands:

- **Network Tools**: `netstat`, `ss`, `lsof`
- **System Info**: `top`, `htop`, `iostat`, `vmstat`  
- **File System**: `ls -la`, `find`, `df`, `mount`
- **Security**: `iptables -L`, `ufw status`, `fail2ban-client`
- **Containers**: `docker ps`, `kubectl get pods`
- **Custom Tools**: Any tabular command output

## Contributing

When adding new command parsers:

1. Follow the established plugin architecture
2. Use header-driven parsing (avoid parameter dependencies)
3. Include comprehensive column mappings
4. Add thorough test coverage
5. Document supported formats and field mappings
6. Preserve raw data for forensic verification

## License

This framework is part of the dissect.target project. See the main project license for details. 