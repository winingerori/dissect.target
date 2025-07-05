"""Linux ps command output parser plugin.

This plugin parses Linux ps command output files stored in the command_outputs directory.
The parser is completely header-driven and parameter-agnostic - it relies solely on
table headers to determine how to parse the data, making it flexible for any ps format.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional

from dissect.target.helpers.addons.command_parser.command_parser import CommandParserPlugin
from dissect.target.helpers.addons.command_parser.table_parser import LinuxTableCommandParser
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export

if TYPE_CHECKING:
    from dissect.target.target import Target

# Record descriptor for ps command output
PsRecord = TargetRecordDescriptor(
    "command/ps",
    [
        ("string", "pid"),
        ("string", "ppid"),
        ("string", "user"),
        ("string", "uid"),
        ("string", "gid"),
        ("string", "command"),
        ("string", "args"),
        ("string", "state"),
        ("string", "tty"),
        ("string", "time"),
        ("string", "cpu_percent"),
        ("string", "mem_percent"),
        ("string", "vsz"),
        ("string", "rss"),
        ("string", "priority"),
        ("string", "nice"),
        ("string", "start_time"),
        ("string", "elapsed_time"),
        ("string", "wchan"),
        ("string", "flags"),
        ("string", "pgid"),
        ("string", "sid"),
        ("string", "tpgid"),
        ("string", "ruid"),
        ("string", "rgid"),
        ("string", "cpu_utilization"),
        ("string[]", "arguments"),
        ("string", "source_file"),
        ("string", "raw_data"),  # Store all parsed columns as JSON string
    ],
)


class PsCommandPlugin(CommandParserPlugin, LinuxTableCommandParser):
    """Header-driven Linux ps command output parser.
    
    This plugin parses Linux ps command output files by analyzing table headers only.
    It doesn't rely on command parameters or format detection - instead it dynamically
    maps any ps output format based on the column headers present in the data.
    
    Supported ps variations (automatically detected from headers):
    - Any ps format with standard headers (PID, USER, COMMAND, etc.)
    - BSD-style formats (ps aux, ps axjf, etc.)
    - System V formats (ps -ef, ps -elyf, etc.)
    - Custom formats (ps -eo pid,user,command, etc.)
    - Tree formats with process hierarchy
    - Any combination of ps options and custom field selections
    """

    def __init__(self, target: Target):
        CommandParserPlugin.__init__(self, target)
        LinuxTableCommandParser.__init__(self)
        
        # Comprehensive column name mappings to standardized field names
        # This covers all possible ps column variations across different systems
        self.column_mappings = {
            # Process ID variations
            'PID': 'pid',
            'PPID': 'ppid',
            'PGID': 'pgid',
            'SID': 'sid',
            'TPGID': 'tpgid',
            'SPID': 'pid',  # Thread ID in some contexts
            
            # User variations
            'USER': 'user',
            'EUSER': 'user',
            'RUSER': 'ruser',
            'FUSER': 'user',
            'UID': 'uid',
            'EUID': 'uid',
            'RUID': 'ruid',
            'FUID': 'uid',
            'GID': 'gid',
            'EGID': 'gid',
            'RGID': 'rgid',
            'FGID': 'gid',
            'SUPGID': 'gid',
            'SUPGRP': 'gid',
            
            # Command variations
            'CMD': 'command',
            'COMMAND': 'args',
            'COMM': 'command',
            'ARGS': 'args',
            'UCMD': 'command',
            'EXE': 'command',
            
            # State and status
            'STAT': 'state',
            'S': 'state',
            'STATE': 'state',
            'PENDING': 'state',
            
            # Terminal
            'TTY': 'tty',
            'TT': 'tty',
            'TNAME': 'tty',
            'TPGID': 'tpgid',
            
            # Time variations
            'TIME': 'time',
            'CPUTIME': 'time',
            'ETIME': 'elapsed_time',
            'ELAPSED': 'elapsed_time',
            'START': 'start_time',
            'STARTED': 'start_time',
            'LSTART': 'start_time',
            'STIME': 'start_time',
            'BSDSTART': 'start_time',
            'BSDTIME': 'time',
            
            # CPU and memory variations
            '%CPU': 'cpu_percent',
            'PCPU': 'cpu_percent',
            'CP': 'cpu_utilization',
            'C': 'cpu_utilization',
            '%MEM': 'mem_percent',
            'PMEM': 'mem_percent',
            'VSZ': 'vsz',
            'VSIZE': 'vsz',
            'SIZE': 'vsz',
            'RSS': 'rss',
            'RSSIZE': 'rss',
            'RSZ': 'rss',
            'SHARE': 'rss',
            'SZ': 'vsz',
            'DRS': 'rss',
            'TRS': 'rss',
            
            # Priority and nice
            'PRI': 'priority',
            'PRIORITY': 'priority',
            'OPRI': 'priority',
            'INTPRI': 'priority',
            'NI': 'nice',
            'NICE': 'nice',
            'PSR': 'priority',
            'RTPRIO': 'priority',
            'SCH': 'priority',
            'CLS': 'priority',
            
            # Other fields
            'WCHAN': 'wchan',
            'ADDR': 'wchan',
            'NWCHAN': 'wchan',
            'F': 'flags',
            'FLAGS': 'flags',
            'FLAG': 'flags',
            'CAUGHT': 'flags',
            'IGNORED': 'flags',
            'PENDING': 'flags',
            'BLOCKED': 'flags',
            'SIGMASK': 'flags',
            'SIGCATCH': 'flags',
            'SIGIGNORE': 'flags',
            'SIGPEND': 'flags',
            'CONTEXT': 'flags',
            'LABEL': 'flags',
            'MACHINE': 'flags',
            'UNIT': 'flags',
            'SLICE': 'flags',
            'CGROUP': 'flags',
            'SUPGID': 'gid',
            'SUPGRP': 'gid',
            'ENVIRON': 'flags',
            'STACKP': 'flags',
            'ESP': 'flags',
            'EIP': 'flags',
            'TMOUT': 'flags',
            'F': 'flags',
            'SCHED': 'flags',
            'THCOUNT': 'flags',
            'NLWP': 'flags',
            'LWP': 'flags',
            'SPID': 'flags',
            'TID': 'flags',
            'SESS': 'sid',
            'JOBC': 'flags',
            'MWCHAN': 'wchan',
            'MAJFLT': 'flags',
            'MINFLT': 'flags',
            'CMAJFLT': 'flags',
            'CMINFLT': 'flags',
            'UTIME': 'time',
            'CUTIME': 'time',
            'CSTIME': 'time',
            'POLICY': 'flags',
            'RTPRIO': 'priority',
            'SCHED': 'flags',
            'WCHAN': 'wchan',
        }

    def get_command_name(self) -> str:
        """Return the command name."""
        return "ps"

    def get_supported_arguments(self) -> List[str]:
        """Return supported ps arguments.
        
        Note: This is now informational only - the parser doesn't use these
        for format detection anymore, it relies purely on headers.
        """
        return [
            "",           # Basic ps
            "aux",        # BSD style all processes
            "-ef",        # System V style full format
            "-elyf",      # Long format with additional fields
            "axjf",       # BSD job control format with tree
            "-eo",        # Custom format
            "-ax",        # All processes
            "-u",         # User-oriented format
            "-l",         # Long format
            "-f",         # Full format
            "-j",         # Job format
            "-v",         # Virtual memory format
            "-m",         # Show threads
            "-H",         # Show process hierarchy
            "-T",         # Show threads with SPID
            "--forest",   # ASCII art process tree
            "-C",         # Select by command name
            "-p",         # Select by PID
            "-g",         # Select by session/group
            "-t",         # Select by terminal
            "-U",         # Select by real user ID
            # Any other combination - parser will handle it
        ]

    @export(record=PsRecord)
    def ps(self) -> Iterator[PsRecord]:
        """Parse ps command output files using header-driven parsing.
        
        This method parses any ps format by analyzing the table headers
        and mapping columns to standardized field names automatically.
        
        Yields:
            PsRecord: Parsed process information from ps output
        """
        for file_path in self.get_command_output_files():
            lines = self.read_command_output(file_path)
            arguments = self.parse_command_arguments(file_path.name)
            
            # Add source file to arguments
            arguments["source_file"] = file_path.name
            
            yield from self.parse_command_output(lines, arguments)

    def parse_command_output(self, lines: List[str], arguments: Dict[str, Any]) -> Iterator[PsRecord]:
        """Parse ps command output lines using pure header-driven approach.
        
        This method analyzes the table structure and maps columns based on
        headers only, without any parameter-specific logic.
        
        Args:
            lines: Lines from ps output
            arguments: Parsed command arguments (used only for metadata)
            
        Yields:
            PsRecord: Parsed process records
        """
        if not lines:
            return
            
        # Parse the tabular output using generic table parser
        parsed_rows = self.parse_table_output(lines)
        
        for row in parsed_rows:
            # Map columns to standardized field names using comprehensive mapping
            mapped_row = self.map_columns_to_fields(row, self.column_mappings)
            
            # Create record with all available fields, defaulting to empty string
            record_data = {
                'pid': mapped_row.get('pid', ''),
                'ppid': mapped_row.get('ppid', ''),
                'user': mapped_row.get('user', ''),
                'uid': mapped_row.get('uid', ''),
                'gid': mapped_row.get('gid', ''),
                'command': mapped_row.get('command', ''),
                'args': mapped_row.get('args', ''),
                'state': mapped_row.get('state', ''),
                'tty': mapped_row.get('tty', ''),
                'time': mapped_row.get('time', ''),
                'cpu_percent': mapped_row.get('cpu_percent', ''),
                'mem_percent': mapped_row.get('mem_percent', ''),
                'vsz': mapped_row.get('vsz', ''),
                'rss': mapped_row.get('rss', ''),
                'priority': mapped_row.get('priority', ''),
                'nice': mapped_row.get('nice', ''),
                'start_time': mapped_row.get('start_time', ''),
                'elapsed_time': mapped_row.get('elapsed_time', ''),
                'wchan': mapped_row.get('wchan', ''),
                'flags': mapped_row.get('flags', ''),
                'pgid': mapped_row.get('pgid', ''),
                'sid': mapped_row.get('sid', ''),
                'tpgid': mapped_row.get('tpgid', ''),
                'ruid': mapped_row.get('ruid', ''),
                'rgid': mapped_row.get('rgid', ''),
                'cpu_utilization': mapped_row.get('cpu_utilization', ''),
                'arguments': arguments.get('arguments', []),
                'source_file': arguments.get('source_file', ''),
                'raw_data': json.dumps(row),  # Store original parsed data as JSON
                '_target': self.target,
            }
            
            yield PsRecord(**record_data)

    def parse_command_arguments(self, filename: str) -> Dict[str, Any]:
        """Parse command arguments from filename.
        
        Note: This is now used only for metadata - the actual parsing
        doesn't depend on these arguments anymore.
        
        Args:
            filename: The command output filename
            
        Returns:
            Dict[str, Any]: Parsed arguments (metadata only)
        """
        base_args = super().parse_command_arguments(filename)
        
        # Add format detection for informational purposes only
        # The actual parsing doesn't use this information
        args = base_args.get("arguments", [])
        format_info = self._detect_format_info(args)
        
        return {
            "arguments": args,
            "format_info": format_info,
        }
    
    def _detect_format_info(self, args: List[str]) -> str:
        """Detect format information for metadata purposes only.
        
        This is purely informational and doesn't affect parsing logic.
        
        Args:
            args: Command arguments
            
        Returns:
            str: Format description for metadata
        """
        if not args:
            return "basic"
        
        args_str = " ".join(args)
        
        # Common format patterns (informational only)
        if "aux" in args_str:
            return "bsd_all_processes"
        elif "-ef" in args_str:
            return "sysv_full_format"
        elif "-eo" in args_str:
            return "custom_format"
        elif "axjf" in args_str or "f" in args_str:
            return "tree_format"
        elif "-l" in args_str:
            return "long_format"
        elif "-u" in args_str:
            return "user_format"
        elif "-v" in args_str:
            return "virtual_memory_format"
        elif "-j" in args_str:
            return "job_format"
        else:
            return "custom_or_mixed" 