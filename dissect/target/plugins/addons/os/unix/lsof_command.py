from typing import Iterator, List, Dict, Any

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.addons.command_parser.command_parser import CommandParserPlugin
from dissect.target.helpers.addons.command_parser.table_parser import LinuxTableCommandParser
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export


LsofRecord = TargetRecordDescriptor(
    "command/lsof",
    [
        ("string", "command"),
        ("varint", "pid"),
        ("string", "user"),
        ("string", "fd"),
        ("string", "type"),
        ("string", "device"),
        ("string", "size_off"),
        ("string", "node"),
        ("string", "name"),
        ("string", "source_file"),
        ("string", "raw_data"),
    ],
)


class LsofCommandPlugin(CommandParserPlugin, LinuxTableCommandParser):
    """Plugin for parsing lsof command output.
    
    The lsof command lists open files and network connections. This plugin
    uses header-driven parsing to handle all lsof variations automatically.
    
    Common lsof formats:
    - lsof: List all open files
    - lsof -i: List network connections only
    - lsof -p PID: List files for specific process
    - lsof -u USER: List files for specific user
    - lsof -c COMMAND: List files for specific command
    - lsof +D /path: List files in directory tree
    """
    
    COMMAND_NAME = "lsof"
    
    # Column mapping for lsof output variations
    COLUMN_MAPPING = {
        # Standard lsof columns
        "COMMAND": "command",
        "CMD": "command",
        "PID": "pid",
        "USER": "user",
        "FD": "fd",
        "TYPE": "type",
        "DEVICE": "device",
        "SIZE/OFF": "size_off",
        "SIZE": "size_off",
        "OFF": "size_off",
        "NODE": "node",
        "NAME": "name",
        "FILENAME": "name",
        "PATH": "name",
        
        # Additional possible variations
        "PROC": "command",
        "PROCESS": "command",
        "OWNER": "user",
        "USERNAME": "user",
        "FILE_DESCRIPTOR": "fd",
        "FILETYPE": "type",
        "DEV": "device",
        "INODE": "node",
        "OFFSET": "size_off",
        "FILEPATH": "name",
        "TARGET": "name",
    }
    
    def __init__(self, target):
        CommandParserPlugin.__init__(self, target)
        LinuxTableCommandParser.__init__(self)
    
    def get_command_name(self) -> str:
        """Return the command name."""
        return "lsof"
    
    def get_supported_arguments(self) -> List[str]:
        """Return supported lsof arguments."""
        return [
            "-i",      # Internet files
            "-p",      # Process ID
            "-u",      # User
            "-c",      # Command
            "-d",      # File descriptor
            "-t",      # Terse output (PID only)
            "-n",      # No hostname lookup
            "-P",      # No port lookup
            "-l",      # No user lookup
            "-R",      # Repeat mode
            "-r",      # Repeat every N seconds
            "-a",      # AND mode
            "-o",      # Offset column
            "+D",      # Directory tree
            "+d",      # Directory
            "+L",      # List link count
            "-L",      # Disable link count
            "-b",      # Avoid blocking
            "-w",      # Disable warnings
        ]
    
    def check_compatible(self):
        """Check if the target contains lsof command output files."""
        try:
            return bool(list(self.get_command_output_files()))
        except Exception:
            return False
    
    def safe_int(self, value: str) -> int:
        """Safely convert string to integer."""
        if not value or not isinstance(value, str):
            return 0
        try:
            return int(value)
        except (ValueError, TypeError):
            return 0
    

    
    def parse_command_output(self, lines: List[str], arguments: Dict[str, Any]) -> Iterator[LsofRecord]:
        """Parse lsof command output lines into structured records."""
        if not lines:
            return
            
        # Find header line
        header_line_idx = self.detect_header_line(lines)
        if header_line_idx is None:
            self.target.log.warning("Could not detect header line in lsof output")
            return
            
        # Parse each data line manually for better accuracy with lsof format
        for line in lines[header_line_idx + 1:]:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Parse lsof line using custom logic
            parsed_data = self._parse_lsof_line(line)
            if not parsed_data:
                continue
                
            # Create record with parsed data
            record_data = {
                "command": parsed_data.get("command", ""),
                "pid": self.safe_int(parsed_data.get("pid", "")),
                "user": parsed_data.get("user", ""),
                "fd": parsed_data.get("fd", ""),
                "type": parsed_data.get("type", ""),
                "device": parsed_data.get("device", ""),
                "size_off": parsed_data.get("size_off", ""),
                "node": parsed_data.get("node", ""),
                "name": parsed_data.get("name", ""),
                "source_file": arguments.get("source_file", ""),
                "raw_data": line,
            }
            
            yield LsofRecord(**record_data)
    
    def _parse_lsof_line(self, line: str) -> Dict[str, str]:
        """Parse a single lsof output line using custom logic.
        
        lsof output format is typically:
        COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        
        Args:
            line: Data line to parse
            
        Returns:
            Dictionary with parsed fields
        """
        # Split the line into fields, but be careful about the NAME field
        # which can contain spaces and should be treated as the remainder
        
        fields = line.split()
        if len(fields) < 8:  # Need at least 8 fields for a valid lsof line
            return {}
            
        # Standard lsof format has these fixed positions:
        # 0: COMMAND, 1: PID, 2: USER, 3: FD, 4: TYPE, 5: DEVICE, 6: SIZE/OFF, 7: NODE, 8+: NAME
        
        result = {
            "command": fields[0],
            "pid": fields[1],
            "user": fields[2],
            "fd": fields[3],
            "type": fields[4],
            "device": fields[5],
            "size_off": fields[6],
            "node": fields[7] if len(fields) > 7 else "",
        }
        
        # For lsof, the NAME field should include protocol information for network connections
        # This provides more complete information for forensic analysis
        if len(fields) > 8:
            # For network connections, include the NODE (protocol) with the NAME
            node_field = result["node"]
            name_parts = fields[8:]
            base_name = " ".join(name_parts)
            
            # If the node field looks like a protocol (TCP, UDP, etc.), include it in name
            if node_field and node_field.upper() in ['TCP', 'UDP', 'UNIX', 'IPv4', 'IPv6']:
                result["name"] = f"{node_field} {base_name}"
            else:
                result["name"] = base_name
                
        elif len(fields) == 8:
            # Handle case where NAME might be empty but NODE exists
            node_field = result["node"]
            if node_field and node_field.upper() in ['TCP', 'UDP', 'UNIX', 'IPv4', 'IPv6']:
                result["name"] = node_field
            else:
                result["name"] = ""
        else:
            result["name"] = ""
            
        return result
    
    @export(record=LsofRecord)
    def lsof_command(self) -> Iterator[LsofRecord]:
        """Parse lsof command output files and yield records."""
        if not self.check_compatible():
            raise UnsupportedPluginError("No lsof command output files found")
        
        for file_path in self.get_command_output_files():
            try:
                lines = self.read_command_output(file_path)
                if not lines:
                    continue
                    
                # Parse command arguments from filename
                arguments = self.parse_command_arguments(file_path.name)
                arguments["source_file"] = str(file_path)
                
                # Parse the command output
                yield from self.parse_command_output(lines, arguments)
                        
            except Exception as e:
                self.target.log.warning(f"Error parsing lsof file {file_path}: {e}")
                continue 