from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regex.regex import RegexPlugin
from dissect.target.plugin import export

PamModuleRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "pam/module",
    [
        ("string", "service"),
        ("string", "module_type"),
        ("string", "control_flag"),
        ("string", "module_path"),
        ("string", "module_name"), 
        ("string[]", "arguments"),
        ("path", "config_file"),
        ("string", "source_line"),
    ],
)


class PamPlugin(RegexPlugin):
    """Plugin to parse PAM (Pluggable Authentication Modules) configuration files.
    
    This plugin parses PAM configuration files from /etc/pam.conf and /etc/pam.d/
    to extract information about loaded PAM modules, particularly .so files.
    
    PAM configuration files contain rules that define authentication, authorization,
    session management, and password policies for various services.
    """

    def __init__(self, target):
        super().__init__(target)
        
        # Add regex patterns for parsing PAM configuration lines
        self.add_patterns({
            # Pattern for /etc/pam.conf format: service type control module args...
            # This handles both simple control flags and complex ones with brackets
            "pam_conf_line": r"^\s*([^\s#]+)\s+([^\s]+)\s+(\[[^\]]+\]|[^\s]+)\s+([^\s]+)(?:\s+(.*))?$",
            
            # Pattern for /etc/pam.d/ format: type control module args...
            # This handles both simple control flags and complex ones with brackets  
            "pam_d_line": r"^\s*([^\s]+)\s+(\[[^\]]+\]|[^\s]+)\s+([^\s]+)(?:\s+(.*))?$",
            
            # Pattern for @include directives in pam.d files
            "include_directive": r"^\s*@include\s+([^\s]+).*$",
            
            # Pattern to extract .so module name from module path
            "so_module": r"([^/\s]+\.so)(?:\s|$)",
            
            # Pattern to match comment lines and empty lines
            "comment_or_empty": r"^\s*(?:#.*)?$",
            
            # Pattern for control flags with complex syntax [value=action ...]
            "complex_control": r"\[([^\]]+)\]",
        })

    def check_compatible(self) -> None:
        # No specific compatibility requirements
        pass

    @export(record=PamModuleRecord)
    def pam_modules(self) -> Iterator[PamModuleRecord]:
        """Parse PAM configuration files and yield module information.
        
        Yields:
            PamModuleRecord: Records containing PAM module information including
                           service, module type, control flag, module path, etc.
        """
        # Parse /etc/pam.conf first (single file format)
        pam_conf = self.target.fs.path("/etc/pam.conf")
        if pam_conf.exists() and pam_conf.is_file():
            yield from self._parse_pam_conf(pam_conf)
        
        # Parse /etc/pam.d/* files (directory format)
        pam_d_dir = self.target.fs.path("/etc/pam.d")
        if pam_d_dir.exists() and pam_d_dir.is_dir():
            for config_file in pam_d_dir.iterdir():
                if config_file.is_file() and not config_file.name.startswith('.'):
                    yield from self._parse_pam_d_file(config_file)

    def _parse_pam_conf(self, config_file: Path) -> Iterator[PamModuleRecord]:
        """Parse /etc/pam.conf format configuration file.
        
        Args:
            config_file: Path to the pam.conf file
            
        Yields:
            PamModuleRecord: Parsed PAM module records
        """
        try:
            lines = list(config_file.open("rt"))
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                line_num = i + 1
                
                # Skip comments and empty lines
                if self.match("comment_or_empty", line):
                    i += 1
                    continue
                
                # Handle line continuations with backslash
                full_line = line
                while full_line.endswith('\\') and i + 1 < len(lines):
                    i += 1
                    next_line = lines[i].strip()
                    full_line = full_line[:-1] + ' ' + next_line
                
                # Parse the PAM configuration line
                match = self.match("pam_conf_line", full_line)
                if match:
                    service = match.group(1)
                    module_type = match.group(2)
                    control_flag = match.group(3)
                    module_path = match.group(4)
                    arguments = match.group(5) or ""
                    
                    # Extract .so module name from path
                    module_name = self._extract_module_name(module_path)
                    
                    # Parse arguments into list
                    args_list = self._parse_arguments(arguments)
                    
                    yield PamModuleRecord(
                        service=service,
                        module_type=module_type,
                        control_flag=control_flag,
                        module_path=module_path,
                        module_name=module_name,
                        arguments=args_list,
                        config_file=config_file,
                        source_line=full_line,
                        _target=self.target,
                    )
                else:
                    self.target.log.warning(
                        "Failed to parse PAM config line %d in %s: %s", 
                        line_num, config_file, full_line
                    )
                
                i += 1
                    
        except Exception as e:
            self.target.log.error("Error parsing PAM config file %s: %s", config_file, e)

    def _parse_pam_d_file(self, config_file: Path) -> Iterator[PamModuleRecord]:
        """Parse /etc/pam.d/ format configuration file.
        
        Args:
            config_file: Path to the service-specific PAM configuration file
            
        Yields:
            PamModuleRecord: Parsed PAM module records
        """
        try:
            service = config_file.name  # Service name is the filename
            lines = list(config_file.open("rt"))
            i = 0
            
            while i < len(lines):
                line = lines[i].strip()
                line_num = i + 1
                
                # Skip comments and empty lines
                if self.match("comment_or_empty", line):
                    i += 1
                    continue
                
                # Skip @include directives (they don't define modules directly)
                if self.match("include_directive", line):
                    i += 1
                    continue
                
                # Handle line continuations with backslash
                full_line = line
                while full_line.endswith('\\') and i + 1 < len(lines):
                    i += 1
                    next_line = lines[i].strip()
                    full_line = full_line[:-1] + ' ' + next_line
                
                # Parse the PAM configuration line
                match = self.match("pam_d_line", full_line)
                if match:
                    module_type = match.group(1)
                    control_flag = match.group(2)
                    module_path = match.group(3)
                    arguments = match.group(4) or ""
                    
                    # Extract .so module name from path
                    module_name = self._extract_module_name(module_path)
                    
                    # Parse arguments into list
                    args_list = self._parse_arguments(arguments)
                    
                    yield PamModuleRecord(
                        service=service,
                        module_type=module_type,
                        control_flag=control_flag,
                        module_path=module_path,
                        module_name=module_name,
                        arguments=args_list,
                        config_file=config_file,
                        source_line=full_line,
                        _target=self.target,
                    )
                else:
                    self.target.log.warning(
                        "Failed to parse PAM config line %d in %s: %s", 
                        line_num, config_file, full_line
                    )
                
                i += 1
                    
        except Exception as e:
            self.target.log.error("Error parsing PAM config file %s: %s", config_file, e)

    def _extract_module_name(self, module_path: str) -> str:
        """Extract the .so module name from a module path.
        
        Args:
            module_path: Full path to the PAM module
            
        Returns:
            The module name (e.g., "pam_unix.so") or the full path if no .so found
        """
        match = self.search("so_module", module_path)
        if match:
            return match.group(1)
        
        # If no .so extension found, return the last component of the path
        return Path(module_path).name

    def _parse_arguments(self, arguments: str) -> list[str]:
        """Parse PAM module arguments string into a list.
        
        PAM arguments can include quoted strings with square brackets for
        complex arguments containing spaces.
        
        Args:
            arguments: Raw arguments string
            
        Returns:
            List of parsed argument strings
        """
        if not arguments:
            return []
        
        args = []
        current_arg = ""
        in_brackets = False
        i = 0
        
        while i < len(arguments):
            char = arguments[i]
            
            if char == '[' and not in_brackets:
                in_brackets = True
                current_arg += char
            elif char == ']' and in_brackets:
                in_brackets = False
                current_arg += char
            elif char.isspace() and not in_brackets:
                if current_arg:
                    args.append(current_arg)
                    current_arg = ""
            else:
                current_arg += char
            
            i += 1
        
        if current_arg:
            args.append(current_arg)
        
        return args 