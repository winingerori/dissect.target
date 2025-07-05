"""Base class for command output parsing plugins.

This module provides the CommandParserPlugin base class that helps parse
command line tool outputs from various operating systems and tools.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Iterator, List, Optional

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.addons.regex.regex import RegexPlugin
from dissect.target.plugin import export

if TYPE_CHECKING:
    from dissect.target.target import Target


class CommandParserPlugin(RegexPlugin, ABC):
    """Base class for parsing command line tool outputs.
    
    This class provides functionality to parse command outputs that are stored
    in files within the target filesystem. It's designed to handle various
    command line tools and their different output formats.
    
    Subclasses should implement the command-specific parsing logic and define
    the appropriate record descriptors for the parsed data.
    """

    COMMAND_OUTPUTS_DIR = "command_outputs"
    """Directory name where command outputs are stored."""

    def __init__(self, target: Target):
        super().__init__(target)
        self.command_outputs_path = self.target.fs.path(f"/{self.COMMAND_OUTPUTS_DIR}")

    def check_compatible(self) -> None:
        """Check if command outputs directory exists."""
        if not self.command_outputs_path.exists():
            raise UnsupportedPluginError(f"{self.COMMAND_OUTPUTS_DIR} directory not available")

    @abstractmethod
    def get_command_name(self) -> str:
        """Return the name of the command this plugin parses.
        
        Returns:
            str: The command name (e.g., 'pslist', 'netstat', 'tasklist')
        """
        pass

    @abstractmethod
    def get_supported_arguments(self) -> List[str]:
        """Return a list of supported command arguments.
        
        Returns:
            List[str]: List of supported command line arguments
        """
        pass

    def get_command_output_files(self) -> Iterator[Path]:
        """Get all command output files for this command.
        
        Yields:
            Path: Path objects for command output files
        """
        command_name = self.get_command_name()
        
        # Look for files matching the command name pattern
        for file_path in self.command_outputs_path.iterdir():
            if file_path.is_file() and file_path.name.startswith(command_name):
                yield file_path

    def parse_command_arguments(self, filename: str) -> Dict[str, Any]:
        """Parse command arguments from filename.
        
        Expected filename format: commandname_arg1_arg2_...extension
        For example: pslist_-d_-m.txt, pslist_-u_username.txt
        
        Args:
            filename: The command output filename
            
        Returns:
            Dict[str, Any]: Parsed arguments and their values
        """
        command_name = self.get_command_name()
        
        # Remove command name prefix and file extension
        if not filename.startswith(command_name):
            return {}
            
        # Remove command name and extension
        args_part = filename[len(command_name):].rsplit('.', 1)[0]
        
        # Remove leading underscore if present
        if args_part.startswith('_'):
            args_part = args_part[1:]
            
        if not args_part:
            return {"arguments": []}
            
        # Split by underscores to get individual arguments
        arg_parts = args_part.split('_')
        
        parsed_args = {"arguments": []}
        i = 0
        
        while i < len(arg_parts):
            arg = arg_parts[i]
            
            # Handle arguments that start with dash
            if arg.startswith('-'):
                parsed_args["arguments"].append(arg)
                
                # Check if next part is a value (doesn't start with dash)
                if i + 1 < len(arg_parts) and not arg_parts[i + 1].startswith('-'):
                    i += 1
                    parsed_args["arguments"].append(arg_parts[i])
            else:
                # Standalone argument or value
                parsed_args["arguments"].append(arg)
                
            i += 1
            
        return parsed_args

    def read_command_output(self, file_path: Path) -> List[str]:
        """Read command output from file.
        
        Args:
            file_path: Path to the command output file
            
        Returns:
            List[str]: Lines from the command output file
        """
        try:
            with file_path.open("rt", encoding="utf-8", errors="replace") as f:
                return f.readlines()
        except Exception as e:
            self.target.log.error(f"Error reading command output file {file_path}: {e}")
            return []

    @abstractmethod
    def parse_command_output(self, lines: List[str], arguments: Dict[str, Any]) -> Iterator[Any]:
        """Parse command output lines into structured records.
        
        Args:
            lines: Lines from the command output
            arguments: Parsed command arguments
            
        Yields:
            Any: Parsed record objects
        """
        pass 