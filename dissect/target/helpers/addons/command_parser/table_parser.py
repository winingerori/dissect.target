"""Generic table parser for Linux command outputs.

This module provides utilities to parse tabular command outputs with headers,
which is common in many Linux command line tools like ps, netstat, lsof, etc.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


class TableParser:
    """Generic parser for tabular command output with headers.
    
    This parser can automatically detect column boundaries based on headers
    and parse data rows accordingly. It handles various spacing and alignment
    patterns commonly found in Linux command outputs.
    """

    def __init__(self, header_line: str, sample_data_lines: List[str] = None):
        """Initialize the table parser with a header line.
        
        Args:
            header_line: The header line containing column names
            sample_data_lines: Optional sample data lines to improve column detection
        """
        self.header_line = header_line.strip()
        self.sample_data_lines = sample_data_lines or []
        self.columns = self._parse_header_smart()
        
    def _parse_header_smart(self) -> List[Dict[str, Any]]:
        """Parse the header line using a smart approach.
        
        Returns:
            List of column dictionaries with name, start, end positions
        """
        if not self.header_line:
            return []
            
        # Use regex to find all words and their positions
        header_words = []
        for match in re.finditer(r'\S+', self.header_line):
            header_words.append({
                "name": match.group(),
                "start": match.start(),
                "end": match.end()
            })
        
        if not header_words:
            return []
        
        # If we have sample data, use it to determine better column boundaries
        if self.sample_data_lines:
            return self._analyze_with_sample_data(header_words)
        else:
            return self._simple_column_detection(header_words)
    
    def _simple_column_detection(self, header_words: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Simple column detection based on header word positions.
        
        Args:
            header_words: List of header word dictionaries
            
        Returns:
            List of column dictionaries
        """
        columns = []
        
        for i, word in enumerate(header_words):
            if i < len(header_words) - 1:
                # Column ends where the next column starts
                next_word = header_words[i + 1]
                col_end = next_word["start"]
            else:
                # Last column extends to end of line
                col_end = None
            
            columns.append({
                "name": word["name"],
                "start": word["start"],
                "end": col_end,
                "width": col_end - word["start"] if col_end is not None else None
            })
        
        return columns
    
    def _analyze_with_sample_data(self, header_words: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze sample data to determine optimal column boundaries.
        
        Args:
            header_words: List of header word dictionaries
            
        Returns:
            List of column dictionaries
        """
        # For each line, split it into fields using whitespace
        # Then analyze where the natural field boundaries are
        
        all_field_splits = []
        for line in self.sample_data_lines:
            # Split by whitespace, but keep track of positions
            fields = []
            current_pos = 0
            
            # Use regex to find all non-whitespace sequences
            for match in re.finditer(r'\S+', line):
                fields.append({
                    "text": match.group(),
                    "start": match.start(),
                    "end": match.end()
                })
            
            all_field_splits.append(fields)
        
        # Now try to align these fields with header columns
        columns = []
        
        for i, header_word in enumerate(header_words):
            header_start = header_word["start"]
            
            # Find the best matching field positions for this column
            field_starts = []
            for field_split in all_field_splits:
                if i < len(field_split):
                    field_starts.append(field_split[i]["start"])
            
            # Use the most common field start position, or header position as fallback
            if field_starts:
                # Find the most common start position
                from collections import Counter
                most_common_start = Counter(field_starts).most_common(1)[0][0]
                col_start = most_common_start
            else:
                col_start = header_start
            
            # Determine column end
            if i < len(header_words) - 1:
                # Look at the next column's start position
                next_header = header_words[i + 1]
                next_field_starts = []
                for field_split in all_field_splits:
                    if i + 1 < len(field_split):
                        next_field_starts.append(field_split[i + 1]["start"])
                
                if next_field_starts:
                    from collections import Counter
                    most_common_next_start = Counter(next_field_starts).most_common(1)[0][0]
                    col_end = most_common_next_start
                else:
                    col_end = next_header["start"]
            else:
                col_end = None
            
            columns.append({
                "name": header_word["name"],
                "start": col_start,
                "end": col_end,
                "width": col_end - col_start if col_end is not None else None
            })
        
        return columns
    
    def parse_data_line(self, line: str) -> Dict[str, str]:
        """Parse a data line using the detected column boundaries.
        
        Args:
            line: Data line to parse
            
        Returns:
            Dictionary mapping column names to values
        """
        if not self.columns:
            return {}
        
        # For better results, try a hybrid approach
        # First try positional parsing, then fall back to field-based parsing
        
        line = line.rstrip()
        result = {}
        
        # Try positional parsing first
        positional_result = self._parse_positional(line)
        
        # If that doesn't work well, try field-based parsing
        field_result = self._parse_field_based(line)
        
        # Use the better result (field-based is often more reliable)
        if len(field_result) == len(self.columns):
            result = field_result
        else:
            result = positional_result
        
        return result
    
    def _parse_positional(self, line: str) -> Dict[str, str]:
        """Parse using positional column boundaries.
        
        Args:
            line: Data line to parse
            
        Returns:
            Dictionary mapping column names to values
        """
        result = {}
        
        for i, column in enumerate(self.columns):
            start = column["start"]
            end = column["end"]
            
            if end is None or i == len(self.columns) - 1:
                value = line[start:].strip() if start < len(line) else ""
            else:
                value = line[start:end].strip() if start < len(line) else ""
            
            result[column["name"]] = value
        
        return result
    
    def _parse_field_based(self, line: str) -> Dict[str, str]:
        """Parse using field-based splitting.
        
        Args:
            line: Data line to parse
            
        Returns:
            Dictionary mapping column names to values
        """
        # Split line into fields by whitespace
        fields = line.split()
        
        result = {}
        
        # Map fields to columns
        for i, column in enumerate(self.columns):
            if i < len(fields):
                if i == len(self.columns) - 1:
                    # Last column gets all remaining fields joined
                    result[column["name"]] = " ".join(fields[i:])
                else:
                    result[column["name"]] = fields[i]
            else:
                result[column["name"]] = ""
        
        return result
    
    def get_column_names(self) -> List[str]:
        """Get the list of column names.
        
        Returns:
            List of column names in order
        """
        return [col["name"] for col in self.columns]
    
    def get_column_info(self) -> List[Dict[str, Any]]:
        """Get detailed column information.
        
        Returns:
            List of column dictionaries with name, start, end, width
        """
        return self.columns.copy()


class LinuxTableCommandParser:
    """Base parser for Linux commands that output tabular data.
    
    This class provides common functionality for parsing Linux command outputs
    that have a header line followed by data rows.
    """
    
    def __init__(self):
        self.table_parser: Optional[TableParser] = None
        
    def detect_header_line(self, lines: List[str]) -> Optional[int]:
        """Detect which line contains the table header.
        
        Args:
            lines: Lines from command output
            
        Returns:
            Index of header line, or None if not found
        """
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Skip empty lines and common non-header patterns
            if not line or line.startswith('#') or line.startswith('//'):
                continue
                
            # Look for lines that contain common header keywords
            header_indicators = [
                'PID', 'PPID', 'USER', 'TIME', 'CMD', 'COMMAND', 'STAT', 'RSS', 'VSZ',
                'PORT', 'PROTO', 'STATE', 'ADDRESS', 'NAME', 'TYPE', 'SIZE'
            ]
            
            # Check if line contains multiple header-like words
            words = line.split()
            if len(words) >= 2:
                header_word_count = sum(1 for word in words if word.upper() in header_indicators)
                if header_word_count >= 2:
                    return i
                    
        return None
    
    def parse_table_output(self, lines: List[str], skip_lines: int = 0) -> List[Dict[str, str]]:
        """Parse tabular command output.
        
        Args:
            lines: Lines from command output
            skip_lines: Number of lines to skip at the beginning
            
        Returns:
            List of dictionaries representing parsed rows
        """
        if skip_lines > 0:
            lines = lines[skip_lines:]
            
        # Find header line
        header_index = self.detect_header_line(lines)
        if header_index is None:
            return []
            
        # Get header and data lines
        header_line = lines[header_index]
        data_lines = lines[header_index + 1:]
        
        # Use sample data lines for better column detection
        sample_lines = [line for line in data_lines[:5] if line.strip()]
        self.table_parser = TableParser(header_line, sample_lines)
        
        # Parse data lines
        results = []
        
        for line in data_lines:
            line = line.strip()
            if not line:
                continue
                
            parsed_row = self.table_parser.parse_data_line(line)
            if parsed_row:
                results.append(parsed_row)
                
        return results
    
    def normalize_column_name(self, name: str) -> str:
        """Normalize column name for consistent field mapping.
        
        Args:
            name: Original column name
            
        Returns:
            Normalized column name
        """
        # Convert to lowercase and replace special characters
        normalized = re.sub(r'[^a-zA-Z0-9]', '_', name.lower())
        # Remove multiple underscores
        normalized = re.sub(r'_+', '_', normalized)
        # Remove leading/trailing underscores
        normalized = normalized.strip('_')
        
        return normalized if normalized else name.lower()
    
    def map_columns_to_fields(self, row: Dict[str, str], column_mapping: Dict[str, str]) -> Dict[str, str]:
        """Map parsed columns to standardized field names.
        
        Args:
            row: Parsed row dictionary
            column_mapping: Mapping from column names to field names
            
        Returns:
            Dictionary with standardized field names
        """
        result = {}
        
        for column_name, value in row.items():
            # Try exact match first
            field_name = column_mapping.get(column_name)
            
            # Try normalized match
            if not field_name:
                normalized_name = self.normalize_column_name(column_name)
                field_name = column_mapping.get(normalized_name)
                
            # Use original name if no mapping found
            if not field_name:
                field_name = self.normalize_column_name(column_name)
                
            result[field_name] = value
            
        return result 