"""Base scanner class with shared file discovery utilities."""

import os
from pathlib import Path
from typing import Generator, List

from api_scanner.core.config import ScanConfig
from api_scanner.core.models import ScannerResult


class BaseScanner:
    """Base class for all scanner engines."""

    name: str = "Base Scanner"

    def __init__(self, config: ScanConfig):
        self.config = config

    def scan(self) -> ScannerResult:
        """Run the scan. Override in subclasses."""
        raise NotImplementedError

    def find_files(self, patterns: tuple) -> List[Path]:
        """Find files matching patterns, excluding configured directories."""
        found = []
        for pattern in patterns:
            for file_path in self.config.project_path.rglob(pattern):
                # Skip excluded directories
                if any(excluded in file_path.parts for excluded in self.config.exclude_dirs):
                    continue
                found.append(file_path)
        return found

    def read_file_safe(self, file_path: Path) -> str:
        """Read file content safely, returning empty string on error."""
        try:
            return file_path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            return ""

    def calculate_score(self, checks_passed: int, checks_total: int) -> int:
        """Calculate percentage score."""
        if checks_total == 0:
            return 100
        return int((checks_passed / checks_total) * 100)
