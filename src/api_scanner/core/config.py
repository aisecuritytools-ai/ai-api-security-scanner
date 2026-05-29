"""Configuration for API Security Scanner."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ScanConfig:
    """Scan configuration."""

    project_path: Path
    min_score: int = 50
    fail_on_issues: bool = False
    verbose: bool = False
    scan_timeout: int = 300

    # File patterns to scan
    java_patterns: tuple = ("*.java",)
    typescript_patterns: tuple = ("*.ts", "*.tsx")
    graphql_patterns: tuple = ("*.graphql", "*.gql")
    yaml_patterns: tuple = ("*.yml", "*.yaml")
    config_patterns: tuple = ("*.properties", "*.env", "*.conf")

    # Directories to skip
    exclude_dirs: tuple = (
        "node_modules", ".git", "target", "build", "dist",
        "__pycache__", ".venv", "venv", ".idea", ".vscode",
    )

    def __post_init__(self):
        if self.min_score < 0 or self.min_score > 100:
            raise ValueError("min_score must be between 0 and 100")
