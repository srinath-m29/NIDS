"""
path_helper.py - Centralized repository root path resolver.
"""

from pathlib import Path


def get_project_root() -> Path:
    """Returns the absolute root directory of the NIDS project."""
    return Path(__file__).resolve().parent.parent
