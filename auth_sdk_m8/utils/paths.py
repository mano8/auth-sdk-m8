"""
File-path utilities for locating `.env` files.
"""

import logging
from os.path import join as join_path
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).resolve().parent


def find_dotenv(start_path: Path = ROOT_DIR) -> Path:
    """
    Walk up the directory tree from *start_path* to locate a ``.env`` file.

    Args:
        start_path: Directory (or file) to begin the search from.
                    Defaults to the directory containing this module.

    Returns:
        The resolved path to the first ``.env`` file found.

    Raises:
        FileNotFoundError: If no ``.env`` file exists in the tree.
    """
    logger.debug("Looking for .env file starting from: %s", start_path)
    search_root = start_path if start_path.is_dir() else start_path.parent
    for parent in [search_root, *search_root.parents]:
        logger.debug("Checking directory: %s", parent)
        potential = parent / ".env"
        if potential.exists():
            return Path(join_path(parent, ".env"))
    raise FileNotFoundError(f".env file not found from {start_path}")
