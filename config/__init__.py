"""
config/__init__.py
------------------
Makes `config` a package and exposes the most-used symbols
so modules can do:

    from config import settings, constants
    from config import get_logger
"""

from config.settings       import *          # noqa: F401,F403
from config.constants      import *          # noqa: F401,F403
from config.logging_config import get_logger  # noqa: F401
