"""pkgforge - inspetor/gerador de containers .pkg (NPDRM e CNT).

Sem dependências externas, sem chaves proprietárias da Sony.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .ps3 import (  # noqa: F401
    ITEM_DIR, ITEM_FILE, ITEM_PBP, ITEM_TYPE_NAMES, META_NAMES,
    PackOptions, Pkg3, PkgError, REVISION_DEBUG, REVISION_RETAIL,
    build_pkg,
)
from .ps4 import Pkg4, Pkg4Error, detect  # noqa: F401
from .sfo import SFO, read_sfo, write_sfo  # noqa: F401

__all__ = [
    "__version__", "Pkg3", "Pkg4", "PkgError", "Pkg4Error", "PackOptions",
    "build_pkg", "detect", "SFO", "read_sfo", "write_sfo",
    "ITEM_FILE", "ITEM_DIR", "ITEM_PBP", "ITEM_TYPE_NAMES", "META_NAMES",
    "REVISION_DEBUG", "REVISION_RETAIL",
]
