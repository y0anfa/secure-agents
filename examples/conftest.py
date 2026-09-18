"""Put each example directory on sys.path.

Examples are standalone scripts, not an installed package, so their tests
import them the way a reader would after cloning: by being in the directory.
"""

import sys
from pathlib import Path

for child in sorted(Path(__file__).parent.iterdir()):
    if child.is_dir() and not child.name.startswith((".", "__")):
        sys.path.insert(0, str(child))
