import sys
from pathlib import Path

# Dirs
proj_dir = Path(__file__).parent.parent
pkg_dir  = Path(proj_dir, 'packages')

# Add to path
sys.path.append(str(pkg_dir.resolve()))