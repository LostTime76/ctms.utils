import shutil
import subprocess
from pathlib import Path

# Paths
cwd = Path(__file__).parent

# Build the package
subprocess.run(['python', '-m', 'build'], cwd=str(cwd.resolve()))

# Remove idiotic egg file items
for ipath in cwd.glob('**\\*egg*'):
	if ipath.is_dir():
		shutil.rmtree(str(ipath.resolve()))
	else:
		ipath.unlink()