import sys
from pathlib import Path

# Let tests import analysis/ and database/ from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
