import os
import sys

# Make the package importable when pytest is run from backend/.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
