#!/usr/bin/env python3
"""
Convenience wrapper script for the OpenGrep rules manager utility
This allows running the rules manager from the project root
"""

import sys
import os
from pathlib import Path

# Add utils directory to Python path
project_root = Path(__file__).parent
utils_path = project_root / "utils"
sys.path.insert(0, str(utils_path))

# Import and run the rules manager
if __name__ == "__main__":
    try:
        from rules_manager import main
        main()
    except ImportError as e:
        print(f"Error importing rules manager: {e}")
        print("Make sure all dependencies are installed and the utils directory exists.")
        sys.exit(1)
