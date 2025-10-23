#!/usr/bin/env python3
"""
Convenience wrapper script for the main analyzer
This allows running the analyzer from the project root without specifying the full src path
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
project_root = Path(__file__).parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))

# Import and run the main analyzer
if __name__ == "__main__":
    try:
        from main_analyzer import main
        main()
    except ImportError as e:
        print(f"Error importing main analyzer: {e}")
        print("Make sure all dependencies are installed and the src directory exists.")
        sys.exit(1)
