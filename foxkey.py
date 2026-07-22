#!/usr/bin/env python3
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from cli import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    finally:
        sys.path.pop(0)
