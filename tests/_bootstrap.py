"""Put src/ on sys.path so tests run without installing keel."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))
SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
