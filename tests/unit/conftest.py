import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

for sub in ("filter_plugins", "library"):
    path = os.path.join(ROOT, "playbooks", "ceph", sub)
    if path not in sys.path:
        sys.path.insert(0, path)
