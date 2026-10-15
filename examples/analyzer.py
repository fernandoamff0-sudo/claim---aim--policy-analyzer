"""Compatibility entry point: analyze the bundled example by default."""

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from analyzer import main  # noqa: E402


if __name__ == "__main__":
    arguments = sys.argv[1:] or [str(PROJECT_ROOT / "examples" / "broad_policy.json")]
    sys.exit(main(arguments))
