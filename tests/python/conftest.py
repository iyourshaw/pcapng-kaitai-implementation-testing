"""pytest setup: put the generated decoders on sys.path and find the samples.

Run scripts/compile.py (or scripts/run_tests.py) first to create generated/.
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
GENERATED = HERE / "generated"
SAMPLES = REPO / "samples"
EXPECTED = REPO / "tests" / "expected"

if not (GENERATED / "pcapng.py").is_file():
    raise RuntimeError(f"{GENERATED} has no generated code; run: python scripts/compile.py --target python")
sys.path.insert(0, str(GENERATED))
sys.path.insert(0, str(HERE))
