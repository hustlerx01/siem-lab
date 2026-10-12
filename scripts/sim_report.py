"""Run the OFFLINE simulator (tests/wazuh_sim.py) over every sample and print siem-lab rule hits per file."""
import json, sys
from collections import Counter
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from wazuh_sim import Engine
for f in sorted(Path("samples").rglob("*.jsonl")):
    e, c = Engine(), Counter()
    for l in f.read_text().splitlines():
        c.update(e.process(json.loads(l)))
    hits = {k: v for k, v in c.items() if k not in {"100100", "100101", "100102", "100113"}}
    print(f"{f}: {dict(sorted(hits.items())) or '-'}")
