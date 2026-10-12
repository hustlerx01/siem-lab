"""Convert EVTX into Wazuh eventchannel-shaped JSON lines ({"win":{"system":..,"eventdata":..}}).
Reuses evtx-triage's parser idea (python-evtx -> flat dict); field names are camelCased like Wazuh's decoder."""
import json, sys, xml.etree.ElementTree as ET
from pathlib import Path

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def camel(k): return k[:1].lower() + k[1:] if k else k

def to_wazuh(xml):
    r = ET.fromstring(xml); s = r.find(f"{NS}System")
    tc = s.find(f"{NS}TimeCreated")
    system = {"eventID": s.findtext(f"{NS}EventID"), "channel": s.findtext(f"{NS}Channel"),
              "computer": s.findtext(f"{NS}Computer"),
              "systemTime": tc.get("SystemTime") if tc is not None else None}
    data = {camel(d.get("Name")): (d.text or "").strip() for d in r.iter(f"{NS}Data") if d.get("Name")}
    return {"win": {"system": system, "eventdata": data}}

def convert(path):
    import Evtx.Evtx as evtx
    out = []
    with evtx.Evtx(str(path)) as log:
        for rec in log.records():
            try: out.append(to_wazuh(rec.xml()))
            except Exception: pass
    return out

if __name__ == "__main__":
    src, dst = Path(sys.argv[1]), Path(sys.argv[2]); dst.mkdir(parents=True, exist_ok=True)
    for f in sorted(src.glob("*.evtx")):
        evs = convert(f)
        (dst / (f.stem + ".jsonl")).write_text("".join(json.dumps(e) + "\n" for e in evs))
        print(f"{f.name}: {len(evs)} events")
